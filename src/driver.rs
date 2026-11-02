//! The integrations a desktop Bridge uses to reach a phone.

use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// Runs a program with an argument list (never through a shell) and returns its output.
pub type Runner = Arc<dyn Fn(String, Vec<String>) -> BoxFuture<Result<Vec<u8>, String>> + Send + Sync>;

pub const NAMES: [&str; 3] = ["dry-run", "kdeconnect", "macos-messages"];

pub const UNSUPPORTED: &str = "not supported on this operating system";

/// How long a readiness check may take. On a Mac the first check waits for the user to answer
/// macOS's "wants to control Messages" prompt, which can take forever.
pub const CHECK_TIMEOUT: Duration = Duration::from_secs(15);

/// Keeps console programs (kdeconnect-cli) from flashing a window when the windowless app starts them.
pub fn hide_window(_cmd: &mut tokio::process::Command) {
    #[cfg(windows)]
    {
        _cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
}

pub fn exec_runner() -> Runner {
    Arc::new(|name: String, args: Vec<String>| {
        Box::pin(async move {
            let mut cmd = tokio::process::Command::new(&name);
            cmd.args(&args).kill_on_drop(true).stdin(std::process::Stdio::null());
            hide_window(&mut cmd);
            let out = cmd.output().await;
            let base = Path::new(&name).file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or(name.clone());
            let out = out.map_err(|e| format!("{base}: {e}"))?;
            let mut all = out.stdout.clone();
            all.extend_from_slice(&out.stderr);
            if !out.status.success() {
                let msg = String::from_utf8_lossy(&all).trim().to_string();
                let status = match out.status.code() {
                    Some(c) => format!("exit status {c}"),
                    None => "killed".to_string(),
                };
                return Err(if msg.is_empty() { format!("{base}: {status}") } else { format!("{base}: {status}: {msg}") });
            }
            Ok(out.stdout)
        })
    })
}

/// Finds a program on PATH, then in well-known install locations.
pub fn look_path(name: &str, extra: &[&str]) -> Option<String> {
    let exts: &[&str] = if cfg!(windows) { &[".exe", ""] } else { &[""] };
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            for ext in exts {
                let p = dir.join(format!("{name}{ext}"));
                if p.is_file() {
                    return Some(p.to_string_lossy().into_owned());
                }
            }
        }
    }
    extra.iter().find(|p| Path::new(p).exists()).map(|p| p.to_string())
}

#[derive(Clone)]
pub enum Kind {
    DryRun,
    /// Messages.app with AppleScript; "sms" (default) or "imessage".
    MacMessages {
        service: String,
    },
    /// kdeconnect-cli with a paired Android phone; empty device = first reachable.
    KdeConnect {
        device: String,
    },
}

#[derive(Clone)]
pub struct Driver {
    pub kind: Kind,
    run: Runner,
    /// For tests: pretend to be on another OS, or find kdeconnect-cli elsewhere.
    os: &'static str,
    kde_bin: Option<String>,
}

const KDE_EXTRA: &[&str] = &[
    r"C:\Program Files\KDE Connect\bin\kdeconnect-cli.exe",
    r"C:\Program Files (x86)\KDE Connect\bin\kdeconnect-cli.exe",
    "/usr/bin/kdeconnect-cli",
    "/usr/local/bin/kdeconnect-cli",
    "/Applications/KDE Connect.app/Contents/MacOS/kdeconnect-cli",
];

/// The recipient and text are AppleScript argv, never spliced into the script source, so the
/// text cannot inject AppleScript.
pub const MAC_SEND_SCRIPT: &str = r#"on run argv
	set theNumber to item 1 of argv
	set theText to item 2 of argv
	set wantService to item 3 of argv
	tell application "Messages"
		if wantService is "imessage" then
			set theAccount to first account whose service type = iMessage
		else
			set theAccount to first account whose service type = SMS
		end if
		set theTarget to participant theNumber of theAccount
		send theText to theTarget
	end tell
end run"#;

const MAC_AUTOMATION_HINT: &str =
    "allow Pocketwire Bridge, or the terminal you run it from, to control Messages in System Settings → Privacy & Security → Automation";

const MAC_CHECK_SCRIPT: &str = r#"tell application "Messages" to get name of every account"#;

/// The most likely driver for this OS.
pub fn default_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos-messages"
    } else {
        "kdeconnect"
    }
}

impl Driver {
    pub fn new(name: &str, opts: &std::collections::BTreeMap<String, String>, run: Option<Runner>) -> Result<Driver, String> {
        let opt = |k: &str| opts.get(k).cloned().unwrap_or_default();
        let kind = match name {
            "dry-run" => Kind::DryRun,
            "macos-messages" => Kind::MacMessages { service: opt("service") },
            "kdeconnect" => Kind::KdeConnect { device: opt("device") },
            _ => return Err(format!("unknown driver {name:?} (choose one of: {})", NAMES.join(", "))),
        };
        Ok(Driver { kind, run: run.unwrap_or_else(exec_runner), os: std::env::consts::OS, kde_bin: None })
    }

    #[cfg(test)]
    pub(crate) fn for_test(kind: Kind, run: Runner, os: &'static str, kde_bin: Option<&str>) -> Driver {
        Driver { kind, run, os, kde_bin: kde_bin.map(str::to_string) }
    }

    pub fn name(&self) -> &'static str {
        match self.kind {
            Kind::DryRun => "dry-run",
            Kind::MacMessages { .. } => "macos-messages",
            Kind::KdeConnect { .. } => "kdeconnect",
        }
    }

    fn mac_service(service: &str) -> &'static str {
        if service.eq_ignore_ascii_case("imessage") {
            "imessage"
        } else {
            "sms"
        }
    }

    fn kde(&self) -> Result<String, String> {
        if let Some(b) = &self.kde_bin {
            return Ok(b.clone());
        }
        look_path("kdeconnect-cli", KDE_EXTRA).ok_or_else(|| "kdeconnect-cli not found: install KDE Connect and pair your Android phone with it".to_string())
    }

    async fn kde_device(&self, bin: &str, device: &str) -> Result<String, String> {
        if !device.is_empty() {
            return Ok(device.to_string());
        }
        let out = (self.run)(bin.to_string(), vec!["--list-available".into(), "--id-only".into()]).await?;
        String::from_utf8_lossy(&out)
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty())
            .map(str::to_string)
            .ok_or_else(|| "no reachable KDE Connect device: open KDE Connect on the phone and make sure it is paired".to_string())
    }

    /// Reports whether the integration is usable on this machine.
    pub async fn check(&self) -> Result<(), String> {
        match &self.kind {
            Kind::DryRun => Ok(()),
            Kind::MacMessages { .. } => {
                if self.os != "macos" {
                    return Err(UNSUPPORTED.into());
                }
                (self.run)("/usr/bin/osascript".into(), vec!["-e".into(), MAC_CHECK_SCRIPT.into()])
                    .await
                    .map(|_| ())
                    .map_err(|e| format!("cannot talk to Messages.app ({MAC_AUTOMATION_HINT}): {e}"))
            }
            Kind::KdeConnect { device } => {
                let bin = self.kde()?;
                self.kde_device(&bin, device).await.map(|_| ())
            }
        }
    }

    /// `check`, given at most `limit` to answer.
    pub async fn check_within(&self, limit: Duration) -> Result<(), String> {
        match tokio::time::timeout(limit, self.check()).await {
            Ok(r) => r,
            Err(_) => Err(match self.kind {
                Kind::MacMessages { .. } => {
                    format!("Messages.app did not answer; if macOS asks whether Pocketwire Bridge may control Messages, click OK ({MAC_AUTOMATION_HINT})")
                }
                _ => "the check timed out".to_string(),
            }),
        }
    }

    pub async fn send_sms(&self, to: &str, body: &str) -> Result<(), String> {
        match &self.kind {
            Kind::DryRun => {
                eprintln!("[dry-run] would send to {to}: {}", crate::log::quote(body));
                Ok(())
            }
            Kind::MacMessages { service } => {
                if self.os != "macos" {
                    return Err(UNSUPPORTED.into());
                }
                let svc = Self::mac_service(service);
                let args = vec!["-e".into(), MAC_SEND_SCRIPT.into(), to.into(), body.into(), svc.into()];
                (self.run)("/usr/bin/osascript".into(), args).await.map(|_| ()).map_err(|e| {
                    if e.contains("-1728") {
                        format!("no {svc} account in Messages.app (enable Text Message Forwarding on your iPhone for this Mac): {e}")
                    } else {
                        e
                    }
                })
            }
            Kind::KdeConnect { device } => {
                let bin = self.kde()?;
                let dev = self.kde_device(&bin, device).await?;
                // The --opt=value form keeps text that starts with "-" from being read as an option.
                let args = vec![format!("--device={dev}"), format!("--send-sms={body}"), format!("--destination={to}")];
                (self.run)(bin, args).await.map(|_| ()).map_err(|e| format!("KDE Connect could not send: {e}"))
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::Mutex;

    type Calls = Arc<Mutex<Vec<(String, Vec<String>)>>>;

    fn recorder(out: &'static str) -> (Calls, Runner) {
        let calls: Calls = Arc::default();
        let c = calls.clone();
        let run: Runner = Arc::new(move |name, args| {
            let list = args.first().map(|a| a == "--list-available").unwrap_or(false);
            c.lock().unwrap().push((name, args));
            Box::pin(async move { Ok(if list { out.as_bytes().to_vec() } else { Vec::new() }) })
        });
        (calls, run)
    }

    #[tokio::test]
    async fn mac_messages_passes_text_as_argv() {
        let (calls, run) = recorder("");
        let d = Driver::for_test(Kind::MacMessages { service: String::new() }, run.clone(), "macos", None);
        let evil = r#""; do shell script "rm -rf ~" --"#;
        d.send_sms("+48501234567", evil).await.unwrap();
        let (name, args) = calls.lock().unwrap()[0].clone();
        assert_eq!(name, "/usr/bin/osascript");
        assert_eq!(args[..2], ["-e".to_string(), MAC_SEND_SCRIPT.to_string()]);
        assert_eq!(args[2..], ["+48501234567".to_string(), evil.to_string(), "sms".to_string()]);
        let d = Driver::for_test(Kind::MacMessages { service: "iMessage".into() }, run.clone(), "macos", None);
        d.send_sms("+1", "x").await.unwrap();
        assert_eq!(calls.lock().unwrap()[1].1[4], "imessage");
        let d = Driver::for_test(Kind::MacMessages { service: String::new() }, run, "linux", None);
        assert_eq!(d.send_sms("+1", "x").await, Err(UNSUPPORTED.to_string()));
    }

    #[tokio::test]
    async fn kdeconnect_picks_first_device_and_uses_equals_form() {
        let (calls, run) = recorder("abc123\ndef456\n");
        let d = Driver::for_test(Kind::KdeConnect { device: String::new() }, run, "linux", Some("/usr/bin/kdeconnect-cli"));
        d.send_sms("+48501234567", "-starts with dash").await.unwrap();
        assert_eq!(calls.lock().unwrap()[1].1, ["--device=abc123", "--send-sms=-starts with dash", "--destination=+48501234567"]);
    }

    #[tokio::test]
    async fn kdeconnect_without_device() {
        let (_, run) = recorder("\n");
        let d = Driver::for_test(Kind::KdeConnect { device: String::new() }, run, "linux", Some("kdeconnect-cli"));
        assert!(d.check().await.unwrap_err().contains("no reachable"));
    }

    /// A program that never answers, like osascript while macOS shows its Automation prompt.
    pub(crate) fn hanging() -> Runner {
        Arc::new(|_, _| Box::pin(std::future::pending()))
    }

    #[tokio::test]
    async fn check_gives_up_on_a_silent_messages_app() {
        let d = Driver::for_test(Kind::MacMessages { service: String::new() }, hanging(), "macos", None);
        let e = d.check_within(Duration::from_millis(50)).await.unwrap_err();
        assert!(e.contains("Automation"), "{e}");
    }

    #[test]
    fn unknown_driver() {
        assert!(Driver::new("phone-link", &Default::default(), None).is_err());
        for n in NAMES {
            assert_eq!(Driver::new(n, &Default::default(), None).unwrap().name(), n);
        }
    }
}
