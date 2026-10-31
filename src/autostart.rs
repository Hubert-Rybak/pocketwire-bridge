//! Starts the background app when the user signs in: a Run key on Windows, a launchd agent on
//! macOS and an XDG autostart entry on Linux.

use std::path::PathBuf;

/// How the entry shows up in the OS (Task Manager > Startup apps on Windows).
pub const NAME: &str = "Pocketwire Bridge";
/// The windowless Windows build that the installer puts next to pocketwire.exe.
pub const GUI_EXE: &str = "PocketwireBridge.exe";
/// The launchd agent that starts the app (`service install` uses app.pocketwire.bridge).
#[cfg_attr(windows, allow(dead_code))]
pub const LABEL: &str = "app.pocketwire.bridge.app";

pub fn current_exe() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    Ok(std::fs::canonicalize(&exe).map(strip_verbatim).unwrap_or(exe))
}

/// canonicalize on Windows returns \\?\C:\…; programs expect C:\….
fn strip_verbatim(p: PathBuf) -> PathBuf {
    let s = p.to_string_lossy();
    match s.strip_prefix(r"\\?\") {
        Some(rest) if !rest.starts_with("UNC") => PathBuf::from(rest),
        _ => p,
    }
}

/// The program and arguments that start the background app without opening its window.
pub fn command() -> Result<(PathBuf, Vec<String>), String> {
    let exe = current_exe()?;
    if cfg!(windows) {
        if let Some(dir) = exe.parent() {
            let gui = dir.join(GUI_EXE);
            if gui.exists() {
                return Ok((gui, vec!["--background".into()]));
            }
        }
    }
    Ok((exe, vec!["app".into(), "--background".into()]))
}

pub fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// The launchd agent that starts the app once at login (no KeepAlive, so Quit sticks).
#[cfg_attr(windows, allow(dead_code))]
pub fn plist(exe: &str, args: &[String]) -> String {
    let mut a = format!("<string>{}</string>", xml_escape(exe));
    for x in args {
        a.push_str(&format!("<string>{}</string>", xml_escape(x)));
    }
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{LABEL}</string>
  <key>ProgramArguments</key><array>{a}</array>
  <key>RunAtLoad</key><true/>
  <key>ProcessType</key><string>Interactive</string>
</dict>
</plist>
"#
    )
}

/// The XDG autostart entry.
#[cfg_attr(windows, allow(dead_code))]
pub fn desktop_entry(exe: &str, args: &[String]) -> String {
    let q = |s: &str| {
        if s.contains([' ', '\t', '"', '\\', '$', '`', '\'']) {
            format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"").replace('$', "\\$").replace('`', "\\`"))
        } else {
            s.to_string()
        }
    };
    let mut parts = vec![q(exe)];
    parts.extend(args.iter().map(|a| q(a)));
    format!(
        "[Desktop Entry]\nType=Application\nName={NAME}\nComment=Lets your AI agents text from your phone, with your approval\nExec={}\nTerminal=false\nX-GNOME-Autostart-enabled=true\n",
        parts.join(" ")
    )
}

/// The Run key value for an executable and its arguments.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn run_line(exe: &str, args: &[String]) -> String {
    let mut parts = vec![format!("\"{exe}\"")];
    for a in args {
        parts.push(if a.contains([' ', '\t']) { format!("\"{a}\"") } else { a.clone() });
    }
    parts.join(" ")
}

#[cfg(not(windows))]
fn entry_path() -> Result<PathBuf, String> {
    let home = crate::config::home_dir()?;
    if cfg!(target_os = "macos") {
        return Ok(home.join("Library").join("LaunchAgents").join(format!("{LABEL}.plist")));
    }
    let dir = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()).map(PathBuf::from).unwrap_or_else(|| home.join(".config"));
    Ok(dir.join("autostart").join("pocketwire-bridge.desktop"))
}

#[cfg(not(windows))]
pub fn enabled() -> bool {
    entry_path().map(|p| p.exists()).unwrap_or(false)
}

/// Writes or removes the entry; it takes effect at the next sign-in.
#[cfg(not(windows))]
pub fn set(on: bool) -> Result<(), String> {
    let p = entry_path()?;
    if !on {
        return match std::fs::remove_file(&p) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.to_string()),
            _ => Ok(()),
        };
    }
    let (exe, args) = command()?;
    let exe = exe.to_string_lossy();
    let body = if cfg!(target_os = "macos") { plist(&exe, &args) } else { desktop_entry(&exe, &args) };
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
    }
    std::fs::write(&p, body).map_err(|e| e.to_string())
}

#[cfg(windows)]
const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

#[cfg(windows)]
pub fn enabled() -> bool {
    crate::winreg::get_string(RUN_KEY, NAME).is_some()
}

#[cfg(windows)]
pub fn set(on: bool) -> Result<(), String> {
    if !on {
        return crate::winreg::delete_value(RUN_KEY, NAME);
    }
    let (exe, args) = command()?;
    crate::winreg::set_string(RUN_KEY, NAME, &run_line(&exe.to_string_lossy(), &args), false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries() {
        let a = vec!["app".to_string(), "--background".to_string()];
        assert!(desktop_entry("/home/a b/pocketwire", &a).contains(r#"Exec="/home/a b/pocketwire" app --background"#));
        assert_eq!(
            run_line(r"C:\Program Files\Pocketwire\PocketwireBridge.exe", &["--background".into()]),
            r#""C:\Program Files\Pocketwire\PocketwireBridge.exe" --background"#
        );
        assert!(plist("/Applications/Pocketwire Bridge.app/Contents/MacOS/pocketwire", &a).contains("<string>app</string><string>--background</string>"));
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn set_and_remove() {
        let dir = std::env::temp_dir().join(format!("pw-auto-{}", crate::util::random_hex(4)));
        std::env::set_var("XDG_CONFIG_HOME", &dir);
        assert!(!enabled());
        set(true).unwrap();
        let p = entry_path().unwrap();
        assert!(std::fs::read_to_string(&p).unwrap().contains("app --background"));
        assert!(enabled());
        set(false).unwrap();
        assert!(!enabled());
        set(false).unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }
}
