//! `pocketwire service install|uninstall`: a per-user background service.

use std::path::PathBuf;

use crate::config::home_dir;
use crate::driver::{self, Runner};

const UNIT_NAME: &str = "pocketwire.service";
const AGENT_ID: &str = "app.pocketwire.bridge";
#[cfg(windows)]
const TASK_NAME: &str = "Pocketwire Bridge"; // scheduled task of older versions on Windows

/// The systemd --user unit for Linux.
pub fn systemd_unit(exe: &str) -> String {
    format!(
        "[Unit]\nDescription=Pocketwire Bridge\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nExecStart={} run\nRestart=always\nRestartSec=5\n\n[Install]\nWantedBy=default.target\n",
        crate::log::quote(exe)
    )
}

/// The launchd plist for macOS.
pub fn launch_agent(exe: &str, log_path: &str) -> String {
    let (exe, log) = (crate::autostart::xml_escape(exe), crate::autostart::xml_escape(log_path));
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{AGENT_ID}</string>
  <key>ProgramArguments</key><array><string>{exe}</string><string>run</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>{log}</string>
  <key>StandardErrorPath</key><string>{log}</string>
</dict>
</plist>
"#
    )
}

async fn run(r: &Runner, cmd: &str, args: &[&str]) -> Result<Vec<u8>, String> {
    r(cmd.to_string(), args.iter().map(|s| s.to_string()).collect()).await
}

fn write(dir: &PathBuf, name: &str, body: &str) -> Result<PathBuf, String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let p = dir.join(name);
    std::fs::write(&p, body).map_err(|e| e.to_string())?;
    Ok(p)
}

/// Writes the service definition for this OS and starts it; returns where it went.
pub async fn install(r: &Runner) -> Result<String, String> {
    let exe = crate::autostart::current_exe()?;
    let exe = exe.to_string_lossy().to_string();
    let home = home_dir()?;
    if cfg!(target_os = "linux") || cfg!(target_os = "freebsd") {
        let p = write(&home.join(".config").join("systemd").join("user"), UNIT_NAME, &systemd_unit(&exe))?;
        let shown = p.display().to_string();
        run(r, "systemctl", &["--user", "daemon-reload"]).await.map_err(|e| format!("{shown}: {e}"))?;
        run(r, "systemctl", &["--user", "enable", "--now", UNIT_NAME]).await.map_err(|e| format!("{shown}: {e}"))?;
        return Ok(shown);
    }
    if cfg!(target_os = "macos") {
        let log = home.join("Library").join("Logs").join("pocketwire-bridge.log");
        let p = write(&home.join("Library").join("LaunchAgents"), &format!("{AGENT_ID}.plist"), &launch_agent(&exe, &log.to_string_lossy()))?;
        let ps = p.to_string_lossy().to_string();
        let _ = run(r, "launchctl", &["unload", &ps]).await;
        run(r, "launchctl", &["load", "-w", &ps]).await?;
        return Ok(ps);
    }
    #[cfg(windows)]
    {
        // Start the tray app at sign-in (a scheduled task running `pocketwire run` would keep a
        // console window open), and start it now.
        let _ = run(r, "schtasks", &["/Delete", "/F", "/TN", TASK_NAME]).await;
        crate::autostart::set(true)?;
        let (bin, args) = crate::autostart::command()?;
        let mut cmd = std::process::Command::new(bin);
        cmd.args(args);
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x0800_0000 | 0x0000_0008); // CREATE_NO_WINDOW | DETACHED_PROCESS
        }
        cmd.spawn().map_err(|e| e.to_string())?;
        return Ok("the tray app, started now and at every sign-in".into());
    }
    #[allow(unreachable_code)]
    Err(driver::UNSUPPORTED.into())
}

/// Stops and removes the service.
pub async fn uninstall(r: &Runner) -> Result<(), String> {
    let home = home_dir()?;
    let rm = |p: PathBuf| std::fs::remove_file(&p).map_err(|e| format!("remove {}: {e}", p.display()));
    if cfg!(target_os = "linux") || cfg!(target_os = "freebsd") {
        let _ = run(r, "systemctl", &["--user", "disable", "--now", UNIT_NAME]).await;
        return rm(home.join(".config").join("systemd").join("user").join(UNIT_NAME));
    }
    if cfg!(target_os = "macos") {
        let p = home.join("Library").join("LaunchAgents").join(format!("{AGENT_ID}.plist"));
        let _ = run(r, "launchctl", &["unload", "-w", &p.to_string_lossy()]).await;
        return rm(p);
    }
    #[cfg(windows)]
    {
        let _ = run(r, "schtasks", &["/Delete", "/F", "/TN", TASK_NAME]).await;
        return crate::autostart::set(false);
    }
    #[allow(unreachable_code)]
    Err(driver::UNSUPPORTED.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_quotes_the_path() {
        assert!(systemd_unit("/home/a b/pocketwire").contains("ExecStart=\"/home/a b/pocketwire\" run"));
        assert!(launch_agent("/x&y", "/l").contains("<string>/x&amp;y</string>"));
    }
}
