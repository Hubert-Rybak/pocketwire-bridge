//! Windows only: opening pocketwire.exe from Explorer, and the installer's helpers.

use windows_sys::Win32::System::Console::{FreeConsole, GetConsoleProcessList};
use windows_sys::Win32::UI::WindowsAndMessaging::{SendMessageTimeoutW, HWND_BROADCAST, SMTO_ABORTIFHUNG, WM_SETTINGCHANGE};

/// Whether Windows made a console just for this process, as it does when pocketwire.exe is
/// opened from Explorer. Then it lets go of that console, so the window closes.
pub fn started_by_double_click() -> bool {
    let mut pids = [0u32; 2];
    let n = unsafe { GetConsoleProcessList(pids.as_mut_ptr(), 2) };
    if n != 1 {
        return false;
    }
    unsafe { FreeConsole() };
    true
}

/// What the Windows installer runs: put the Bridge on the user's Path and turn starting at
/// sign-in on or off.
pub fn installer(args: &[String]) -> Result<(), String> {
    let [action] = args else { return Err("usage: pocketwire _installer path-add|path-remove|autostart-on|autostart-off".into()) };
    let exe = crate::autostart::current_exe()?;
    let dir = exe.parent().map(|d| d.to_string_lossy().to_string()).unwrap_or_default();
    match action.as_str() {
        "path-add" => edit_user_path(&dir, true),
        "path-remove" => edit_user_path(&dir, false),
        "autostart-on" => crate::autostart::set(true),
        "autostart-off" => crate::autostart::set(false),
        a => Err(format!("unknown installer action {}", crate::log::quote(a))),
    }
}

/// Adds dir to, or removes it from, the user's Path and tells running programs.
fn edit_user_path(dir: &str, add: bool) -> Result<(), String> {
    let (cur, expand) = crate::winreg::get("Environment", "Path").unwrap_or_default();
    let norm = |s: &str| s.trim_end_matches('\\').to_lowercase();
    let mut found = false;
    let mut parts: Vec<String> = Vec::new();
    for p in cur.split(';').filter(|p| !p.is_empty()) {
        if norm(p) == norm(dir) {
            found = true;
            if !add {
                continue;
            }
        }
        parts.push(p.to_string());
    }
    if add == found {
        return Ok(());
    }
    if add {
        parts.push(dir.to_string());
    }
    crate::winreg::set_string("Environment", "Path", &parts.join(";"), expand)?;
    let env: Vec<u16> = "Environment".encode_utf16().chain(std::iter::once(0)).collect();
    let mut result = 0usize;
    unsafe { SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, env.as_ptr() as isize, SMTO_ABORTIFHUNG, 5000, &mut result) };
    Ok(())
}
