//! A tiny logger: time-stamped lines to stderr and, in the background app, to a file.

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

static FILE: Mutex<Option<std::fs::File>> = Mutex::new(None);
static QUIET: AtomicBool = AtomicBool::new(false);

/// Sends log lines to a file too; with `quiet`, only there (the windowless build has no stderr).
pub fn to_file(f: std::fs::File, quiet: bool) {
    *FILE.lock().unwrap_or_else(|e| e.into_inner()) = Some(f);
    QUIET.store(quiet, Ordering::Relaxed);
}

pub fn write(msg: &str) {
    let line = format!("{} {msg}\n", crate::util::rfc3339(crate::util::now_ms(), false));
    if !QUIET.load(Ordering::Relaxed) {
        let _ = std::io::stderr().write_all(line.as_bytes());
    }
    if let Some(f) = FILE.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
        let _ = f.write_all(line.as_bytes());
    }
}

#[macro_export]
macro_rules! logf {
    ($($arg:tt)*) => { $crate::log::write(&format!($($arg)*)) };
}

/// Quotes a string the way Go's %q does, so log lines read the same as before.
pub fn quote(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => o.push_str(&format!("\\x{:02x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}
