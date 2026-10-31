//! A few HKEY_CURRENT_USER registry calls (Run key, the user's Path).

use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE,
    REG_EXPAND_SZ, REG_OPTION_NON_VOLATILE, REG_SZ,
};

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        unsafe { RegCloseKey(self.0) };
    }
}

fn open(path: &str, write: bool) -> Result<Key, u32> {
    let mut k: HKEY = std::ptr::null_mut();
    let p = wide(path);
    let rc = unsafe {
        if write {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                p.as_ptr(),
                0,
                std::ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE | KEY_QUERY_VALUE,
                std::ptr::null(),
                &mut k,
                std::ptr::null_mut(),
            )
        } else {
            RegOpenKeyExW(HKEY_CURRENT_USER, p.as_ptr(), 0, KEY_QUERY_VALUE, &mut k)
        }
    };
    if rc == ERROR_SUCCESS {
        Ok(Key(k))
    } else {
        Err(rc)
    }
}

/// A string value and whether it is REG_EXPAND_SZ.
pub fn get(path: &str, name: &str) -> Option<(String, bool)> {
    let k = open(path, false).ok()?;
    let n = wide(name);
    let (mut typ, mut size) = (0u32, 0u32);
    if unsafe { RegQueryValueExW(k.0, n.as_ptr(), std::ptr::null(), &mut typ, std::ptr::null_mut(), &mut size) } != ERROR_SUCCESS {
        return None;
    }
    if typ != REG_SZ && typ != REG_EXPAND_SZ {
        return None;
    }
    let mut buf = vec![0u16; (size as usize).div_ceil(2) + 1];
    let mut size = (buf.len() * 2) as u32;
    if unsafe { RegQueryValueExW(k.0, n.as_ptr(), std::ptr::null(), &mut typ, buf.as_mut_ptr() as *mut u8, &mut size) } != ERROR_SUCCESS {
        return None;
    }
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    Some((String::from_utf16_lossy(&buf[..len]), typ == REG_EXPAND_SZ))
}

pub fn get_string(path: &str, name: &str) -> Option<String> {
    get(path, name).map(|(s, _)| s)
}

pub fn set_string(path: &str, name: &str, value: &str, expand: bool) -> Result<(), String> {
    let k = open(path, true).map_err(|e| format!("registry {path}: error {e}"))?;
    let n = wide(name);
    let v = wide(value);
    let rc = unsafe { RegSetValueExW(k.0, n.as_ptr(), 0, if expand { REG_EXPAND_SZ } else { REG_SZ }, v.as_ptr() as *const u8, (v.len() * 2) as u32) };
    if rc == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(format!("registry {path}\\{name}: error {rc}"))
    }
}

pub fn delete_value(path: &str, name: &str) -> Result<(), String> {
    let k = match open(path, true) {
        Ok(k) => k,
        Err(ERROR_FILE_NOT_FOUND) => return Ok(()),
        Err(e) => return Err(format!("registry {path}: error {e}")),
    };
    let n = wide(name);
    match unsafe { RegDeleteValueW(k.0, n.as_ptr()) } {
        ERROR_SUCCESS | ERROR_FILE_NOT_FOUND => Ok(()),
        rc => Err(format!("registry {path}\\{name}: error {rc}")),
    }
}
