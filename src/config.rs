//! The Bridge's pairing and driver settings, in the same file and format as earlier versions.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub server: String,
    pub device_id: String,
    pub account_id: String,
    pub name: String,
    pub private_key_pem: String,
    pub driver: String,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub driver_options: BTreeMap<String, String>,

    // Private local MCP endpoint. None of these ever leave this computer.
    /// Hex; keys the recipient tags the server sees.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub tag_key: String,
    /// Bearer token for http://127.0.0.1:<port>/mcp.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub local_token: String,
    #[serde(skip_serializing_if = "is_zero")]
    pub local_port: u16,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub no_open_approvals: bool,
}

fn is_zero(n: &u16) -> bool {
    *n == 0
}

/// Where the private MCP endpoint listens on 127.0.0.1.
pub const DEFAULT_LOCAL_PORT: u16 = 47300;

pub const NOT_PAIRED: &str = "this computer is not paired yet: run `pocketwire pair <code>` first";

#[derive(Debug)]
pub enum LoadError {
    NotPaired,
    Other(String),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::NotPaired => f.write_str(NOT_PAIRED),
            LoadError::Other(e) => f.write_str(e),
        }
    }
}

impl From<LoadError> for String {
    fn from(e: LoadError) -> String {
        e.to_string()
    }
}

impl Config {
    /// Fills in the local endpoint's secrets and port; reports whether anything changed.
    pub fn ensure_local(&mut self) -> bool {
        let mut changed = false;
        if self.tag_key.is_empty() {
            self.tag_key = crate::util::random_hex(32);
            changed = true;
        }
        if self.local_token.is_empty() {
            self.local_token = format!("pwl_{}", crate::util::random_hex(24));
            changed = true;
        }
        if self.local_port == 0 {
            self.local_port = DEFAULT_LOCAL_PORT;
            changed = true;
        }
        changed
    }
}

/// The user's configuration directory, as Go's os.UserConfigDir defines it.
pub fn user_config_dir() -> Result<PathBuf, String> {
    let env = |k: &str| std::env::var_os(k).filter(|v| !v.is_empty()).map(PathBuf::from);
    if cfg!(windows) {
        return env("APPDATA").ok_or_else(|| "%AppData% is not set".to_string());
    }
    let home = env("HOME").ok_or("$HOME is not set")?;
    if cfg!(target_os = "macos") {
        return Ok(home.join("Library").join("Application Support"));
    }
    Ok(env("XDG_CONFIG_HOME").unwrap_or_else(|| home.join(".config")))
}

pub fn home_dir() -> Result<PathBuf, String> {
    let k = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(k).filter(|v| !v.is_empty()).map(PathBuf::from).ok_or_else(|| format!("{k} is not set"))
}

/// <user config dir>/pocketwire/config.json, overridable with POCKETWIRE_CONFIG.
pub fn default_path() -> Result<PathBuf, String> {
    if let Some(p) = std::env::var_os("POCKETWIRE_CONFIG").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(p));
    }
    Ok(user_config_dir()?.join("pocketwire").join("config.json"))
}

/// A file next to the config (messages.json, phones.json, panel.key, certs/).
pub fn sibling(config: &Path, name: &str) -> PathBuf {
    config.parent().unwrap_or(Path::new(".")).join(name)
}

pub fn load(path: &Path) -> Result<Config, LoadError> {
    let b = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(LoadError::NotPaired),
        Err(e) => return Err(LoadError::Other(format!("{}: {e}", path.display()))),
    };
    let c: Config = serde_json::from_slice(&b).map_err(|e| LoadError::Other(format!("{}: {e}", path.display())))?;
    if c.device_id.is_empty() || c.private_key_pem.is_empty() || c.server.is_empty() {
        return Err(LoadError::NotPaired);
    }
    Ok(c)
}

/// Writes the config readable only by this user (it holds the device's private key).
pub fn save(path: &Path, c: &Config) -> Result<(), String> {
    let b = serde_json::to_vec_pretty(c).map_err(|e| e.to_string())?;
    write_private(path, &b)
}

pub fn remove(path: &Path) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.to_string()),
        _ => Ok(()),
    }
}

/// Writes a file with 0600 permissions through a temporary file, creating its directory (0700).
pub fn write_private(path: &Path, data: &[u8]) -> Result<(), String> {
    let dir = path.parent().unwrap_or(Path::new("."));
    create_private_dir(dir)?;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    {
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let mut f = o.open(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
        std::io::Write::write_all(&mut f, data).map_err(|e| e.to_string())?;
    }
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("{}: {e}", path.display())
    })
}

pub fn create_private_dir(dir: &Path) -> Result<(), String> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir).map_err(|e| format!("{}: {e}", dir.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_go_config_and_keeps_fields() {
        let dir = std::env::temp_dir().join(format!("pw-cfg-{}", crate::util::random_hex(4)));
        let p = dir.join("config.json");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&p, r#"{"server":"https://pocketwire.app","device_id":"dev_1","account_id":"acc","name":"Laptop","private_key_pem":"x","driver":"kdeconnect","driver_options":{"device":"abc"},"local_port":47300}"#).unwrap();
        let mut c = load(&p).unwrap();
        assert_eq!(c.driver_options.get("device").map(String::as_str), Some("abc"));
        assert!(c.ensure_local());
        assert!(c.local_token.starts_with("pwl_") && c.local_token.len() == 52);
        assert_eq!(c.tag_key.len(), 64);
        assert!(!c.ensure_local());
        save(&p, &c).unwrap();
        let again = load(&p).unwrap();
        assert_eq!(again.local_token, c.local_token);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        }
        remove(&p).unwrap();
        assert!(matches!(load(&p), Err(LoadError::NotPaired)));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
