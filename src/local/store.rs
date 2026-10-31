//! The private messages this computer remembers (in memory and in a 0600 file).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use crate::util;

/// Times are kept as Unix milliseconds and stored as RFC 3339 text, as the Go Bridge did.
mod time_fmt {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(ms: &i64, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&crate::util::rfc3339(*ms, true))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<i64, D::Error> {
        let s = String::deserialize(d)?;
        Ok(crate::util::parse_rfc3339(&s).unwrap_or(0))
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Message {
    pub id: String,
    pub to: String,
    pub body: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
    /// "device" (approve on this computer) or "none".
    #[serde(default)]
    pub approval: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub client_name: String,
    #[serde(with = "time_fmt")]
    pub created_at: i64,
    #[serde(with = "time_fmt")]
    pub updated_at: i64,
    #[serde(with = "time_fmt")]
    pub expires_at: i64,
}

impl Message {
    /// Whether the status can no longer change.
    pub fn is_final(&self) -> bool {
        matches!(self.status.as_str(), "sent" | "delivered" | "failed" | "rejected" | "expired")
    }
}

const KEEP: usize = 200;

pub struct Store {
    path: Option<PathBuf>,
    by_id: Mutex<HashMap<String, Message>>,
    changed: watch::Sender<u64>,
}

impl Store {
    pub fn new(path: Option<PathBuf>) -> Store {
        let mut by_id = HashMap::new();
        if let Some(p) = &path {
            if let Ok(b) = std::fs::read(p) {
                if let Ok(list) = serde_json::from_slice::<Vec<Message>>(&b) {
                    for m in list {
                        by_id.insert(m.id.clone(), m);
                    }
                }
            }
        }
        Store { path, by_id: Mutex::new(by_id), changed: watch::channel(0).0 }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Message>> {
        self.by_id.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn get(&self, id: &str) -> Option<Message> {
        self.lock().get(id).cloned()
    }

    pub fn put(&self, m: Message) {
        let mut g = self.lock();
        g.insert(m.id.clone(), m);
        self.changed_locked(&mut g);
    }

    /// Changes a message in place; `f` returns false to leave it unchanged.
    pub fn update(&self, id: &str, f: impl FnOnce(&mut Message) -> bool) -> Option<(Message, bool)> {
        let mut g = self.lock();
        let m = g.get_mut(id)?;
        let mut copy = m.clone();
        if !f(&mut copy) {
            return Some((m.clone(), false));
        }
        copy.updated_at = util::now_ms();
        *m = copy.clone();
        self.changed_locked(&mut g);
        Some((copy, true))
    }

    /// Up to n messages, newest first.
    pub fn recent(&self, n: usize) -> Vec<Message> {
        sorted(&self.lock(), n)
    }

    /// Messages waiting for approval on this computer, oldest first.
    pub fn pending(&self, now_ms: i64) -> Vec<Message> {
        let mut out: Vec<Message> = self.lock().values().filter(|m| m.status == "awaiting_approval" && now_ms < m.expires_at).cloned().collect();
        out.sort_by_key(|m| m.created_at);
        out
    }

    /// A receiver that sees every later change.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.changed.subscribe()
    }

    fn changed_locked(&self, g: &mut HashMap<String, Message>) {
        self.changed.send_modify(|n| *n += 1);
        let keep = sorted(g, KEEP);
        if keep.len() < g.len() {
            *g = keep.iter().map(|m| (m.id.clone(), m.clone())).collect();
        }
        if let Some(p) = &self.path {
            if let Ok(b) = serde_json::to_vec(&keep) {
                if let Some(dir) = p.parent() {
                    let _ = crate::config::create_private_dir(dir);
                }
                let _ = crate::config::write_private(p, &b);
            }
        }
    }
}

fn sorted(g: &HashMap<String, Message>, n: usize) -> Vec<Message> {
    let mut out: Vec<Message> = g.values().cloned().collect();
    out.sort_by_key(|m| std::cmp::Reverse(m.created_at));
    if n > 0 && out.len() > n {
        out.truncate(n);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_go_files_and_keeps_the_newest() {
        let dir = std::env::temp_dir().join(format!("pw-store-{}", util::random_hex(4)));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("messages.json");
        std::fs::write(&p, r#"[{"id":"a","to":"+48501234567","body":"hi","status":"sent","approval":"none","created_at":"2026-10-30T12:00:00.123456789+01:00","updated_at":"2026-10-30T12:00:01+01:00","expires_at":"0001-01-01T00:00:00Z"}]"#).unwrap();
        let s = Store::new(Some(p.clone()));
        let m = s.get("a").unwrap();
        assert_eq!(util::rfc3339(m.created_at, true), "2026-10-30T11:00:00.123Z");
        for i in 0..KEEP + 5 {
            s.put(Message { id: format!("m{i}"), status: "queued".into(), created_at: util::now_ms() + i as i64, ..Default::default() });
        }
        assert_eq!(s.recent(0).len(), KEEP);
        assert!(s.get("a").is_none());
        let again = Store::new(Some(p));
        assert_eq!(again.recent(0).len(), KEEP);
        assert_eq!(again.recent(1)[0].id, format!("m{}", KEEP + 4));
        let _ = std::fs::remove_dir_all(dir);
    }
}
