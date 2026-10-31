//! Pairing with Pocketwire and the device connection: authenticate, run commands, reconnect.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;

use crate::driver::{BoxFuture, Driver};
use crate::logf;
use crate::net;
use crate::protocol::{self, DeviceKey, Frame};

/// Relayed sends from the cloud, and private sends from the local MCP endpoint (the server never
/// sees their number or text).
pub const CAPABILITIES: [&str; 2] = ["sms.send", "sms.private"];

pub const OFFLINE: &str = "the Bridge is not connected to Pocketwire right now";
pub const REVOKED: &str = "this device was removed from your Pocketwire account; pair it again";

/// The platform names the server accepts.
pub fn platform() -> &'static str {
    match std::env::consts::OS {
        "macos" => "macos",
        "windows" => "windows",
        _ => "linux",
    }
}

#[derive(Debug, Deserialize)]
pub struct PairResult {
    pub device_id: String,
    #[serde(default)]
    pub account_id: String,
}

/// Registers this computer's public key with a dashboard pairing code.
pub async fn pair(server: &str, code: &str, name: &str, key: &DeviceKey) -> Result<PairResult, String> {
    let body = serde_json::json!({
        "code": protocol::normalize_pairing_code(code),
        "name": name,
        "platform": platform(),
        "kind": "bridge",
        "capabilities": CAPABILITIES,
        "public_key": key.public_spki(),
    });
    let url = format!("{}/v1/device/pair", server.trim_end_matches('/'));
    let res = net::request("POST", &url, &[("content-type", "application/json".into())], Bytes::from(body.to_string()), 64 << 10).await?;
    if res.status != 201 {
        let msg = serde_json::from_slice::<serde_json::Value>(&res.body)
            .ok()
            .and_then(|v| v.get("message").and_then(|m| m.as_str()).map(str::to_string))
            .filter(|m| !m.is_empty())
            .unwrap_or_else(|| {
                format!("{} {}", res.status, hyper::StatusCode::from_u16(res.status).ok().and_then(|s| s.canonical_reason()).unwrap_or("")).trim().to_string()
            });
        return Err(format!("pairing failed: {msg}"));
    }
    serde_json::from_slice(&res.body).map_err(|e| format!("pairing failed: {e}"))
}

/// The delay before reconnect attempt n (0-based): 1s, 2s, 4s … capped at 60s, ±20% jitter.
pub fn backoff(n: u32) -> Duration {
    let base = (1u64 << n.min(6)).min(60) as f64;
    let r = crate::util::random_bytes(2);
    let jitter = 0.8 + (u16::from_le_bytes([r[0], r[1]]) as f64 / 65535.0) * 0.4;
    Duration::from_secs_f64(base * jitter)
}

/// What the local engine needs from the connection.
pub trait Upstream: Send + Sync {
    fn connected(&self) -> bool;
    /// Asks the server whether a private message may go out (only tag, length and segments leave).
    fn decide(&self, f: Frame) -> BoxFuture<Result<Frame, String>>;
    /// Sends a status update; while offline it is kept and sent after reconnecting.
    fn report(&self, message_id: &str, status: &str, error: &str);
}

/// Remembers the last n command ids.
struct Seen {
    n: usize,
    order: VecDeque<String>,
    set: HashSet<String>,
}

impl Seen {
    fn add(&mut self, id: &str) -> bool {
        if !self.set.insert(id.to_string()) {
            return false;
        }
        self.order.push_back(id.to_string());
        if self.order.len() > self.n {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
        true
    }
}

struct State {
    send: Option<mpsc::UnboundedSender<Frame>>,
    waiting: HashMap<String, oneshot::Sender<Frame>>,
    outbox: VecDeque<Frame>,
    seen: Seen,
}

type TrustedHook = Box<dyn Fn(Vec<String>) + Send + Sync>;

/// Keeps a connection open, runs commands and reconnects with backoff.
pub struct Runner {
    pub server: String,
    pub device_id: String,
    key: Arc<DeviceKey>,
    pub driver: Driver,
    on_trusted: Mutex<Option<TrustedHook>>,
    st: Mutex<State>,
}

impl Runner {
    pub fn new(server: &str, device_id: &str, key: Arc<DeviceKey>, driver: Driver) -> Arc<Runner> {
        Arc::new(Runner {
            server: server.to_string(),
            device_id: device_id.to_string(),
            key,
            driver,
            on_trusted: Mutex::new(None),
            st: Mutex::new(State {
                send: None,
                waiting: HashMap::new(),
                outbox: VecDeque::new(),
                seen: Seen { n: 500, order: VecDeque::new(), set: HashSet::new() },
            }),
        })
    }

    /// Receives the account's trusted numbers whenever the server sends them.
    pub fn on_trusted(&self, f: impl Fn(Vec<String>) + Send + Sync + 'static) {
        *self.on_trusted.lock().unwrap() = Some(Box::new(f));
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn is_connected(&self) -> bool {
        self.lock().send.is_some()
    }

    /// Asks whether a bearer token (sent as its SHA-256) is valid for this Bridge.
    pub async fn introspect(&self, token_hash: &str) -> Result<Frame, String> {
        let mut f = Frame::new("introspect");
        f.request_id = crate::util::random_hex(12);
        f.token_hash = token_hash.to_string();
        self.request(f).await
    }

    /// Sends a frame with a request_id and waits for the answer carrying the same id.
    async fn request(&self, f: Frame) -> Result<Frame, String> {
        let (tx, rx) = oneshot::channel();
        let id = f.request_id.clone();
        {
            let mut st = self.lock();
            let Some(send) = st.send.clone() else { return Err(OFFLINE.into()) };
            st.waiting.insert(id.clone(), tx);
            if send.send(f).is_err() {
                st.waiting.remove(&id);
                return Err(OFFLINE.into());
            }
        }
        let out = tokio::time::timeout(Duration::from_secs(15), rx).await;
        self.lock().waiting.remove(&id);
        match out {
            Ok(Ok(f)) => Ok(f),
            Ok(Err(_)) => Err(OFFLINE.into()),
            Err(_) => Err("the server did not answer in time".into()),
        }
    }

    fn set_send(&self, send: Option<mpsc::UnboundedSender<Frame>>) {
        let mut st = self.lock();
        if let Some(s) = &send {
            for f in st.outbox.drain(..).collect::<Vec<_>>() {
                let _ = s.send(f);
            }
        } else {
            st.waiting.clear();
        }
        st.send = send;
    }

    /// Runs until `stop` fires (Ok) or the device is revoked (Err(REVOKED)).
    pub async fn run(self: Arc<Self>, stop: CancellationToken) -> Result<(), String> {
        let mut attempt = 0u32;
        loop {
            let (connected, err) = tokio::select! {
                r = self.session(&stop) => r,
                _ = stop.cancelled() => return Ok(()),
            };
            if stop.is_cancelled() {
                return Ok(());
            }
            if err == REVOKED {
                return Err(err);
            }
            if connected {
                attempt = 0;
            }
            let wait = backoff(attempt);
            attempt += 1;
            logf!("disconnected ({err}); reconnecting in {:.1}s", wait.as_secs_f64());
            tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                _ = stop.cancelled() => return Ok(()),
            }
        }
    }

    /// One connection; returns whether the server accepted the Bridge and why it ended.
    async fn session(self: &Arc<Self>, stop: &CancellationToken) -> (bool, String) {
        let url = match net::Url::with_path(&self.server, "/v1/device/ws") {
            Ok(u) => u,
            Err(e) => return (false, e),
        };
        let ws = match net::websocket(&url, 64 << 10).await {
            Ok(ws) => ws,
            Err(e) => return (false, e),
        };
        let (mut sink, mut stream) = ws.split();
        let (tx, mut rx) = mpsc::unbounded_channel::<Frame>();
        let sess = stop.child_token();
        let _guard = sess.clone().drop_guard();
        let writer_stop = sess.clone();
        tokio::spawn(async move {
            while let Some(f) = tokio::select! { f = rx.recv() => f, _ = writer_stop.cancelled() => None } {
                let text = serde_json::to_string(&f).unwrap_or_default();
                match tokio::time::timeout(Duration::from_secs(10), sink.send(Message::text(text))).await {
                    Ok(Ok(())) => {}
                    _ => break,
                }
            }
            writer_stop.cancel();
            let _ = sink.close().await;
        });
        // Keepalive: the server drops silent sockets after 60 seconds.
        let ping_tx = tx.clone();
        let ping_stop = sess.clone();
        tokio::spawn(async move {
            let mut t = tokio::time::interval(Duration::from_secs(25));
            t.tick().await;
            loop {
                tokio::select! {
                    _ = t.tick() => { if ping_tx.send(Frame::new("ping")).is_err() { return } }
                    _ = ping_stop.cancelled() => return,
                }
            }
        });
        let mut connected = false;
        let end = loop {
            let msg = tokio::select! {
                m = stream.next() => m,
                _ = sess.cancelled() => break "connection closed".to_string(),
            };
            let data = match msg {
                Some(Ok(Message::Text(t))) => t.to_string(),
                Some(Ok(Message::Binary(b))) => String::from_utf8_lossy(&b).into_owned(),
                Some(Ok(Message::Close(c))) => break c.map(|c| format!("closed: {} {}", u16::from(c.code), c.reason)).unwrap_or_else(|| "closed".into()),
                Some(Ok(_)) => continue,
                Some(Err(e)) => break e.to_string(),
                None => break "connection closed".to_string(),
            };
            let Ok(f) = serde_json::from_str::<Frame>(&data) else { continue };
            match f.typ.as_str() {
                "challenge" => {
                    let sig = match self.key.sign(&protocol::challenge_string(&f.nonce, &self.device_id)) {
                        Ok(s) => s,
                        Err(e) => break e,
                    };
                    let mut hello = Frame::new("hello");
                    hello.device_id = self.device_id.clone();
                    hello.signature = sig;
                    hello.app_version = net::version().to_string();
                    hello.capabilities = CAPABILITIES.iter().map(|s| s.to_string()).collect();
                    let _ = tx.send(hello);
                }
                "ready" => {
                    connected = true;
                    self.set_send(Some(tx.clone()));
                    logf!("connected to {} as {} (driver {})", self.server, self.device_id, self.driver.name());
                }
                "trusted" => {
                    if let Some(cb) = self.on_trusted.lock().unwrap().as_ref() {
                        cb(f.numbers);
                    }
                }
                "send_decision" | "introspection" => {
                    if let Some(w) = self.lock().waiting.remove(&f.request_id) {
                        let _ = w.send(f);
                    }
                }
                "ping" => {
                    let _ = tx.send(Frame::new("pong"));
                }
                "error" => {
                    if f.code == "device_revoked" {
                        break REVOKED.to_string();
                    }
                    break format!("server error {}: {}", f.code, f.message);
                }
                "command" => {
                    let me = self.clone();
                    let tx = tx.clone();
                    let s = sess.clone();
                    tokio::spawn(async move {
                        tokio::select! { _ = me.handle(f, tx) => {}, _ = s.cancelled() => {} }
                    });
                }
                _ => {}
            }
        };
        self.set_send(None);
        (connected, end)
    }

    async fn handle(&self, f: Frame, tx: mpsc::UnboundedSender<Frame>) {
        let mut ack = Frame::new("ack");
        ack.id = f.id.clone();
        let _ = tx.send(ack);
        if !self.lock().seen.add(&f.id) {
            return;
        }
        let status = |s: &str, e: &str| {
            let mut st = Frame::new("status");
            st.id = f.id.clone();
            st.status = s.to_string();
            st.error = e.to_string();
            let _ = tx.send(st);
        };
        if f.command != "sms.send" {
            return status("failed", "unsupported_command");
        }
        if f.expires_at > 0 && crate::util::now_secs() > f.expires_at {
            return status("failed", "expired");
        }
        if f.approval == "device" {
            // Bridges have no approval screen; the server routes their approvals to the dashboard.
            return status("rejected", "approval_unsupported");
        }
        let Some(p) = f.params.as_ref().filter(|p| protocol::validate_params(Some(p)).is_ok()) else {
            return status("failed", "invalid_params");
        };
        status("sending", "");
        match tokio::time::timeout(Duration::from_secs(60), self.driver.send_sms(&p.to, &p.body)).await {
            Ok(Ok(())) => {
                logf!("sent {}", f.id);
                status("sent", "");
            }
            Ok(Err(e)) => {
                logf!("send {} failed: {e}", f.id);
                status("failed", &crate::util::truncate(&e, 190));
            }
            Err(_) => {
                logf!("send {} failed: timed out", f.id);
                status("failed", "timed out");
            }
        }
    }
}

impl Upstream for Runner {
    fn connected(&self) -> bool {
        self.is_connected()
    }

    fn decide(&self, mut f: Frame) -> BoxFuture<Result<Frame, String>> {
        f.typ = "send_request".into();
        // The future must not borrow self; take what it needs.
        let (tx, rx) = oneshot::channel();
        let id = f.request_id.clone();
        let sent = {
            let mut st = self.lock();
            match st.send.clone() {
                Some(send) => {
                    st.waiting.insert(id.clone(), tx);
                    send.send(f).is_ok()
                }
                None => false,
            }
        };
        Box::pin(async move {
            if !sent {
                return Err(OFFLINE.to_string());
            }
            match tokio::time::timeout(Duration::from_secs(15), rx).await {
                Ok(Ok(f)) => Ok(f),
                Ok(Err(_)) => Err(OFFLINE.to_string()),
                Err(_) => Err("the server did not answer in time".to_string()),
            }
        })
    }

    fn report(&self, message_id: &str, status: &str, error: &str) {
        let mut f = Frame::new("status");
        f.id = message_id.to_string();
        f.status = status.to_string();
        f.error = error.to_string();
        let mut st = self.lock();
        let sent = st.send.as_ref().map(|s| s.send(f.clone()).is_ok()).unwrap_or(false);
        if !sent {
            st.outbox.push_back(f);
            if st.outbox.len() > 500 {
                st.outbox.pop_front();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_and_caps() {
        for (n, want) in [(0u32, 1.0f64), (3, 8.0), (6, 60.0), (20, 60.0)] {
            let d = backoff(n).as_secs_f64();
            assert!(d >= want * 0.8 - 1e-9 && d <= want * 1.2 + 1e-9, "{n}: {d}");
        }
    }

    #[test]
    fn remembers_command_ids() {
        let mut s = Seen { n: 2, order: VecDeque::new(), set: HashSet::new() };
        assert!(s.add("a") && s.add("b") && !s.add("a"));
        assert!(s.add("c") && s.add("a"));
    }
}
