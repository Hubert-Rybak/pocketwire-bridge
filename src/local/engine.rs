//! Sends private messages: asks the server for a decision without revealing the number or the
//! text, waits for approval on this computer when needed, then hands the text to the driver.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::client::Upstream;
use crate::driver::Driver;
use crate::local::store::{Message, Store};
use crate::logf;
use crate::protocol::{self, CommandParams, Frame};
use crate::util;

pub const NOT_FOUND: &str = "no such message on this computer";

pub type ApprovalHook = Box<dyn Fn(&Message) + Send + Sync>;

pub struct Engine {
    pub up: Arc<dyn Upstream>,
    pub driver: Driver,
    pub store: Arc<Store>,
    /// Keys the recipient tags; it never leaves this computer.
    pub tag_key: Vec<u8>,
    /// Called when a message starts waiting for approval (opens the approval page).
    pub on_approval: Mutex<Option<ApprovalHook>>,
    trusted: Mutex<HashSet<String>>,
}

impl Engine {
    pub fn new(up: Arc<dyn Upstream>, driver: Driver, store: Arc<Store>, tag_key: Vec<u8>) -> Arc<Engine> {
        Arc::new(Engine { up, driver, store, tag_key, on_approval: Mutex::new(None), trusted: Mutex::new(HashSet::new()) })
    }

    /// Replaces the trusted numbers (sent by the server; the user manages them in the dashboard).
    pub fn set_trusted(&self, numbers: &[String]) {
        *self.trusted.lock().unwrap() = numbers.iter().map(|n| protocol::normalize_phone(n)).collect();
    }

    fn is_trusted(&self, to: &str) -> bool {
        self.trusted.lock().unwrap().contains(to)
    }

    /// Starts a private message and returns it in its first state; Err is shown to the AI app.
    pub async fn send(self: &Arc<Self>, to: &str, body: &str, client_name: &str) -> Result<Message, String> {
        let p = CommandParams { to: protocol::normalize_phone(to), body: body.to_string() };
        if protocol::validate_params(Some(&p)).is_err() {
            let n = body.chars().count();
            if n == 0 || n > protocol::MAX_BODY {
                return Err("Message must be 1–1600 characters.".into());
            }
            return Err("Phone number must be in international E.164 format, e.g. +48501234567.".into());
        }
        if !self.up.connected() {
            return Err(
                "The Pocketwire Bridge on this computer is not connected to Pocketwire right now. Check the internet connection, then try again.".into()
            );
        }
        let client_name = util::truncate(client_name, 80);
        let mut f = Frame::new("send_request");
        f.request_id = util::random_hex(12);
        f.to_tag = protocol::recipient_tag(&self.tag_key, &p.to);
        f.body_len = p.body.chars().count() as i64;
        f.segments = protocol::segments(&p.body);
        f.trusted = self.is_trusted(&p.to);
        f.client_name = client_name.clone();
        let d = self.up.decide(f).await.map_err(|e| format!("Could not reach Pocketwire to check limits: {e}"))?;
        if d.ok != Some(true) {
            return Err(if d.message.is_empty() { "Pocketwire refused this message.".into() } else { d.message });
        }
        let t = util::now_ms();
        let mut m = Message {
            id: d.message_id,
            to: p.to,
            body: p.body,
            approval: d.approval,
            client_name,
            created_at: t,
            updated_at: t,
            expires_at: d.expires_at * 1000,
            ..Default::default()
        };
        if m.approval == "device" {
            m.status = "awaiting_approval".into();
            self.store.put(m.clone());
            logf!("message {} waits for approval on this computer", m.id);
            let me = self.clone();
            let (id, at) = (m.id.clone(), m.expires_at);
            tokio::spawn(async move { me.expire_later(id, at).await });
            if let Some(cb) = self.on_approval.lock().unwrap().as_ref() {
                cb(&m);
            }
            return Ok(m);
        }
        m.status = "queued".into();
        self.store.put(m.clone());
        let me = self.clone();
        let id = m.id.clone();
        tokio::spawn(async move { me.deliver(id).await });
        Ok(m)
    }

    /// Sends a message that waits for approval; false if it no longer waits.
    pub fn approve(self: &Arc<Self>, id: &str) -> bool {
        let now = util::now_ms();
        let ok = matches!(
            self.store.update(id, |m| {
                if m.status != "awaiting_approval" || now >= m.expires_at {
                    return false;
                }
                m.status = "queued".into();
                true
            }),
            Some((_, true))
        );
        if ok {
            let me = self.clone();
            let id = id.to_string();
            tokio::spawn(async move { me.deliver(id).await });
        }
        ok
    }

    /// Drops a message that waits for approval.
    pub fn reject(&self, id: &str) -> bool {
        let ok = matches!(
            self.store.update(id, |m| {
                if m.status != "awaiting_approval" {
                    return false;
                }
                m.status = "rejected".into();
                m.error = "rejected_by_user".into();
                true
            }),
            Some((_, true))
        );
        if ok {
            self.up.report(id, "rejected", "rejected_by_user");
        }
        ok
    }

    async fn expire_later(&self, id: String, at_ms: i64) {
        let wait = (at_ms - util::now_ms()).max(0) as u64 + 1000;
        tokio::time::sleep(Duration::from_millis(wait)).await;
        // The server expires its own record at the same time; nothing to report.
        self.store.update(&id, |m| {
            if m.status != "awaiting_approval" {
                return false;
            }
            m.status = "expired".into();
            m.error = "approval_timeout".into();
            true
        });
    }

    fn set(&self, id: &str, status: &str, err: &str) {
        self.store.update(id, |m| {
            m.status = status.into();
            m.error = err.into();
            true
        });
        self.up.report(id, status, err);
    }

    async fn deliver(&self, id: String) {
        let Some(m) = self.store.get(&id) else { return };
        self.set(&id, "sending", "");
        match tokio::time::timeout(Duration::from_secs(60), self.driver.send_sms(&m.to, &m.body)).await {
            Ok(Ok(())) => {
                logf!("private message {id} sent");
                self.set(&id, "sent", "");
            }
            Ok(Err(e)) => {
                logf!("private message {id} failed: {e}");
                self.set(&id, "failed", &util::truncate(&e, 190));
            }
            Err(_) => {
                logf!("private message {id} failed: timed out");
                self.set(&id, "failed", "timed out");
            }
        }
    }

    /// The message once it is final, or as it stands after `timeout`.
    pub async fn wait(&self, id: &str, timeout: Duration) -> Option<Message> {
        let mut rx = self.store.subscribe();
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let m = self.store.get(id)?;
            if m.is_final() {
                return Some(m);
            }
            tokio::select! {
                r = rx.changed() => if r.is_err() { return Some(m) },
                _ = tokio::time::sleep_until(deadline) => return Some(m),
            }
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::driver::BoxFuture;

    #[derive(Default)]
    pub struct FakeUp {
        pub decision: Mutex<Frame>,
        pub asked: Mutex<Vec<Frame>>,
        pub reports: Mutex<Vec<(String, String, String)>>,
    }

    impl Upstream for FakeUp {
        fn connected(&self) -> bool {
            true
        }
        fn decide(&self, f: Frame) -> BoxFuture<Result<Frame, String>> {
            self.asked.lock().unwrap().push(f);
            let d = self.decision.lock().unwrap().clone();
            Box::pin(async move { Ok(d) })
        }
        fn report(&self, id: &str, s: &str, e: &str) {
            self.reports.lock().unwrap().push((id.into(), s.into(), e.into()));
        }
    }

    pub fn engine(approval: &str) -> (Arc<Engine>, Arc<FakeUp>) {
        let up = Arc::new(FakeUp::default());
        let mut d = Frame::new("send_decision");
        d.ok = Some(true);
        d.message_id = "msg_1".into();
        d.approval = approval.into();
        d.expires_at = util::now_secs() + 600;
        *up.decision.lock().unwrap() = d;
        let driver = Driver::new("dry-run", &Default::default(), None).unwrap();
        let e = Engine::new(up.clone(), driver, Arc::new(Store::new(None)), b"tagkey".to_vec());
        (e, up)
    }

    #[tokio::test]
    async fn sends_without_revealing_number_or_text() {
        let (e, up) = engine("none");
        e.set_trusted(&["+48 501 234 567".into()]);
        let m = e.send("+48 501 234 567", "Hello", "Test app").await.unwrap();
        assert_eq!(m.to, "+48501234567");
        let m = e.wait(&m.id, Duration::from_secs(2)).await.unwrap();
        assert_eq!(m.status, "sent");
        let f = up.asked.lock().unwrap()[0].clone();
        let wire = serde_json::to_string(&f).unwrap();
        assert!(!wire.contains("501234567") && !wire.contains("Hello"), "{wire}");
        assert!(f.trusted);
        assert_eq!(f.body_len, 5);
        assert_eq!(f.to_tag, protocol::recipient_tag(b"tagkey", "+48501234567"));
        let r = up.reports.lock().unwrap().clone();
        assert_eq!(r.iter().map(|x| x.1.as_str()).collect::<Vec<_>>(), ["sending", "sent"]);
    }

    #[tokio::test]
    async fn waits_for_approval() {
        let (e, up) = engine("device");
        let opened = Arc::new(Mutex::new(0));
        let o = opened.clone();
        *e.on_approval.lock().unwrap() = Some(Box::new(move |_| *o.lock().unwrap() += 1));
        let m = e.send("+48501234567", "Hi", "").await.unwrap();
        assert_eq!(m.status, "awaiting_approval");
        assert_eq!(*opened.lock().unwrap(), 1);
        assert_eq!(e.store.pending(util::now_ms()).len(), 1);
        assert!(e.approve(&m.id));
        assert!(!e.approve(&m.id));
        assert_eq!(e.wait(&m.id, Duration::from_secs(2)).await.unwrap().status, "sent");
        let m2 = e.send("+48501234567", "Hi", "").await;
        assert!(m2.is_ok());
        assert!(e.reject("msg_1") || up.reports.lock().unwrap().iter().any(|r| r.1 == "rejected"));
    }

    #[tokio::test]
    async fn refuses_bad_input_and_server_no() {
        let (e, up) = engine("none");
        assert_eq!(e.send("12", "x", "").await.unwrap_err(), "Phone number must be in international E.164 format, e.g. +48501234567.");
        assert_eq!(e.send("+48501234567", "", "").await.unwrap_err(), "Message must be 1–1600 characters.");
        let mut d = Frame::new("send_decision");
        d.ok = Some(false);
        d.message = "Daily limit reached.".into();
        *up.decision.lock().unwrap() = d;
        assert_eq!(e.send("+48501234567", "x", "").await.unwrap_err(), "Daily limit reached.");
    }
}
