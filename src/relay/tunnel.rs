//! The outbound tunnel to Pocketwire's blind relay. AI apps in the cloud reach the Bridge at
//! https://<label>.b.pocketwire.app; the server forwards their TLS connections, still encrypted,
//! over this tunnel, and the Bridge terminates TLS itself. The server never holds the
//! certificate's key, so it cannot read the requests.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;

use crate::logf;
use crate::net;
use crate::protocol::{self, DeviceKey, Frame};

// Frame types on the tunnel: [type u8][stream u32 BE][payload].
const OPEN: u8 = 1;
const DATA: u8 = 2;
const CLOSE: u8 = 3;

const MAX_CHUNK: usize = 32 * 1024;
const MAX_BUFFERED: usize = 8 << 20;
const MAX_STREAMS: usize = 64;

fn header(typ: u8, id: u32) -> Vec<u8> {
    let mut b = Vec::with_capacity(5 + MAX_CHUNK);
    b.push(typ);
    b.extend_from_slice(&id.to_be_bytes());
    b
}

/// One forwarded TCP connection, still carrying the AI app's TLS.
pub struct Conn {
    pub io: DuplexStream,
    pub remote: String,
}

struct Inbound {
    tx: mpsc::UnboundedSender<Bytes>,
    buffered: Arc<AtomicUsize>,
}

pub struct Tunnel {
    pub server: String,
    pub device_id: String,
    key: Arc<DeviceKey>,
    /// Called with the Bridge's public host name each time the tunnel is ready.
    on_hostname: Box<dyn Fn(&str) + Send + Sync>,
    streams: Mutex<HashMap<u32, Inbound>>,
}

impl Tunnel {
    pub fn new(server: &str, device_id: &str, key: Arc<DeviceKey>, on_hostname: impl Fn(&str) + Send + Sync + 'static) -> Arc<Tunnel> {
        Arc::new(Tunnel { server: server.into(), device_id: device_id.into(), key, on_hostname: Box::new(on_hostname), streams: Mutex::new(HashMap::new()) })
    }

    /// Keeps the tunnel up until `stop` fires, handing each incoming stream to `accept`.
    pub async fn run(self: Arc<Self>, accept: mpsc::Sender<Conn>, stop: CancellationToken) {
        let mut attempt = 0u32;
        loop {
            let (ready, err) = tokio::select! {
                r = self.session(&accept, &stop) => r,
                _ = stop.cancelled() => return,
            };
            self.drop_all();
            if stop.is_cancelled() {
                return;
            }
            if ready {
                attempt = 0;
            }
            let wait = crate::client::backoff(attempt);
            attempt += 1;
            logf!("relay tunnel down ({err}); reconnecting in {:.1}s", wait.as_secs_f64());
            tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                _ = stop.cancelled() => return,
            }
        }
    }

    fn drop_all(&self) {
        // Dropping the senders ends each stream's input (EOF for the TLS side).
        self.streams.lock().unwrap().clear();
    }

    async fn session(self: &Arc<Self>, accept: &mpsc::Sender<Conn>, stop: &CancellationToken) -> (bool, String) {
        let url = match net::Url::with_path(&self.server, "/v1/device/tunnel") {
            Ok(u) => u,
            Err(e) => return (false, e),
        };
        let ws = match net::websocket(&url, 64 * 1024 + 5).await {
            Ok(ws) => ws,
            Err(e) => return (false, e),
        };
        let (mut sink, mut stream) = ws.split();
        let sess = stop.child_token();
        let _guard = sess.clone().drop_guard();
        let (out_tx, mut out_rx) = mpsc::channel::<Message>(64);
        let writer_stop = sess.clone();
        tokio::spawn(async move {
            while let Some(m) = tokio::select! { m = out_rx.recv() => m, _ = writer_stop.cancelled() => None } {
                match tokio::time::timeout(Duration::from_secs(30), sink.send(m)).await {
                    Ok(Ok(())) => {}
                    _ => break,
                }
            }
            writer_stop.cancel();
            let _ = sink.close().await;
        });
        let mut ready = false;
        loop {
            let msg = tokio::select! {
                m = stream.next() => m,
                _ = sess.cancelled() => return (ready, "connection closed".into()),
            };
            let data = match msg {
                Some(Ok(Message::Text(t))) => {
                    let Ok(f) = serde_json::from_str::<Frame>(&t) else { continue };
                    match f.typ.as_str() {
                        "challenge" => {
                            let sig = match self.key.sign(&protocol::tunnel_challenge_string(&f.nonce, &self.device_id)) {
                                Ok(s) => s,
                                Err(e) => return (false, e),
                            };
                            let mut hello = Frame::new("hello");
                            hello.device_id = self.device_id.clone();
                            hello.signature = sig;
                            if out_tx.send(Message::text(serde_json::to_string(&hello).unwrap_or_default())).await.is_err() {
                                return (false, "connection closed".into());
                            }
                        }
                        "ready" => {
                            ready = true;
                            logf!("relay tunnel ready: https://{}/mcp", f.hostname);
                            (self.on_hostname)(&f.hostname);
                        }
                        "error" => return (ready, format!("relay: {}: {}", f.code, f.message)),
                        _ => {}
                    }
                    continue;
                }
                Some(Ok(Message::Binary(b))) => b,
                Some(Ok(Message::Close(c))) => {
                    return (ready, c.map(|c| format!("closed: {} {}", u16::from(c.code), c.reason)).unwrap_or_else(|| "closed".into()))
                }
                Some(Ok(_)) => continue,
                Some(Err(e)) => return (ready, e.to_string()),
                None => return (ready, "connection closed".into()),
            };
            if data.len() < 5 || !ready {
                continue;
            }
            let id = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
            let payload = data.slice(5..);
            match data[0] {
                OPEN => {
                    let remote = serde_json::from_slice::<serde_json::Value>(&payload)
                        .ok()
                        .and_then(|v| v.get("remote").and_then(|r| r.as_str()).map(str::to_string))
                        .unwrap_or_default();
                    self.open(id, remote, &out_tx, accept, &sess).await;
                }
                DATA => {
                    let mut g = self.streams.lock().unwrap();
                    if let Some(s) = g.get(&id) {
                        let n = s.buffered.fetch_add(payload.len(), Ordering::Relaxed) + payload.len();
                        // The reader is not keeping up; give up on this connection.
                        if n > MAX_BUFFERED || s.tx.send(payload).is_err() {
                            g.remove(&id);
                        }
                    }
                }
                CLOSE => {
                    self.streams.lock().unwrap().remove(&id);
                }
                _ => {}
            }
        }
    }

    async fn open(self: &Arc<Self>, id: u32, remote: String, out: &mpsc::Sender<Message>, accept: &mpsc::Sender<Conn>, sess: &CancellationToken) {
        if self.streams.lock().unwrap().len() >= MAX_STREAMS {
            let _ = out.send(Message::binary(header(CLOSE, id))).await;
            return;
        }
        let (ours, theirs) = tokio::io::duplex(64 * 1024);
        let (mut rd, mut wr) = tokio::io::split(ours);
        let (tx, mut rx) = mpsc::unbounded_channel::<Bytes>();
        let buffered = Arc::new(AtomicUsize::new(0));
        self.streams.lock().unwrap().insert(id, Inbound { tx, buffered: buffered.clone() });
        // Relay → TLS side.
        tokio::spawn(async move {
            while let Some(b) = rx.recv().await {
                let n = b.len();
                if wr.write_all(&b).await.is_err() {
                    break;
                }
                buffered.fetch_sub(n, Ordering::Relaxed);
            }
            let _ = wr.shutdown().await;
        });
        // TLS side → relay.
        let out = out.clone();
        let me = self.clone();
        let s = sess.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_CHUNK];
            loop {
                let n = tokio::select! {
                    r = rd.read(&mut buf) => match r { Ok(0) | Err(_) => break, Ok(n) => n },
                    _ = s.cancelled() => return,
                };
                let mut f = header(DATA, id);
                f.extend_from_slice(&buf[..n]);
                if out.send(Message::binary(f)).await.is_err() {
                    return;
                }
            }
            me.streams.lock().unwrap().remove(&id);
            let _ = out.send(Message::binary(header(CLOSE, id))).await;
        });
        tokio::select! {
            _ = accept.send(Conn { io: theirs, remote }) => {}
            _ = sess.cancelled() => {}
        }
    }
}
