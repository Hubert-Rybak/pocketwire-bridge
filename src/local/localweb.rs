//! The private MCP endpoint and the approval page on 127.0.0.1 only.

use std::sync::{Arc, Mutex};

use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use crate::local::approvals::{self, Phones};
use crate::local::engine::Engine;
use crate::local::mcp::Mcp;
use crate::util;
use crate::web::{self, Req, Resp};

/// The Bridge's relay host name once the tunnel is up ("" before).
pub type Hostname = Arc<Mutex<String>>;

pub struct LocalWeb {
    pub mcp: Arc<Mcp>,
    pub engine: Arc<Engine>,
    pub port: u16,
    /// The bearer token for /mcp (kept in the Bridge config, never sent to the server).
    pub token: String,
    /// With these, the page offers approving from a phone through the relay.
    pub phones: Option<Arc<Phones>>,
    pub hostname: Option<Hostname>,
}

const COOKIE: &str = "pw_approvals";

impl LocalWeb {
    /// The secret in the approval page's address.
    pub fn approval_key(&self) -> String {
        approval_key(&self.token)
    }

    fn csrf(&self) -> String {
        util::hmac_hex(self.token.as_bytes(), b"csrf")[..32].to_string()
    }

    pub fn base(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    pub fn approval_url(&self) -> String {
        approval_url(self.port, &self.token)
    }

    fn authorized(&self, r: &Req) -> (bool, bool) {
        let k = r.query("k");
        if !k.is_empty() && util::eq(k, &self.approval_key()) {
            return (true, true);
        }
        (r.cookie(COOKIE).map(|c| util::eq(&c, &self.approval_key())).unwrap_or(false), false)
    }

    /// Rejects requests that didn't come to a loopback host name (DNS rebinding) and
    /// cross-site form posts.
    fn guard(&self, r: &Req) -> Option<Resp> {
        let host = r.header("host");
        let name = match host.rsplit_once(':') {
            Some((h, p)) if !p.contains(']') => h,
            _ => host,
        };
        if !matches!(name, "127.0.0.1" | "localhost" | "[::1]" | "::1") {
            return Some(Resp::error(403, "forbidden host"));
        }
        let o = r.header("origin");
        if !o.is_empty() && o != "null" && o != self.base() && o != format!("http://localhost:{}", self.port) {
            return Some(Resp::error(403, "forbidden origin"));
        }
        None
    }

    pub async fn handle(self: Arc<Self>, r: Req) -> Resp {
        let resp = match self.guard(&r) {
            Some(e) => e,
            None => self.route(&r).await,
        };
        resp.with("x-frame-options", "DENY").with("cache-control", "no-store").with("referrer-policy", "no-referrer")
    }

    async fn route(&self, r: &Req) -> Resp {
        match (r.method.as_str(), r.path.as_str()) {
            (_, "/mcp") => match r.bearer() {
                Some(t) if util::eq(t, &self.token) => self.mcp.http(r, None).await,
                _ => Resp::error(401, "missing or wrong bearer token (see `pocketwire connect`)"),
            },
            ("GET", "/healthz") => Resp::new(200).body(r#"{"ok":true}"#),
            ("GET", "/approvals") => {
                let (ok, set_cookie) = self.authorized(r);
                if !ok {
                    return Resp::error(403, "Open this page from the link the Bridge opened, or run `pocketwire approvals`.");
                }
                let host = self.hostname.as_ref().map(|h| h.lock().unwrap().clone()).unwrap_or_default();
                let phone = match &self.phones {
                    Some(p) if !host.is_empty() => p.pairing_html(&host),
                    _ => String::new(),
                };
                let resp =
                    approvals::render(&self.engine, &self.csrf(), r.query("done"), &phone, "This page is served by the Pocketwire Bridge on this computer.");
                if set_cookie {
                    resp.with("set-cookie", format!("{COOKIE}={}; Path=/approvals; HttpOnly; SameSite=Strict", self.approval_key()))
                } else {
                    resp
                }
            }
            ("POST", p) if p.starts_with("/approvals/") => {
                let Some((id, d)) = approvals::decision_path(p) else { return Resp::not_found() };
                let (ok, _) = self.authorized(r);
                if !ok || !util::eq(&r.form("csrf"), &self.csrf()) {
                    return Resp::error(403, "forbidden");
                }
                approvals::apply_decision(&self.engine, &id, &d)
            }
            _ => Resp::not_found(),
        }
    }

    /// Listens on 127.0.0.1:port until `stop` fires.
    pub async fn bind(&self) -> Result<TcpListener, String> {
        TcpListener::bind(("127.0.0.1", self.port)).await.map_err(|e| {
            format!(
                "local endpoint on port {}: listen tcp 127.0.0.1:{}: {e} (another Bridge running? set a different port with --local-port)",
                self.port, self.port
            )
        })
    }

    pub async fn serve(self: Arc<Self>, ln: TcpListener, stop: CancellationToken) {
        let h = crate::handler!(self, |s, r| s.handle(r).await);
        web::serve(ln, h, stop).await
    }
}

pub fn approval_key(token: &str) -> String {
    util::hmac_hex(token.as_bytes(), b"approvals")[..32].to_string()
}

pub fn approval_url(port: u16, token: &str) -> String {
    format!("http://127.0.0.1:{port}/approvals?k={}", approval_key(token))
}

/// Opens a URL with the desktop's default browser.
pub fn open_browser(url: &str) -> Result<(), String> {
    let mut cmd = if cfg!(target_os = "macos") {
        let mut c = std::process::Command::new("open");
        c.arg(url);
        c
    } else if cfg!(windows) {
        let mut c = std::process::Command::new("rundll32");
        c.arg("url.dll,FileProtocolHandler").arg(url);
        c
    } else {
        let mut c = std::process::Command::new("xdg-open");
        c.arg(url);
        c
    };
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000);
    }
    cmd.stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
    cmd.spawn().map(|_| ()).map_err(|e| e.to_string())
}
