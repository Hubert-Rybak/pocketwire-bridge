//! The private MCP endpoint for AI apps in the cloud, over TLS that ends on this computer. AI
//! apps sign in with Pocketwire's OAuth server as usual; the Bridge checks each token by sending
//! only its SHA-256 to the server.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::json;

use crate::driver::BoxFuture;
use crate::local::approvals::Phones;
use crate::local::engine::Engine;
use crate::local::localweb::Hostname;
use crate::local::mcp::{Mcp, TokenInfo};
use crate::protocol::Frame;
use crate::util;
use crate::web::{Req, Resp};

/// The cloud's OAuth scopes.
pub const SCOPES: [&str; 3] = ["devices:read", "sms:send", "messages:read"];

pub type Introspect = Arc<dyn Fn(String) -> BoxFuture<Result<Frame, String>> + Send + Sync>;

pub struct RelayWeb {
    pub mcp: Arc<Mcp>,
    /// The OAuth authorization server, e.g. https://pocketwire.app.
    pub auth_server: String,
    pub hostname: Hostname,
    pub introspect: Introspect,
    /// With these, paired phones can open /approvals.
    pub engine: Option<Arc<Engine>>,
    pub phones: Option<Arc<Phones>>,
    cache: Mutex<HashMap<String, (Option<TokenInfo>, i64)>>,
}

enum Verify {
    Ok(TokenInfo),
    Invalid(&'static str),
    Failed(String),
}

impl RelayWeb {
    pub fn new(
        mcp: Arc<Mcp>,
        auth_server: &str,
        hostname: Hostname,
        introspect: Introspect,
        engine: Option<Arc<Engine>>,
        phones: Option<Arc<Phones>>,
    ) -> Arc<RelayWeb> {
        Arc::new(RelayWeb { mcp, auth_server: auth_server.to_string(), hostname, introspect, engine, phones, cache: Mutex::new(HashMap::new()) })
    }

    fn host(&self) -> String {
        self.hostname.lock().unwrap().clone()
    }

    async fn verify(&self, token: &str) -> Verify {
        let h = util::sha256_hex(token.as_bytes());
        let now = util::now_ms();
        if let Some((info, until)) = self.cache.lock().unwrap().get(&h).cloned() {
            if now < until {
                return match info {
                    Some(i) => Verify::Ok(i),
                    None => Verify::Invalid("invalid token"),
                };
            }
        }
        let f = match (self.introspect)(h.clone()).await {
            Ok(f) => f,
            Err(e) => return Verify::Failed(e),
        };
        let mut until = now + 10_000;
        let mut info = None;
        if f.active == Some(true) {
            let exp = f.expires_at * 1000;
            if exp <= now {
                return Verify::Invalid("token expired");
            }
            info = Some(TokenInfo { scopes: f.scopes.clone(), client_name: f.client_name.clone() });
            until = (now + 60_000).min(exp);
        }
        {
            let mut c = self.cache.lock().unwrap();
            if c.len() > 1000 {
                c.clear();
            }
            c.insert(h, (info.clone(), until));
        }
        match info {
            Some(i) => Verify::Ok(i),
            None => Verify::Invalid("invalid token"),
        }
    }

    pub async fn handle(self: Arc<Self>, r: Req) -> Resp {
        self.route(&r)
            .await
            .with("access-control-allow-origin", "*")
            .with("access-control-allow-methods", "GET, POST, DELETE, OPTIONS")
            .with("access-control-allow-headers", "Authorization, Content-Type, Mcp-Session-Id, Mcp-Protocol-Version, Last-Event-ID")
            .with("access-control-expose-headers", "WWW-Authenticate, Mcp-Session-Id")
    }

    async fn route(&self, r: &Req) -> Resp {
        let host = self.host();
        match (r.method.as_str(), r.path.as_str()) {
            ("GET", "/.well-known/oauth-protected-resource" | "/.well-known/oauth-protected-resource/mcp") => Resp::json(
                200,
                &json!({
                    "resource": format!("https://{host}/mcp"),
                    "authorization_servers": [self.auth_server],
                    "scopes_supported": SCOPES,
                    "bearer_methods_supported": ["header"],
                    "resource_name": "Pocketwire (private, through your Bridge)",
                }),
            ),
            ("GET", "/healthz") => Resp::new(200).body(r#"{"ok":true}"#),
            ("OPTIONS", "/mcp") => Resp::new(204),
            (_, "/mcp") => {
                let challenge = format!(r#"Bearer error="invalid_token", resource_metadata="https://{host}/.well-known/oauth-protected-resource/mcp""#);
                let token = r.header("authorization");
                let token = token.strip_prefix("Bearer ").or_else(|| token.strip_prefix("bearer ")).unwrap_or("");
                if token.is_empty() {
                    return Resp::error(401, "no bearer token").with("www-authenticate", challenge);
                }
                match self.verify(token).await {
                    Verify::Ok(info) => self.mcp.http(r, Some(info)).await,
                    Verify::Invalid(why) => Resp::error(401, why).with("www-authenticate", challenge),
                    Verify::Failed(e) => Resp::error(500, &e),
                }
            }
            _ => {
                if let (Some(p), Some(e)) = (&self.phones, &self.engine) {
                    if let Some(resp) = p.handle(r, e) {
                        return resp;
                    }
                }
                Resp::not_found()
            }
        }
    }
}
