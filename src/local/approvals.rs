//! The approval page, on this computer and (for paired phones) at the Bridge's private address.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use base64::Engine as _;

use crate::local::engine::Engine;
use crate::util::{self, esc};
use crate::web::{Req, Resp};

const STYLE: &str = r#":root{color-scheme:light dark;--bg:#f7f7f5;--card:#fff;--text:#1b1b1b;--muted:#6b6b6b;--line:#e2e2de;--accent:#2d6a4f}
@media (prefers-color-scheme:dark){:root{--bg:#141414;--card:#1e1e1e;--text:#ededed;--muted:#a0a0a0;--line:#333;--accent:#74c69d}}
body{margin:0;font:16px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--text)}
main{max-width:640px;margin:0 auto;padding:24px 16px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:0 0 8px}.muted{color:var(--muted);font-size:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;margin:16px 0}
blockquote{white-space:pre-wrap;margin:12px 0;padding:12px;border-left:3px solid var(--accent);background:var(--bg);border-radius:6px}
.row{display:flex;gap:8px;flex-wrap:wrap}button{font:inherit;padding:10px 18px;border-radius:8px;border:1px solid var(--line);background:var(--card);color:var(--text);cursor:pointer}
button.send{background:var(--accent);border-color:var(--accent);color:#fff}
.qr{display:flex;gap:16px;align-items:center;flex-wrap:wrap}.qr img{width:168px;height:168px;image-rendering:pixelated;background:#fff;padding:8px;border-radius:8px}
code{word-break:break-all}"#;

/// Shows times in the viewer's own time zone (the page renders them in UTC).
const LOCAL_TIME: &str = r#"<script>for(const t of document.querySelectorAll("time[data-ms]"))t.textContent=new Date(+t.dataset.ms).toLocaleTimeString([], {hour:"2-digit",minute:"2-digit",second:"2-digit",hour12:false})</script>"#;

/// The approval page (HTML) for the messages that wait on this computer.
pub fn render(e: &Engine, csrf: &str, flash: &str, extra: &str, note: &str) -> Resp {
    let pending = e.store.pending(util::now_ms());
    let mut h = String::with_capacity(4096);
    h.push_str(r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">"#);
    h.push_str("\n<title>Pocketwire approvals</title>");
    h.push_str(if pending.is_empty() { r#"<meta http-equiv="refresh" content="5">"# } else { r#"<meta http-equiv="refresh" content="20">"# });
    h.push_str("\n<style>\n");
    h.push_str(STYLE);
    h.push_str("\n</style></head><body><main>\n<h1>Messages waiting for you</h1>\n");
    h.push_str(&format!(r#"<p class="muted">{} The number and the text never went to the Pocketwire server.</p>"#, esc(note)));
    h.push('\n');
    for m in &pending {
        let by = if m.client_name.is_empty() { String::new() } else { format!("requested by {} · ", esc(&m.client_name)) };
        h.push_str(&format!(
            r#"<section class="card">
<div><strong>To {to}</strong> <span class="muted">{by}<time data-ms="{ms}">{clock}</time></span></div>
<blockquote>{body}</blockquote>
<div class="row">
<form method="post" action="/approvals/{id}/approve"><input type="hidden" name="csrf" value="{csrf}"><button class="send" type="submit">Send</button></form>
<form method="post" action="/approvals/{id}/reject"><input type="hidden" name="csrf" value="{csrf}"><button type="submit">Reject</button></form>
</div></section>"#,
            to = esc(&m.to),
            ms = m.created_at,
            clock = util::clock(m.created_at),
            body = esc(&m.body),
            id = esc(&util::query_escape(&m.id)),
            csrf = esc(csrf),
        ));
    }
    if pending.is_empty() {
        h.push_str(r#"<section class="card"><p>Nothing is waiting for approval.</p></section>"#);
    }
    h.push('\n');
    if !flash.is_empty() {
        h.push_str(&format!(r#"<p class="muted">{}</p>"#, esc(flash)));
    }
    h.push('\n');
    h.push_str(extra);
    h.push('\n');
    h.push_str(LOCAL_TIME);
    h.push_str("\n</main></body></html>");
    Resp::html(h)
}

/// Handles POST /approvals/{id}/{decision} once the caller is authorized.
pub fn apply_decision(e: &Arc<Engine>, id: &str, decision: &str) -> Resp {
    let (ok, done) = match decision {
        "approve" => (e.approve(id), "Sending."),
        "reject" => (e.reject(id), "Rejected. Nothing was sent."),
        _ => return Resp::not_found(),
    };
    let done = if ok { done } else { "That message no longer waits for approval." };
    Resp::redirect(&format!("/approvals?done={}", util::query_escape(done)))
}

/// Splits "/approvals/{id}/{decision}".
pub fn decision_path(path: &str) -> Option<(String, String)> {
    let rest = path.strip_prefix("/approvals/")?;
    let (id, d) = rest.split_once('/')?;
    if id.is_empty() || d.is_empty() || d.contains('/') {
        return None;
    }
    Some((util::query_unescape(&id.replace('+', "%2B")), d.to_string()))
}

/// Lets the user approve from a phone: the approval page at the Bridge's private address (TLS
/// ends on this computer) accepts a phone once it was paired by scanning a code shown here. The
/// pairing never involves the Pocketwire server, so it can't approve or read messages.
pub struct Phones {
    /// SHA-256 hashes of the phones' tokens (0600); None keeps them in memory.
    path: Option<PathBuf>,
    st: Mutex<PhoneState>,
}

struct PhoneState {
    codes: HashMap<String, i64>,
    hashes: HashSet<String>,
}

pub const PHONE_COOKIE: &str = "pw_phone";
const CODE_TTL_MS: i64 = 10 * 60 * 1000;

fn random_token(n: usize) -> String {
    B64URL.encode(util::random_bytes(n))
}

impl Phones {
    pub fn new(path: Option<PathBuf>) -> Phones {
        let mut hashes = HashSet::new();
        if let Some(p) = &path {
            if let Ok(b) = std::fs::read(p) {
                if let Ok(list) = serde_json::from_slice::<Vec<String>>(&b) {
                    hashes.extend(list);
                }
            }
        }
        Phones { path, st: Mutex::new(PhoneState { codes: HashMap::new(), hashes }) }
    }

    fn save(&self, st: &PhoneState) {
        let Some(p) = &self.path else { return };
        let list: Vec<&String> = st.hashes.iter().collect();
        if let Some(dir) = p.parent() {
            let _ = crate::config::create_private_dir(dir);
        }
        let _ = crate::config::write_private(p, serde_json::to_string(&list).unwrap_or_default().as_bytes());
    }

    /// A single-use pairing code, valid for ten minutes.
    pub fn new_code(&self) -> String {
        let mut st = self.st.lock().unwrap();
        let now = util::now_ms();
        st.codes.retain(|_, exp| *exp > now);
        let c = random_token(18);
        st.codes.insert(c.clone(), now + CODE_TTL_MS);
        c
    }

    /// Turns a pairing code into a phone token (the cookie value), or None if the code is no good.
    pub fn redeem(&self, code: &str) -> Option<String> {
        let mut st = self.st.lock().unwrap();
        let exp = st.codes.remove(code)?;
        if util::now_ms() > exp {
            return None;
        }
        let t = random_token(32);
        st.hashes.insert(util::sha256_hex(t.as_bytes()));
        self.save(&st);
        Some(t)
    }

    /// Whether a phone token was issued here.
    pub fn valid(&self, token: &str) -> bool {
        !token.is_empty() && self.st.lock().unwrap().hashes.contains(&util::sha256_hex(token.as_bytes()))
    }

    /// The "approve from your phone" box for the local approval page.
    pub fn pairing_html(&self, hostname: &str) -> String {
        let link = format!("https://{hostname}/approvals/pair?code={}", self.new_code());
        let img = qr_svg(&link)
            .map(|svg| format!(r#"<img src="data:image/svg+xml;base64,{}" alt="QR code to pair your phone">"#, B64.encode(svg)))
            .unwrap_or_default();
        format!(
            r#"<section class="card"><h2>Approve from your phone</h2>
<div class="qr">{img}
<p class="muted">Scan this with your phone's camera once. Your phone can then open approvals at this computer's private address, also when you're away. The code works once, for ten minutes.<br><code>{}</code></p></div></section>"#,
            esc(&link)
        )
    }

    /// Serves /approvals on the relay address to paired phones; None if the path isn't theirs.
    pub fn handle(&self, r: &Req, e: &Arc<Engine>) -> Option<Resp> {
        let token = r.cookie(PHONE_COOKIE).unwrap_or_default();
        match (r.method.as_str(), r.path.as_str()) {
            ("GET", "/approvals/pair") => Some(match self.redeem(r.query("code")) {
                None => Resp::error(403, "This pairing code is wrong, used or expired. Open the approval page on your computer for a new one."),
                Some(t) => Resp::redirect("/approvals?done=This+phone+can+now+approve+messages.")
                    .with("set-cookie", format!("{PHONE_COOKIE}={t}; Path=/approvals; Max-Age={}; HttpOnly; Secure; SameSite=Lax", 400 * 24 * 3600)),
            }),
            ("GET", "/approvals") => {
                if !self.valid(&token) {
                    return Some(
                        Resp::error(
                            403,
                            "This phone isn't paired yet. On your computer, open the approval page (pocketwire approvals) and scan the code there.",
                        )
                        .with("cache-control", "no-store")
                        .with("x-frame-options", "DENY"),
                    );
                }
                Some(
                    render(
                        e,
                        &phone_csrf(&token),
                        r.query("done"),
                        "",
                        "This page comes straight from the Pocketwire Bridge on your computer, over an encrypted connection that ends there.",
                    )
                    .with("cache-control", "no-store")
                    .with("x-frame-options", "DENY"),
                )
            }
            ("POST", p) => {
                let (id, d) = decision_path(p)?;
                if !self.valid(&token) || !util::eq(&r.form("csrf"), &phone_csrf(&token)) {
                    return Some(Resp::error(403, "forbidden"));
                }
                Some(apply_decision(e, &id, &d))
            }
            _ => None,
        }
    }
}

/// Binds approval forms to the phone's own token.
pub fn phone_csrf(token: &str) -> String {
    util::hmac_hex(token.as_bytes(), b"csrf")[..32].to_string()
}

/// A QR code as a small SVG.
pub fn qr_svg(text: &str) -> Option<String> {
    let q = qrcodegen::QrCode::encode_text(text, qrcodegen::QrCodeEcc::Medium).ok()?;
    let n = q.size();
    let border = 2;
    let mut path = String::new();
    for y in 0..n {
        for x in 0..n {
            if q.get_module(x, y) {
                path.push_str(&format!("M{},{}h1v1h-1z", x + border, y + border));
            }
        }
    }
    let s = n + border * 2;
    Some(format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {s} {s}" shape-rendering="crispEdges"><rect width="{s}" height="{s}" fill="#fff"/><path d="{path}" fill="#000"/></svg>"##
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phone_codes_work_once() {
        let p = Phones::new(None);
        let c = p.new_code();
        let t = p.redeem(&c).unwrap();
        assert!(p.valid(&t));
        assert!(p.redeem(&c).is_none());
        assert!(!p.valid("nope") && !p.valid(""));
        assert!(p.pairing_html("abc.b.example").contains("https://abc.b.example/approvals/pair?code="));
    }

    #[test]
    fn paths() {
        assert_eq!(decision_path("/approvals/msg_1/approve"), Some(("msg_1".into(), "approve".into())));
        assert_eq!(decision_path("/approvals/x"), None);
        assert_eq!(decision_path("/approvals//approve"), None);
        assert!(qr_svg("https://x").unwrap().starts_with("<svg"));
    }
}
