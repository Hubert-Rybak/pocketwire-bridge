//! The control page on 127.0.0.1:47301.

use std::sync::Arc;

use serde_json::json;

use super::{hostname, App, State, PANEL_PORT};
use crate::util::{self, esc};
use crate::web::{Req, Resp};

const COOKIE: &str = "pw_panel";
const CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

/// Accepts only loopback host names (DNS rebinding), same-origin posts and requests that carry
/// the page's key (in the address once, then in a cookie).
pub async fn handle(a: &Arc<App>, r: Req) -> Resp {
    let resp = route(a, &r).await;
    resp.with("x-frame-options", "DENY").with("cache-control", "no-store").with("referrer-policy", "no-referrer").with("content-security-policy", CSP)
}

async fn route(a: &Arc<App>, r: &Req) -> Resp {
    let host = r.header("host");
    let name = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
    if name != "127.0.0.1" && name != "localhost" {
        return Resp::error(403, "forbidden host");
    }
    let o = r.header("origin");
    if !o.is_empty() && o != format!("http://127.0.0.1:{PANEL_PORT}") && o != format!("http://localhost:{PANEL_PORT}") {
        return Resp::error(403, "forbidden origin");
    }
    let k = r.query("k");
    let mut cookie = None;
    if !k.is_empty() && util::eq(k, a.key()) {
        cookie = Some(format!("{COOKIE}={k}; Path=/; HttpOnly; SameSite=Strict"));
        if r.method == "GET" && r.path == "/" {
            // Drop the key from the address bar and history.
            return Resp::redirect("/").with("set-cookie", cookie.unwrap());
        }
    } else if !r.cookie(COOKIE).map(|c| util::eq(&c, a.key())).unwrap_or(false) {
        return Resp::error(403, "Open this page from the Pocketwire Bridge icon (or run `pocketwire app`).");
    }
    let resp = match (r.method.as_str(), r.path.as_str()) {
        ("GET", "/") => page(a, r.query("error")),
        ("GET", "/status.json") => {
            let s = a.snapshot();
            let mut v = json!({"state": s.state.label(), "code": s.state as u8});
            if !s.detail.is_empty() {
                v["detail"] = json!(s.detail);
            }
            let p = private_mcp(&s.private_url);
            if !p.is_empty() {
                v["private_url"] = json!(p);
            }
            Resp::json(200, &v)
        }
        ("POST", p @ ("/pair" | "/unpair" | "/autostart" | "/retry")) => {
            if !util::eq(&r.form("csrf"), &a.csrf()) {
                return Resp::error(403, "forbidden");
            }
            let res = match p {
                "/pair" => a.pair(&r.form("code"), r.form("name").trim(), &r.form("driver"), r.form("kdeconnect_device").trim()).await,
                "/unpair" => a.unpair(),
                "/autostart" => a.set_autostart(r.form("on") == "1"),
                _ => {
                    a.retry().await;
                    Ok(())
                }
            };
            Resp::redirect(&match res {
                Ok(()) => "/?".to_string(),
                Err(e) => format!("/?error={}", util::query_escape(&e)),
            })
        }
        _ => Resp::not_found(),
    };
    match cookie {
        Some(c) => resp.with("set-cookie", c),
        None => resp,
    }
}

fn private_mcp(u: &str) -> String {
    if u.is_empty() {
        String::new()
    } else {
        format!("{}/mcp", u.trim_end_matches('/'))
    }
}

const STYLE: &str = r#":root{--bg:#f6f7f8;--card:#fff;--text:#14191d;--muted:#5d6872;--line:#e2e6ea;--accent:#16a34a;--warn:#b45309;--bad:#b91c1c}
@media (prefers-color-scheme:dark){:root{--bg:#0f1418;--card:#171f25;--text:#e8edf1;--muted:#97a3ad;--line:#26313a;--accent:#22c55e;--warn:#f59e0b;--bad:#f87171}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:620px;margin:0 auto;padding:32px 16px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:0 0 8px}
.muted{color:var(--muted)}.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px;margin:16px 0}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;background:var(--muted);margin-right:8px;vertical-align:middle}
.s3 .dot{background:var(--accent)}.s4 .dot,.s2 .dot,.s1 .dot{background:var(--warn)}.s5 .dot{background:var(--bad)}
label{display:block;margin:12px 0 4px;font-weight:600}input,select{width:100%;padding:10px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--text);font:inherit}
button,.btn{display:inline-block;padding:9px 16px;border-radius:8px;border:1px solid var(--line);background:var(--card);color:var(--text);font:inherit;cursor:pointer;text-decoration:none;margin:4px 8px 4px 0}
.primary{background:var(--accent);border-color:var(--accent);color:#fff;font-weight:600}
code{background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:2px 6px;word-break:break-all}
.err{border-color:var(--bad);color:var(--bad)}details summary{cursor:pointer;color:var(--muted);margin-top:12px}
.row{display:flex;align-items:center;justify-content:space-between;gap:12px}"#;

fn page(a: &App, error: &str) -> Resp {
    let s = a.snapshot();
    let csrf = esc(&a.csrf());
    let code = s.state as u8;
    let paired = s.state != State::NotPaired;
    let pmcp = private_mcp(&s.private_url);
    let dashboard = format!("{}/app", a.server.trim_end_matches('/'));
    let hidden = format!(r#"<input type="hidden" name="csrf" value="{csrf}">"#);
    let mut h = String::with_capacity(8192);
    h.push_str("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n<title>Pocketwire Bridge</title>\n<style>\n");
    h.push_str(STYLE);
    h.push_str("\n</style></head><body><main>\n<h1>Pocketwire Bridge</h1>\n");
    h.push_str(&format!("<p class=\"muted\">Version {}. This page is served by the Bridge on this computer.</p>\n", esc(&s.version)));
    if !error.is_empty() {
        h.push_str(&format!("<div class=\"card err\">{}</div>", esc(error)));
    }
    h.push_str(&format!(
        "\n<div class=\"card s{code}\" id=\"status\"><strong><span class=\"dot\"></span><span id=\"state\">{}</span></strong>\n<p class=\"muted\" id=\"detail\">{}</p>\n",
        esc(s.state.label()),
        esc(&s.detail)
    ));
    if matches!(s.state, State::Elsewhere | State::Failed) {
        h.push_str(&format!("<form method=\"post\" action=\"/retry\">{hidden}<button>Try again</button></form>"));
    }
    h.push_str("\n</div>\n");
    if !paired {
        let drivers: String = crate::driver::NAMES
            .iter()
            .map(|d| format!("<option value=\"{d}\"{}>{d}</option>", if *d == crate::driver::default_name() { " selected" } else { "" }))
            .collect();
        h.push_str(&format!(
            r#"<div class="card">
<h2>Pair this computer</h2>
<p>Get a code in the dashboard: <a href="{dash}/devices" target="_blank" rel="noopener">Devices</a>, then <em>Add a device</em>. Keep this computer on and connected to your phone: an Android phone through KDE Connect, or an iPhone through Messages on a Mac.</p>
<form method="post" action="/pair">
{hidden}
<label for="code">Pairing code</label><input id="code" name="code" placeholder="K7Q2-M9XD" autocomplete="off" required autofocus>
<label for="name">Name of this computer</label><input id="name" name="name" value="{host}">
<label for="driver">Send texts through</label>
<select id="driver" name="driver">{drivers}</select>
<details><summary>More options</summary>
<label for="kde">KDE Connect device id (optional)</label><input id="kde" name="kdeconnect_device" placeholder="first phone KDE Connect can reach">
</details>
<p><button class="primary">Pair</button></p>
</form>
</div>
"#,
            dash = esc(&dashboard),
            host = esc(&hostname()),
        ));
    } else {
        let open = if s.approval_url.is_empty() {
            String::new()
        } else {
            format!(r#"<a class="btn primary" href="{}" target="_blank" rel="noopener">Open approvals</a>"#, esc(&s.approval_url))
        };
        let private = if pmcp.is_empty() {
            r#"<span class="muted">Appears here once the Bridge is connected.</span>"#.to_string()
        } else {
            format!("Add <code>{}</code> as the connector URL in Claude or another AI app.", esc(&pmcp))
        };
        let drv = match &s.driver_err {
            Some(e) => format!(r#" <span style="color:var(--warn)">({})</span>"#, esc(e)),
            None => " (ready)".into(),
        };
        h.push_str(&format!(
            r#"<div class="card">
<h2>Approvals</h2>
<p>Texts from AI apps wait for your OK here. The Bridge opens this page when one arrives.</p>
{open}
<a class="btn" href="{dash}" target="_blank" rel="noopener">Open the dashboard</a>
</div>
<div class="card">
<h2>Private address for AI apps</h2>
<p id="private">{private}</p>
<p class="muted">Sending through: {name}{drv}</p>
</div>
"#,
            dash = esc(&dashboard),
            name = esc(&s.driver_name),
        ));
    }
    h.push_str(&format!(
        r#"<div class="card">
<div class="row"><div><h2>Start when I sign in</h2><p class="muted">Keeps the Bridge running in the background, with an icon in the tray.</p></div>
<form method="post" action="/autostart">{hidden}<input type="hidden" name="on" value="{on}">
<button>{label}</button></form></div>
"#,
        on = if s.autostart { "0" } else { "1" },
        label = if s.autostart { "Turn off" } else { "Turn on" },
    ));
    if !s.log_path.is_empty() {
        h.push_str(&format!("<p class=\"muted\">Log: <code>{}</code></p>", esc(&s.log_path)));
    }
    if paired {
        h.push_str(&format!(r#"<form method="post" action="/unpair" onsubmit="return confirm('Unpair this computer? You can pair it again with a new code.')">{hidden}<button>Unpair this computer</button></form>"#));
    }
    h.push_str(&format!(
        r#"
</div>
</main>
<script>
var last={code};
setInterval(function(){{fetch('/status.json').then(function(r){{return r.json()}}).then(function(s){{
 if((s.code===0)!==(last===0)||(!!s.private_url)!=={has_private}){{location.replace('/');return}}
 document.getElementById('state').textContent=s.state;document.getElementById('detail').textContent=s.detail||'';
 document.getElementById('status').className='card s'+s.code;last=s.code;
}}).catch(function(){{}})}},2000);
</script>
</body></html>"#,
        has_private = !pmcp.is_empty(),
    ));
    Resp::html(h)
}
