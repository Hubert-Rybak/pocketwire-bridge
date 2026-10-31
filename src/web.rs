//! A minimal HTTP/1.1 server layer over hyper: requests are read whole (they are small), and
//! handlers return complete responses.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use crate::driver::BoxFuture;
use crate::util;

/// Largest request body accepted.
const MAX_BODY: usize = 1 << 20;

pub struct Req {
    pub method: String,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub headers: HeaderMap,
    pub body: Bytes,
}

impl Req {
    pub fn header(&self, name: &str) -> &str {
        self.headers.get(name).and_then(|v| v.to_str().ok()).unwrap_or("")
    }

    pub fn query(&self, key: &str) -> &str {
        util::get(&self.query, key)
    }

    /// The value of a cookie, if sent.
    pub fn cookie(&self, name: &str) -> Option<String> {
        for v in self.headers.get_all("cookie") {
            let Ok(v) = v.to_str() else { continue };
            for part in v.split(';') {
                if let Some((k, val)) = part.trim().split_once('=') {
                    if k == name {
                        return Some(val.trim_matches('"').to_string());
                    }
                }
            }
        }
        None
    }

    /// A field of an urlencoded form body (or of the query, like Go's FormValue).
    pub fn form(&self, key: &str) -> String {
        if self.header("content-type").starts_with("application/x-www-form-urlencoded") {
            let pairs = util::parse_query(&String::from_utf8_lossy(&self.body));
            if let Some((_, v)) = pairs.iter().find(|(k, _)| k == key) {
                return v.clone();
            }
        }
        self.query(key).to_string()
    }

    /// The bearer token from the Authorization header.
    pub fn bearer(&self) -> Option<&str> {
        self.header("authorization").strip_prefix("Bearer ")
    }
}

pub struct Resp {
    pub status: u16,
    pub headers: Vec<(&'static str, String)>,
    pub body: Bytes,
}

impl Resp {
    pub fn new(status: u16) -> Resp {
        Resp { status, headers: Vec::new(), body: Bytes::new() }
    }

    pub fn with(mut self, name: &'static str, value: impl Into<String>) -> Resp {
        self.headers.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
        self.headers.push((name, value.into()));
        self
    }

    pub fn body(mut self, b: impl Into<Bytes>) -> Resp {
        self.body = b.into();
        self
    }

    /// A plain-text error, like Go's http.Error.
    pub fn error(status: u16, msg: &str) -> Resp {
        Resp::new(status).with("content-type", "text/plain; charset=utf-8").with("x-content-type-options", "nosniff").body(format!("{msg}\n"))
    }

    pub fn json(status: u16, v: &serde_json::Value) -> Resp {
        Resp::new(status).with("content-type", "application/json").body(format!("{v}\n"))
    }

    pub fn html(body: String) -> Resp {
        Resp::new(200).with("content-type", "text/html; charset=utf-8").body(body)
    }

    pub fn redirect(location: &str) -> Resp {
        Resp::new(303).with("location", location)
    }

    pub fn not_found() -> Resp {
        Resp::error(404, "404 page not found")
    }
}

pub type Handler = Arc<dyn Fn(Req) -> BoxFuture<Resp> + Send + Sync>;

async fn read(req: hyper::Request<Incoming>) -> Result<Req, Resp> {
    let (parts, body) = req.into_parts();
    let body = match Limited::new(body, MAX_BODY).collect().await {
        Ok(b) => b.to_bytes(),
        Err(_) => return Err(Resp::error(413, "request body too large")),
    };
    Ok(Req {
        method: parts.method.as_str().to_string(),
        path: parts.uri.path().to_string(),
        query: util::parse_query(parts.uri.query().unwrap_or("")),
        headers: parts.headers,
        body,
    })
}

fn into_hyper(r: Resp) -> hyper::Response<Full<Bytes>> {
    let mut out = hyper::Response::new(Full::new(r.body));
    *out.status_mut() = hyper::StatusCode::from_u16(r.status).unwrap_or(hyper::StatusCode::INTERNAL_SERVER_ERROR);
    let h = out.headers_mut();
    for (n, v) in r.headers {
        if let (Ok(n), Ok(v)) = (HeaderName::from_bytes(n.as_bytes()), HeaderValue::from_str(&v)) {
            h.append(n, v);
        }
    }
    out
}

/// Serves HTTP/1.1 on one connection until it closes or `stop` fires.
pub async fn serve_conn<IO>(io: IO, h: Handler, stop: CancellationToken)
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let svc = hyper::service::service_fn(move |req: hyper::Request<Incoming>| {
        let h = h.clone();
        async move {
            let resp = match read(req).await {
                Ok(r) => h(r).await,
                Err(e) => e,
            };
            Ok::<_, Infallible>(into_hyper(resp))
        }
    });
    let conn = hyper::server::conn::http1::Builder::new()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(Duration::from_secs(10))
        .keep_alive(true)
        .serve_connection(TokioIo::new(io), svc);
    tokio::pin!(conn);
    tokio::select! {
        _ = conn.as_mut() => {}
        _ = stop.cancelled() => {
            conn.as_mut().graceful_shutdown();
            let _ = tokio::time::timeout(Duration::from_secs(3), conn).await;
        }
    }
}

/// Accepts connections until `stop` fires.
pub async fn serve(ln: TcpListener, h: Handler, stop: CancellationToken) {
    loop {
        let (sock, _) = tokio::select! {
            r = ln.accept() => match r {
                Ok(x) => x,
                Err(_) => { tokio::time::sleep(Duration::from_millis(50)).await; continue }
            },
            _ = stop.cancelled() => return,
        };
        let _ = sock.set_nodelay(true);
        tokio::spawn(serve_conn(sock, h.clone(), stop.clone()));
    }
}

/// Builds a Handler from an async closure.
#[macro_export]
macro_rules! handler {
    ($state:expr, |$s:ident, $r:ident| $body:expr) => {{
        let st = $state;
        let h: $crate::web::Handler = std::sync::Arc::new(move |$r: $crate::web::Req| {
            let $s = st.clone();
            Box::pin(async move { $body })
        });
        h
    }};
}
