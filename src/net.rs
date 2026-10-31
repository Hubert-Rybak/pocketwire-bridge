//! Outbound connections: TLS with the system's and Mozilla's roots, HTTP(S) proxies from the
//! environment, one-shot HTTP/1.1 requests and WebSocket connections.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

pub fn version() -> &'static str {
    option_env!("POCKETWIRE_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"))
}

pub fn user_agent() -> String {
    format!("pocketwire-bridge/{}", version())
}

/// Client TLS: the operating system's roots (so company proxies that inspect TLS keep
/// working) plus Mozilla's, as a fallback.
pub fn tls_config() -> Arc<rustls::ClientConfig> {
    static CFG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CFG.get_or_init(|| {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        for c in rustls_native_certs::load_native_certs().certs {
            let _ = roots.add(c);
        }
        let mut cfg = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(cfg)
    })
    .clone()
}

#[derive(Debug, Clone, PartialEq)]
pub struct Url {
    pub https: bool,
    pub host: String,
    pub port: u16,
    /// Path and query, starting with "/".
    pub path: String,
}

impl Url {
    /// Parses http(s)://host[:port][/path]; ws and wss count as http and https.
    pub fn parse(s: &str) -> Result<Url, String> {
        let (scheme, rest) = s.split_once("://").ok_or_else(|| format!("server must be http(s), got {s:?}"))?;
        let https = match scheme.to_ascii_lowercase().as_str() {
            "https" | "wss" => true,
            "http" | "ws" => false,
            _ => return Err(format!("server must be http(s), got {s:?}")),
        };
        let (authority, path) = match rest.find(['/', '?']) {
            Some(i) => (&rest[..i], rest[i..].to_string()),
            None => (rest, String::new()),
        };
        let authority = authority.rsplit('@').next().unwrap_or(authority);
        let (host, port) = if let Some(h) = authority.strip_prefix('[') {
            let (h, after) = h.split_once(']').ok_or("bad IPv6 address")?;
            (h.to_string(), after.strip_prefix(':').map(str::to_string))
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) => (h.to_string(), Some(p.to_string())),
                None => (authority.to_string(), None),
            }
        };
        if host.is_empty() {
            return Err(format!("no host in {s:?}"));
        }
        let port = match port {
            Some(p) => p.parse().map_err(|_| format!("bad port in {s:?}"))?,
            None => {
                if https {
                    443
                } else {
                    80
                }
            }
        };
        let path = if path.starts_with('/') { path } else { format!("/{path}") };
        Ok(Url { https, host, port, path })
    }

    pub fn authority(&self) -> String {
        let h = if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() };
        if (self.https && self.port == 443) || (!self.https && self.port == 80) {
            h
        } else {
            format!("{h}:{}", self.port)
        }
    }

    /// The same address with another path (for /v1/device/ws and the like).
    pub fn with_path(server: &str, suffix: &str) -> Result<Url, String> {
        let mut u = Url::parse(server.trim_end_matches('/'))?;
        let base = u.path.trim_end_matches('/').to_string();
        u.path = format!("{base}{suffix}");
        Ok(u)
    }
}

/// A plain or TLS connection.
pub enum Stream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl AsyncRead for Stream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_flush(cx),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

fn env_any(keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
}

/// The proxy for a host from HTTPS_PROXY / HTTP_PROXY / NO_PROXY, as Go and curl read them.
pub fn proxy_for(u: &Url) -> Option<String> {
    let host = u.host.to_ascii_lowercase();
    if host == "localhost" || host.parse::<std::net::IpAddr>().map(|ip| ip.is_loopback()).unwrap_or(false) {
        return None;
    }
    if let Some(no) = env_any(&["NO_PROXY", "no_proxy"]) {
        for p in no.split(',').map(|p| p.trim().to_ascii_lowercase()) {
            let p = p.split(':').next().unwrap_or("").trim_start_matches('*').to_string();
            if p == "*" || (!p.is_empty() && (host == p.trim_start_matches('.') || host.ends_with(&format!(".{}", p.trim_start_matches('.'))))) {
                return None;
            }
        }
    }
    if u.https {
        env_any(&["HTTPS_PROXY", "https_proxy"])
    } else {
        env_any(&["HTTP_PROXY", "http_proxy"])
    }
}

async fn tcp(host: &str, port: u16) -> io::Result<TcpStream> {
    let s = tokio::time::timeout(Duration::from_secs(20), TcpStream::connect((host, port)))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, format!("connecting to {host}:{port} timed out")))??;
    let _ = s.set_nodelay(true);
    Ok(s)
}

/// Opens a TCP connection to the URL's host, through an HTTP CONNECT proxy when one is set.
async fn tunnel_tcp(u: &Url) -> Result<TcpStream, String> {
    let Some(proxy) = proxy_for(u) else {
        return tcp(&u.host, u.port).await.map_err(|e| format!("{}: {e}", u.authority()));
    };
    let p = Url::parse(if proxy.contains("://") { proxy.clone() } else { format!("http://{proxy}") }.as_str())?;
    let mut s = tcp(&p.host, p.port).await.map_err(|e| format!("proxy {}: {e}", p.authority()))?;
    let target = format!("{}:{}", if u.host.contains(':') { format!("[{}]", u.host) } else { u.host.clone() }, u.port);
    let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if let Some(userinfo) = proxy.split("://").last().and_then(|r| r.split('/').next()).and_then(|a| a.rsplit_once('@')).map(|(ui, _)| ui) {
        let cred = base64::engine::general_purpose::STANDARD.encode(crate::util::query_unescape(userinfo));
        req.push_str(&format!("Proxy-Authorization: Basic {cred}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await.map_err(|e| format!("proxy: {e}"))?;
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 8192 || s.read(&mut byte).await.map_err(|e| format!("proxy: {e}"))? == 0 {
            return Err("proxy closed the connection".into());
        }
        head.push(byte[0]);
    }
    let status = String::from_utf8_lossy(&head);
    let line = status.lines().next().unwrap_or("");
    if line.split_whitespace().nth(1) != Some("200") {
        return Err(format!("proxy refused the connection: {line}"));
    }
    Ok(s)
}

pub async fn connect(u: &Url) -> Result<Stream, String> {
    let s = tunnel_tcp(u).await?;
    if !u.https {
        return Ok(Stream::Plain(s));
    }
    let name = rustls::pki_types::ServerName::try_from(u.host.clone()).map_err(|_| format!("bad host name {:?}", u.host))?;
    let tls = tokio::time::timeout(Duration::from_secs(20), tokio_rustls::TlsConnector::from(tls_config()).connect(name, s))
        .await
        .map_err(|_| format!("{}: TLS handshake timed out", u.authority()))?
        .map_err(|e| format!("{}: {e}", u.authority()))?;
    Ok(Stream::Tls(Box::new(tls)))
}

pub struct Response {
    pub status: u16,
    pub headers: hyper::HeaderMap,
    pub body: Bytes,
}

/// Sends one HTTP/1.1 request on a new connection and reads the whole answer (at most `limit` bytes).
pub async fn request(method: &str, url: &str, headers: &[(&str, String)], body: Bytes, limit: usize) -> Result<Response, String> {
    let u = Url::parse(url)?;
    let stream = connect(&u).await?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.map_err(|e| e.to_string())?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let mut b = hyper::Request::builder().method(method).uri(&u.path).header("host", u.authority()).header("user-agent", user_agent());
    for (k, v) in headers {
        b = b.header(*k, v);
    }
    let req = b.body(Full::new(body)).map_err(|e| e.to_string())?;
    let res = tokio::time::timeout(Duration::from_secs(60), sender.send_request(req))
        .await
        .map_err(|_| "request timed out".to_string())?
        .map_err(|e| e.to_string())?;
    let (parts, incoming) = res.into_parts();
    let body = http_body_util::Limited::new(incoming, limit).collect().await.map_err(|e| e.to_string())?.to_bytes();
    Ok(Response { status: parts.status.as_u16(), headers: parts.headers, body })
}

pub type WebSocket = tokio_tungstenite::WebSocketStream<Stream>;

/// Opens a WebSocket (ws:// or wss://), with frames of at most `max_message` bytes.
pub async fn websocket(url: &Url, max_message: usize) -> Result<WebSocket, String> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let scheme = if url.https { "wss" } else { "ws" };
    let mut req = format!("{scheme}://{}{}", url.authority(), url.path).into_client_request().map_err(|e| e.to_string())?;
    req.headers_mut().insert("user-agent", user_agent().parse().map_err(|_| "bad user agent")?);
    let stream = connect(url).await?;
    let mut cfg = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default();
    cfg.max_message_size = Some(max_message);
    cfg.max_frame_size = Some(max_message);
    let (ws, _) = tokio::time::timeout(Duration::from_secs(20), tokio_tungstenite::client_async_with_config(req, stream, Some(cfg)))
        .await
        .map_err(|_| "WebSocket handshake timed out".to_string())?
        .map_err(|e| e.to_string())?;
    Ok(ws)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_urls() {
        let u = Url::parse("https://pocketwire.app").unwrap();
        assert_eq!((u.https, u.host.as_str(), u.port, u.path.as_str()), (true, "pocketwire.app", 443, "/"));
        let u = Url::with_path("http://127.0.0.1:8080/base/", "/v1/device/ws").unwrap();
        assert_eq!((u.port, u.path.as_str(), u.authority()), (8080, "/base/v1/device/ws", "127.0.0.1:8080".to_string()));
        let u = Url::parse("http://[::1]:9/x?y=1").unwrap();
        assert_eq!((u.host.as_str(), u.port, u.path.as_str(), u.authority()), ("::1", 9, "/x?y=1", "[::1]:9".to_string()));
        assert!(Url::parse("ftp://x").is_err());
    }
}
