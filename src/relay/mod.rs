//! The blind relay: the tunnel to Pocketwire and TLS that ends on this computer.

pub mod certs;
pub mod tunnel;

use std::sync::Arc;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::web::Handler;

/// Terminates TLS on each relayed connection and serves `h` over it.
pub async fn serve(mut conns: mpsc::Receiver<tunnel::Conn>, certs: Arc<certs::Certs>, h: Handler, stop: CancellationToken) {
    loop {
        let c = tokio::select! {
            c = conns.recv() => match c { Some(c) => c, None => return },
            _ = stop.cancelled() => return,
        };
        let (certs, h, stop) = (certs.clone(), h.clone(), stop.clone());
        tokio::spawn(async move {
            let acc = tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), c.io);
            let Ok(Ok(start)) = tokio::time::timeout(std::time::Duration::from_secs(10), acc).await else { return };
            let hello = start.client_hello();
            let sni = hello.server_name().map(str::to_string);
            let alpn: Vec<Vec<u8>> = hello.alpn().map(|a| a.map(|p| p.to_vec()).collect()).unwrap_or_default();
            let acme = alpn.iter().any(|p| p == b"acme-tls/1");
            let cfg = match certs.config_for(sni.as_deref(), &alpn).await {
                Ok(c) => c,
                Err(e) => {
                    crate::logf!("relay TLS from {}: {e}", c.remote);
                    return;
                }
            };
            let Ok(Ok(tls)) = tokio::time::timeout(std::time::Duration::from_secs(10), start.into_stream(cfg)).await else { return };
            if acme {
                // The CA only checks the handshake.
                return;
            }
            crate::web::serve_conn(tls, h, stop).await;
        });
    }
}
