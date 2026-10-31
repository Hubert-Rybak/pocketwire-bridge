//! Starting a paired Bridge: the device connection, the private endpoint and the approval page,
//! and the private address through the relay.

use std::path::Path;
use std::sync::{Arc, Mutex};

use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use crate::client::{self, Runner, Upstream};
use crate::config::{self, Config};
use crate::driver::Driver;
use crate::local::approvals::Phones;
use crate::local::engine::Engine;
use crate::local::localweb::{self, Hostname, LocalWeb};
use crate::local::mcp::Mcp;
use crate::local::relayweb::{Introspect, RelayWeb};
use crate::local::store::Store;
use crate::logf;
use crate::net;
use crate::protocol::DeviceKey;
use crate::relay::{self, certs::Certs, tunnel::Tunnel};

/// A started Bridge.
pub struct Running {
    pub runner: Arc<Runner>,
    pub approval_url: String,
    pub hostname: Hostname,
    pub relay: bool,
    pub driver: Driver,
    /// The Bridge's result when it stops (Err(REVOKED), another error, or Ok when stopped).
    pub done: oneshot::Receiver<Result<(), String>>,
}

/// Registers this computer with a dashboard pairing code and saves the config.
pub async fn pair_device(
    server: &str,
    code: &str,
    name: &str,
    drv: &str,
    kde_device: &str,
    msg_service: &str,
) -> Result<(std::path::PathBuf, client::PairResult), String> {
    Driver::new(drv, &Default::default(), None)?;
    let key = DeviceKey::generate()?;
    let res = client::pair(server, code, name, &key).await?;
    let mut opts = std::collections::BTreeMap::new();
    if !kde_device.is_empty() {
        opts.insert("device".to_string(), kde_device.to_string());
    }
    if drv == "macos-messages" {
        opts.insert("service".to_string(), msg_service.to_string());
    }
    let path = config::default_path()?;
    let c = Config {
        server: server.trim_end_matches('/').to_string(),
        device_id: res.device_id.clone(),
        account_id: res.account_id.clone(),
        name: name.to_string(),
        private_key_pem: key.to_pem(),
        driver: drv.to_string(),
        driver_options: opts,
        ..Default::default()
    };
    config::save(&path, &c)?;
    Ok((path, res))
}

/// Loads the config and makes sure the private endpoint's secrets exist.
pub fn load_local() -> Result<(Config, std::path::PathBuf), String> {
    let path = config::default_path()?;
    let mut c = config::load(&path)?;
    if c.ensure_local() {
        config::save(&path, &c)?;
    }
    Ok((c, path))
}

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.is_empty())
}

/// Starts everything; it runs until `stop` fires or the device is revoked.
pub async fn start(c: &Config, path: &Path, no_relay: bool, stop: CancellationToken) -> Result<Running, String> {
    let d = Driver::new(&c.driver, &c.driver_options, None)?;
    let key = Arc::new(DeviceKey::from_pem(&c.private_key_pem)?);
    let tag_key = crate::util::unhex(&c.tag_key).ok_or("config tag_key: invalid hex")?;
    if let Err(e) = d.check().await {
        logf!("warning: driver {} is not ready: {e}", d.name());
    }
    let r = Runner::new(&c.server, &c.device_id, key.clone(), d.clone());
    let store = Arc::new(Store::new(Some(config::sibling(path, "messages.json"))));
    let eng = Engine::new(r.clone() as Arc<dyn Upstream>, d.clone(), store, tag_key);
    {
        let e = eng.clone();
        r.on_trusted(move |n| e.set_trusted(&n));
    }
    let hostname: Hostname = Arc::new(Mutex::new(String::new()));
    let phones = Arc::new(Phones::new(Some(config::sibling(path, "phones.json"))));
    let mcp = Mcp::new(eng.clone(), &c.device_id, &c.name, client::platform());
    let web = Arc::new(LocalWeb {
        mcp: mcp.clone(),
        engine: eng.clone(),
        port: c.local_port,
        token: c.local_token.clone(),
        phones: (!no_relay).then(|| phones.clone()),
        hostname: (!no_relay).then(|| hostname.clone()),
    });
    let approval_url = web.approval_url();
    if !c.no_open_approvals {
        let url = approval_url.clone();
        *eng.on_approval.lock().unwrap() = Some(Box::new(move |_| {
            let _ = localweb::open_browser(&url);
        }));
    }

    logf!("Pocketwire Bridge {} starting ({})", net::version(), c.server);
    match web.bind().await {
        Ok(ln) => {
            tokio::spawn(web.clone().serve(ln, stop.clone()));
        }
        Err(e) => logf!("warning: private MCP endpoint not available: {e}"),
    }
    logf!("private MCP endpoint: {}/mcp (see `pocketwire connect`)", web.base());

    if !no_relay {
        // TLS ends here, with a certificate whose key never leaves this computer.
        match Certs::new(config::sibling(path, "certs"), env("POCKETWIRE_ACME_DIRECTORY"), env("POCKETWIRE_RELAY_CERT"), env("POCKETWIRE_RELAY_KEY")) {
            Err(e) => logf!("warning: private address for cloud AI apps not available: {e}"),
            Ok(certs) => {
                let introspect: Introspect = {
                    let r = r.clone();
                    Arc::new(move |h: String| {
                        let r = r.clone();
                        Box::pin(async move { r.introspect(&h).await })
                    })
                };
                let rw = RelayWeb::new(mcp.clone(), &c.server, hostname.clone(), introspect, Some(eng.clone()), Some(phones.clone()));
                let (tx, rx) = mpsc::channel(16);
                let (h2, c2) = (hostname.clone(), certs.clone());
                let t = Tunnel::new(&c.server, &c.device_id, key.clone(), move |h| {
                    *h2.lock().unwrap() = h.to_string();
                    c2.set_hostname(h);
                });
                let handler = crate::handler!(rw, |s, req| s.handle(req).await);
                tokio::spawn(relay::serve(rx, certs, handler, stop.clone()));
                tokio::spawn(t.run(tx, stop.clone()));
            }
        }
    }

    let (done_tx, done) = oneshot::channel();
    let runner = r.clone();
    let s = stop.clone();
    tokio::spawn(async move {
        let res = runner.run(s.clone()).await;
        // Stop the endpoints too, whatever ended the connection.
        s.cancel();
        let _ = done_tx.send(res);
    });
    Ok(Running { runner: r, approval_url, hostname, relay: !no_relay, driver: d, done })
}
