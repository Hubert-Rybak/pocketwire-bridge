//! Starting a paired Bridge: the device connection to Pocketwire, and a small marker on
//! 127.0.0.1 that tells other copies of the Bridge on this computer that one already runs.

use std::path::PathBuf;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use crate::client::{self, Runner};
use crate::config::{self, Config};
use crate::driver::Driver;
use crate::logf;
use crate::net;
use crate::protocol::DeviceKey;
use crate::web::Resp;

/// Where a running Bridge answers GET /healthz on 127.0.0.1, so that the background app and
/// `pocketwire run` don't both connect as the same device. Earlier versions answered on the
/// same port, so they are recognised too.
pub const LOCK_PORT: u16 = 47300;

/// A started Bridge.
pub struct Running {
    pub runner: Arc<Runner>,
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
) -> Result<(PathBuf, client::PairResult), String> {
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
    };
    config::save(&path, &c)?;
    Ok((path, res))
}

/// Loads the pairing from the default config file.
pub fn load_paired() -> Result<(Config, PathBuf), String> {
    let path = config::default_path()?;
    let c = config::load(&path)?;
    Ok((c, path))
}

/// Takes the marker port, or explains why another Bridge probably runs already.
async fn bind_lock() -> Result<TcpListener, String> {
    TcpListener::bind(("127.0.0.1", LOCK_PORT))
        .await
        .map_err(|e| format!("listen tcp 127.0.0.1:{LOCK_PORT}: {e} (is another Bridge running on this computer?)"))
}

/// Starts the device connection; it runs until `stop` fires or the device is revoked.
pub async fn start(c: &Config, stop: CancellationToken) -> Result<Running, String> {
    let d = Driver::new(&c.driver, &c.driver_options, None)?;
    let key = Arc::new(DeviceKey::from_pem(&c.private_key_pem)?);
    if let Err(e) = d.check().await {
        logf!("warning: driver {} is not ready: {e}", d.name());
    }
    let r = Runner::new(&c.server, &c.device_id, key, d.clone());

    logf!("Pocketwire Bridge {} starting ({})", net::version(), c.server);
    match bind_lock().await {
        Ok(ln) => {
            let h = crate::handler!((), |_s, r| match (r.method.as_str(), r.path.as_str()) {
                ("GET", "/healthz") => Resp::new(200).with("content-type", "application/json").body(r#"{"ok":true}"#),
                _ => Resp::not_found(),
            });
            tokio::spawn(crate::web::serve(ln, h, stop.clone()));
        }
        Err(e) => logf!("warning: {e}"),
    }

    let (done_tx, done) = oneshot::channel();
    let runner = r.clone();
    let s = stop.clone();
    tokio::spawn(async move {
        let res = runner.run(s.clone()).await;
        // Stop the marker too, whatever ended the connection.
        s.cancel();
        let _ = done_tx.send(res);
    });
    Ok(Running { runner: r, driver: d, done })
}
