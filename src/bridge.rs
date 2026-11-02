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
    start_with(c, d, stop).await
}

async fn start_with(c: &Config, d: Driver, stop: CancellationToken) -> Result<Running, String> {
    let key = Arc::new(DeviceKey::from_pem(&c.private_key_pem)?);
    // The phone check runs on the side: on a Mac it can wait for the Automation prompt, and the
    // connection to Pocketwire must not wait for it.
    {
        let d = d.clone();
        tokio::spawn(async move {
            if let Err(e) = d.check_within(crate::driver::CHECK_TIMEOUT).await {
                logf!("warning: driver {} is not ready: {e}", d.name());
            }
        });
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::{tests::hanging, Kind};

    #[tokio::test]
    async fn starts_without_waiting_for_the_phone_check() {
        let key = DeviceKey::generate().unwrap();
        let c = Config {
            server: "http://127.0.0.1:9".into(),
            device_id: "dev".into(),
            account_id: "acc".into(),
            name: "test".into(),
            private_key_pem: key.to_pem(),
            driver: "macos-messages".into(),
            driver_options: Default::default(),
        };
        let d = Driver::for_test(Kind::MacMessages { service: String::new() }, hanging(), "macos", None);
        let stop = CancellationToken::new();
        let started = tokio::time::timeout(std::time::Duration::from_secs(5), start_with(&c, d, stop.clone())).await;
        stop.cancel();
        assert!(matches!(started, Ok(Ok(_))), "start waited for the driver check");
    }
}
