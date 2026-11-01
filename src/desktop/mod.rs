//! The Bridge's background app: a tray icon (the menu bar on a Mac) and a small control page on
//! 127.0.0.1, where the user pairs the computer, sees whether the Bridge is connected and turns
//! starting at sign-in on or off. Approvals and message history live in the dashboard.

pub mod panel;
#[cfg(feature = "tray")]
pub mod tray;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use crate::bridge::{self, Running};
use crate::client::{self, Runner};
use crate::config::{self, LoadError};
use crate::driver::Driver;
use crate::logf;
use crate::util::open_browser;

/// Where the control page listens on 127.0.0.1. It also keeps a second copy of the app from
/// starting: the second copy opens the first one's page and exits.
pub const PANEL_PORT: u16 = 47301;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    NotPaired = 0,
    Starting = 1,
    Connecting = 2,
    Connected = 3,
    /// Another Bridge (pocketwire run or the service) already runs on this computer.
    Elsewhere = 4,
    Failed = 5,
}

impl State {
    pub fn label(self) -> &'static str {
        match self {
            State::NotPaired => "Not paired yet",
            State::Starting => "Starting…",
            State::Connecting => "Connecting to Pocketwire…",
            State::Connected => "Connected",
            State::Elsewhere => "Another Bridge is running on this computer",
            State::Failed => "Stopped with an error",
        }
    }
}

struct Run {
    runner: Arc<Runner>,
    driver: Driver,
    stop: CancellationToken,
    id: u64,
}

struct St {
    state: State,
    detail: String,
    run: Option<Run>,
    driver_err: Option<String>,
    next_id: u64,
}

/// The current state for the tray and the page.
#[derive(Clone, Debug)]
pub struct Snapshot {
    pub state: State,
    pub detail: String,
    pub driver_name: String,
    pub driver_err: Option<String>,
    pub autostart: bool,
    pub log_path: String,
    pub version: String,
}

pub struct App {
    key: String,
    pub config_path: PathBuf,
    pub log_path: String,
    pub server: String,
    st: Mutex<St>,
    changes: watch::Sender<u64>,
    /// Ends the app (Quit in the tray, or a signal).
    pub quit: CancellationToken,
}

fn panel_key(path: &std::path::Path) -> Result<String, String> {
    if let Ok(s) = std::fs::read_to_string(path) {
        if s.trim().len() >= 32 {
            return Ok(s.trim().to_string());
        }
    }
    let k = crate::util::random_hex(16);
    if let Some(d) = path.parent() {
        config::create_private_dir(d)?;
    }
    config::write_private(path, k.as_bytes())?;
    Ok(k)
}

/// This computer's name, as the dashboard shows it by default.
pub fn hostname() -> String {
    if let Ok(n) = std::env::var("COMPUTERNAME") {
        if cfg!(windows) && !n.is_empty() {
            return n;
        }
    }
    if let Ok(n) = std::fs::read_to_string("/proc/sys/kernel/hostname") {
        if !n.trim().is_empty() {
            return n.trim().to_string();
        }
    }
    std::process::Command::new("hostname")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "My computer".into())
}

impl App {
    pub fn new(config_path: PathBuf, log_path: String, server: String, quit: CancellationToken) -> Result<Arc<App>, String> {
        let key = panel_key(&config::sibling(&config_path, "panel.key"))?;
        Ok(Arc::new(App {
            key,
            config_path,
            log_path,
            server,
            st: Mutex::new(St { state: State::Starting, detail: String::new(), run: None, driver_err: None, next_id: 0 }),
            changes: watch::channel(0).0,
            quit,
        }))
    }

    /// Opens the control page (the key sets a cookie on first use).
    pub fn panel_url(&self) -> String {
        format!("http://127.0.0.1:{PANEL_PORT}/?k={}", self.key)
    }

    /// A page of the dashboard, such as "/approvals" or "/devices" ("" for its start page).
    pub fn dashboard_url(&self, page: &str) -> String {
        format!("{}/app{page}", self.server.trim_end_matches('/'))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, St> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn snapshot(&self) -> Snapshot {
        let st = self.lock();
        let driver_name = st.run.as_ref().map(|r| r.driver.name().to_string()).unwrap_or_default();
        Snapshot {
            state: st.state,
            detail: st.detail.clone(),
            driver_name,
            driver_err: st.driver_err.clone(),
            autostart: crate::autostart::enabled(),
            log_path: self.log_path.clone(),
            version: crate::net::version().to_string(),
        }
    }

    /// Fires whenever the state may have changed.
    #[cfg_attr(not(feature = "tray"), allow(dead_code))]
    pub fn changes(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }

    pub fn poke(&self) {
        self.changes.send_modify(|n| *n += 1);
    }

    fn set(&self, s: State, detail: &str) {
        let changed = {
            let mut st = self.lock();
            let c = st.state != s || st.detail != detail;
            st.state = s;
            st.detail = detail.to_string();
            c
        };
        if changed {
            logf!("app: {} {detail}", s.label());
            self.poke();
        }
    }

    pub fn csrf(&self) -> String {
        crate::util::hmac_hex(self.key.as_bytes(), b"csrf")[..32].to_string()
    }

    pub fn key(&self) -> &str {
        &self.key
    }

    /// Takes the control page's port, or None after opening the page of the copy that holds it.
    pub async fn listen(&self) -> Result<Option<TcpListener>, String> {
        match TcpListener::bind(("127.0.0.1", PANEL_PORT)).await {
            Ok(ln) => Ok(Some(ln)),
            Err(e) => {
                if tokio::time::timeout(Duration::from_secs(1), tokio::net::TcpStream::connect(("127.0.0.1", PANEL_PORT)))
                    .await
                    .map(|r| r.is_ok())
                    .unwrap_or(false)
                {
                    let _ = open_browser(&self.panel_url());
                    return Ok(None);
                }
                Err(format!("control page on port {PANEL_PORT}: {e}"))
            }
        }
    }

    /// Runs the control page and keeps the Bridge running until `quit` fires.
    pub async fn serve(self: Arc<Self>, ln: TcpListener, open_panel: bool) {
        let h = crate::handler!(self.clone(), |s, r| panel::handle(&s, r).await);
        tokio::spawn(crate::web::serve(ln, h, self.quit.clone()));
        self.start_if_paired().await;
        if open_panel {
            let _ = open_browser(&self.panel_url());
        }
        let mut t = tokio::time::interval(Duration::from_secs(2));
        let mut last_check: Option<Instant> = None;
        loop {
            tokio::select! {
                _ = t.tick() => {}
                _ = self.quit.cancelled() => { self.stop(); return }
            }
            let (st, run) = {
                let g = self.lock();
                (g.state, g.run.as_ref().map(|r| (r.runner.clone(), r.driver.clone())))
            };
            match (st, run) {
                (State::Elsewhere, _) => self.start_if_paired().await,
                (State::Connecting | State::Connected | State::Starting, Some((runner, driver))) => {
                    self.set(if runner.is_connected() { State::Connected } else { State::Connecting }, "");
                    if last_check.map(|t| t.elapsed() > Duration::from_secs(60)).unwrap_or(true) {
                        last_check = Some(Instant::now());
                        let me = self.clone();
                        tokio::spawn(async move { me.check_driver(driver).await });
                    }
                }
                _ => {}
            }
        }
    }

    async fn check_driver(&self, d: Driver) {
        let err = match tokio::time::timeout(Duration::from_secs(15), d.check()).await {
            Ok(Ok(())) => None,
            Ok(Err(e)) => Some(e),
            Err(_) => Some("the check timed out".into()),
        };
        self.lock().driver_err = err;
    }

    /// Whether a Bridge outside this app already answers on its marker port.
    async fn other_bridge(&self) -> bool {
        let url = format!("http://127.0.0.1:{}/healthz", bridge::LOCK_PORT);
        matches!(tokio::time::timeout(Duration::from_secs(1), crate::net::request("GET", &url, &[], Default::default(), 4096)).await, Ok(Ok(r)) if r.status == 200)
    }

    async fn start_if_paired(self: &Arc<Self>) {
        if let Err(e) = config::load(&self.config_path) {
            match e {
                LoadError::NotPaired => self.set(State::NotPaired, ""),
                LoadError::Other(e) => self.set(State::Failed, &e),
            }
            return;
        }
        if self.lock().run.is_some() {
            return;
        }
        if self.other_bridge().await {
            self.set(State::Elsewhere, "It may be `pocketwire run` in a terminal or the background service. Stop it and this app takes over.");
            return;
        }
        self.set(State::Starting, "");
        let stop = self.quit.child_token();
        let started = match bridge::load_paired() {
            Ok((c, _)) => bridge::start(&c, stop.clone()).await,
            Err(e) => Err(e),
        };
        let r: Running = match started {
            Ok(r) => r,
            Err(e) => {
                stop.cancel();
                self.set(State::Failed, &e);
                return;
            }
        };
        let id = {
            let mut g = self.lock();
            g.next_id += 1;
            let id = g.next_id;
            g.run = Some(Run { runner: r.runner.clone(), driver: r.driver.clone(), stop: stop.clone(), id });
            id
        };
        {
            let me = self.clone();
            let d = r.driver.clone();
            tokio::spawn(async move { me.check_driver(d).await });
        }
        let me = self.clone();
        tokio::spawn(async move {
            let res = r.done.await.unwrap_or(Ok(()));
            let current = {
                let mut g = me.lock();
                let cur = g.run.as_ref().map(|x| x.id) == Some(id);
                if cur {
                    g.run = None;
                }
                cur
            };
            stop.cancel();
            if !current || me.quit.is_cancelled() {
                return;
            }
            match res {
                Err(e) if e == client::REVOKED => {
                    if let Err(e) = config::remove(&me.config_path) {
                        logf!("app: removing pairing: {e}");
                    }
                    me.set(State::NotPaired, "This computer was removed from your Pocketwire account. Pair it again.");
                }
                Err(e) => me.set(State::Failed, &e),
                Ok(()) => me.set(State::Failed, "The Bridge stopped."),
            }
        });
    }

    fn stop(&self) {
        if let Some(r) = self.lock().run.take() {
            r.stop.cancel();
        }
    }

    /// Pairs from the control page.
    pub async fn pair(self: &Arc<Self>, code: &str, name: &str, drv: &str, kde: &str) -> Result<(), String> {
        if self.snapshot().state != State::NotPaired {
            return Err("this computer is already paired; unpair it first".into());
        }
        if code.trim().is_empty() {
            return Err("enter the pairing code from the dashboard".into());
        }
        let name = if name.is_empty() { hostname() } else { name.to_string() };
        tokio::time::timeout(Duration::from_secs(30), bridge::pair_device(&self.server, code, &name, drv, kde, "sms"))
            .await
            .map_err(|_| "pairing timed out".to_string())??;
        self.start_if_paired().await;
        Ok(())
    }

    /// Stops the Bridge and removes the local pairing.
    pub fn unpair(&self) -> Result<(), String> {
        self.stop();
        config::remove(&self.config_path)?;
        self.set(State::NotPaired, "Removed the pairing from this computer. Also remove it under Devices in the dashboard.");
        Ok(())
    }

    /// Starts the Bridge again after an error.
    pub async fn retry(self: &Arc<Self>) {
        if matches!(self.snapshot().state, State::Failed | State::Elsewhere) {
            self.start_if_paired().await;
        }
    }

    pub fn set_autostart(&self, on: bool) -> Result<(), String> {
        let r = crate::autostart::set(on);
        self.poke();
        r
    }

    #[cfg_attr(not(feature = "tray"), allow(dead_code))]
    pub fn open(&self, url: &str) {
        if !url.is_empty() {
            let _ = open_browser(url);
        }
    }
}
