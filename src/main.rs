//! Pocketwire Bridge: lets AI apps send texts from your own phone, with your approval.
//! The command-line tool, the service and the background app with a tray icon are one binary.

// The windowless Windows build (PocketwireBridge.exe) has no console window.
#![cfg_attr(all(windows, feature = "gui"), windows_subsystem = "windows")]

mod autostart;
mod bridge;
mod client;
mod config;
mod desktop;
mod driver;
mod log;
mod net;
mod protocol;
mod service;
mod util;
mod web;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
mod winreg;

use std::collections::HashMap;
use std::io::Write;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

const DEFAULT_SERVER: &str = "https://pocketwire.app";

/// The connector address for every AI app; the server queues texts and sends them to the Bridge.
const MCP_URL: &str = "https://pocketwire.app/mcp";

/// Whether this is the windowless build (PocketwireBridge.exe, the binary in the macOS app bundle).
const GUI_BUILD: bool = cfg!(feature = "gui");

fn usage() -> String {
    format!(
        r#"Pocketwire Bridge — lets your AI agents text from your phone, with your approval.
Keep this computer on and connected to your phone: an iPhone through Messages on a Mac,
or an Android phone through KDE Connect on any computer.

Usage:
  pocketwire pair <CODE> [--server URL] [--name NAME] [--driver NAME] [--kdeconnect-device ID] [--messages-service sms|imessage]
  pocketwire run                          keep this computer connected and deliver texts
  pocketwire app [--background]           run in the background with a tray icon and a control page
  pocketwire connect                      how to connect an AI app
  pocketwire doctor
  pocketwire test-send <+E164> <text>     send one message through the driver locally (asks first)
  pocketwire service install|uninstall     start at sign-in (Windows: the tray app; macOS and Linux: a service)
  pocketwire unpair
  pocketwire version

Drivers: {}
  macos-messages  macOS Messages.app with your iPhone (Text Message Forwarding, or iMessage); default on macOS
  kdeconnect      KDE Connect with a paired Android phone; default on Windows and Linux, works on macOS too
  dry-run         prints messages instead of sending; for trying things out

AI apps connect to {MCP_URL}. The Pocketwire server keeps their
texts, queues them while this computer or the phone is offline and sends them to
this Bridge, which delivers them. Approvals, history and limits are in the
dashboard at {DEFAULT_SERVER}/app.

Get a pairing code at {DEFAULT_SERVER}/app/devices.
"#,
        driver::NAMES.join(", ")
    )
}

fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut args: Vec<String> = std::env::args().collect();
    // The windowless build, and pocketwire.exe double-clicked in Explorer, start the background
    // app instead of printing the usage. Finder may pass -psn_…; with any other argument the
    // same binary works as the command-line tool.
    let gui_start = GUI_BUILD && (args.len() == 1 || args[1] == "--background" || args[1].starts_with("-psn_"));
    let double_click = !gui_start && args.len() == 1 && started_by_double_click();
    if gui_start || double_click {
        if args.get(1).is_some_and(|a| a.starts_with("-psn_")) {
            args.remove(1);
        }
        args.insert(1, "app".into());
    }
    let quiet = GUI_BUILD || double_click;
    if args.len() < 2 {
        eprint!("{}", usage());
        std::process::exit(2);
    }
    let cmd = args[1].clone();
    let rest = args[2..].to_vec();
    let result = match cmd.as_str() {
        "version" | "--version" | "-v" => {
            println!("pocketwire {}", net::version());
            Ok(())
        }
        "help" | "--help" | "-h" => {
            print!("{}", usage());
            Ok(())
        }
        "_installer" => installer(&rest),
        "app" => cmd_app(&rest, quiet),
        "pair" | "run" | "connect" | "doctor" | "test-send" | "service" | "unpair" => block_on(async move {
            let stop = CancellationToken::new();
            tokio::spawn(on_signal(stop.clone()));
            match cmd.as_str() {
                "pair" => cmd_pair(&rest).await,
                "run" => cmd_run(&rest, stop).await,
                "connect" => cmd_connect(),
                "doctor" => cmd_doctor().await,
                "test-send" => cmd_test_send(&rest).await,
                "service" => cmd_service(&rest).await,
                _ => cmd_unpair(),
            }
        }),
        other => Err(format!("unknown command {} (try `pocketwire help`)", log::quote(other))),
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread().enable_all().build().expect("tokio runtime")
}

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    runtime().block_on(f)
}

/// Cancels `stop` on Ctrl-C, or SIGTERM on Unix.
async fn on_signal(stop: CancellationToken) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
    stop.cancel();
}

#[cfg(windows)]
fn started_by_double_click() -> bool {
    windows::started_by_double_click()
}

#[cfg(not(windows))]
fn started_by_double_click() -> bool {
    false
}

#[cfg(windows)]
fn installer(args: &[String]) -> Result<(), String> {
    windows::installer(args)
}

#[cfg(not(windows))]
fn installer(_: &[String]) -> Result<(), String> {
    Err("the installer helper is for Windows only".into())
}

fn env_or(k: &str, def: &str) -> String {
    std::env::var(k).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| def.to_string())
}

/// Flags in the style of Go's flag package: -name or --name, a value after = or as the next
/// argument, and bare names for switches. Parsing stops at the first argument that isn't one.
struct Flags {
    values: HashMap<&'static str, String>,
    switches: HashMap<&'static str, bool>,
    rest: Vec<String>,
}

fn parse_flags(args: &[String], value_flags: &[&'static str], switch_flags: &[&'static str]) -> Result<Flags, String> {
    let mut f = Flags { values: HashMap::new(), switches: HashMap::new(), rest: Vec::new() };
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            i += 1;
            break;
        }
        if !a.starts_with('-') || a == "-" {
            break;
        }
        let name = a.trim_start_matches('-');
        let (name, inline) = match name.split_once('=') {
            Some((n, v)) => (n, Some(v.to_string())),
            None => (name, None),
        };
        if let Some(k) = value_flags.iter().find(|k| **k == name) {
            let v = match inline {
                Some(v) => v,
                None => {
                    i += 1;
                    args.get(i).cloned().ok_or_else(|| format!("flag needs an argument: -{name}"))?
                }
            };
            f.values.insert(k, v);
        } else if let Some(k) = switch_flags.iter().find(|k| **k == name) {
            let on = match inline.as_deref() {
                None | Some("true") | Some("1") => true,
                Some("false") | Some("0") => false,
                Some(v) => return Err(format!("invalid boolean value {} for -{name}", log::quote(v))),
            };
            f.switches.insert(k, on);
        } else {
            return Err(format!("flag provided but not defined: -{name}"));
        }
        i += 1;
    }
    f.rest.extend(args[i..].iter().cloned());
    Ok(f)
}

impl Flags {
    fn value(&self, k: &str) -> Option<&str> {
        self.values.get(k).map(String::as_str)
    }
    fn on(&self, k: &str) -> bool {
        self.switches.get(k).copied().unwrap_or(false)
    }
}

async fn cmd_pair(args: &[String]) -> Result<(), String> {
    // Allow the code before or after the flags.
    let (mut code, args) = match args.first() {
        Some(a) if !a.starts_with('-') => (a.clone(), &args[1..]),
        _ => (String::new(), args),
    };
    let f = parse_flags(args, &["server", "name", "driver", "kdeconnect-device", "messages-service"], &[])?;
    if code.is_empty() {
        code = f.rest.first().cloned().unwrap_or_default();
    }
    if code.is_empty() {
        return Err("missing pairing code: pocketwire pair K7Q2-M9XD".into());
    }
    let server = f.value("server").map(str::to_string).unwrap_or_else(|| env_or("POCKETWIRE_SERVER", DEFAULT_SERVER));
    let name = f.value("name").map(str::to_string).unwrap_or_else(desktop::hostname);
    let drv = f.value("driver").unwrap_or(driver::default_name()).to_string();
    let (path, res) =
        bridge::pair_device(&server, &code, &name, &drv, f.value("kdeconnect-device").unwrap_or(""), f.value("messages-service").unwrap_or("sms")).await?;
    println!(
        "Paired as {} ({}) using the {drv} driver.\nConfig: {}\nNext: run `pocketwire run`, or `pocketwire service install` to keep it running.",
        log::quote(&name),
        res.device_id,
        path.display()
    );
    Ok(())
}

async fn cmd_run(args: &[String], stop: CancellationToken) -> Result<(), String> {
    let f = parse_flags(args, &[], &[])?;
    if let Some(a) = f.rest.first() {
        return Err(format!("unexpected argument {} (usage: pocketwire run)", log::quote(a)));
    }
    let (c, _) = bridge::load_paired()?;
    let run = bridge::start(&c, stop).await?;
    run.done.await.unwrap_or(Ok(()))
}

fn cmd_connect() -> Result<(), String> {
    let server = env_or("POCKETWIRE_SERVER", DEFAULT_SERVER);
    let server = server.trim_end_matches('/');
    print!(
        r#"Every AI app connects to the same address:

  {server}/mcp

Add it in the app as a custom connector (a remote MCP server); the app asks you to sign in
to Pocketwire once. There is nothing to set up on this computer besides pairing it.

The Pocketwire server keeps the texts the app sends, queues them while this computer or your
phone is offline (for up to 24 hours) and sends them to this Bridge, which delivers them.
Approvals: {server}/app/approvals
"#
    );
    Ok(())
}

async fn cmd_doctor() -> Result<(), String> {
    let path = config::default_path()?;
    let c = match config::load(&path) {
        Ok(c) => {
            println!("Pairing:  {} on {} (driver {})\nConfig:   {}", c.device_id, c.server, c.driver, path.display());
            Some(c)
        }
        Err(e) => {
            println!("Pairing:  not paired — {e}");
            None
        }
    };
    for n in driver::NAMES {
        let opts = c.as_ref().filter(|c| c.driver == n).map(|c| c.driver_options.clone()).unwrap_or_default();
        let res = match driver::Driver::new(n, &opts, None) {
            Ok(d) => d.check_within(Duration::from_secs(10)).await,
            Err(e) => Err(e),
        };
        match res {
            Ok(()) => println!("  ✓ {n:<15} ready"),
            Err(e) => println!("  ✗ {n:<15} {e}"),
        }
    }
    Ok(())
}

async fn cmd_test_send(args: &[String]) -> Result<(), String> {
    let [to, body] = args else { return Err("usage: pocketwire test-send +48501234567 \"text\"".into()) };
    let path = config::default_path()?;
    let c = config::load(&path)?;
    let d = driver::Driver::new(&c.driver, &c.driver_options, None)?;
    let p = protocol::CommandParams { to: to.clone(), body: body.clone() };
    protocol::validate_params(Some(&p))?;
    print!("Send {} to {} via {}? Type yes to confirm: ", log::quote(&p.body), p.to, d.name());
    let _ = std::io::stdout().flush();
    let mut answer = String::new();
    let _ = std::io::stdin().read_line(&mut answer);
    if answer.split_whitespace().next() != Some("yes") {
        return Err("cancelled".into());
    }
    d.send_sms(&p.to, &p.body).await
}

async fn cmd_service(args: &[String]) -> Result<(), String> {
    let r = driver::exec_runner();
    match args {
        [a] if a == "install" => {
            let w = service::install(&r).await?;
            println!("Installed and started: {w}");
            Ok(())
        }
        [a] if a == "uninstall" => service::uninstall(&r).await,
        [a] => Err(format!("unknown service action {}", log::quote(a))),
        _ => Err("usage: pocketwire service install|uninstall".into()),
    }
}

fn cmd_unpair() -> Result<(), String> {
    let path = config::default_path()?;
    config::remove(&path)?;
    println!("Removed local pairing. Also remove the device in the dashboard to revoke it on the server.");
    Ok(())
}

/// Appends to the app's log, starting over once it passes 5 MB.
fn open_log(path: &std::path::Path) -> Result<std::fs::File, String> {
    if let Some(d) = path.parent() {
        config::create_private_dir(d)?;
    }
    if std::fs::metadata(path).map(|m| m.len() > 5 << 20).unwrap_or(false) {
        let mut old = path.as_os_str().to_owned();
        old.push(".old");
        let _ = std::fs::rename(path, old);
    }
    let mut o = std::fs::OpenOptions::new();
    o.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path).map_err(|e| e.to_string())
}

/// `pocketwire app`: the Bridge in the background, with a tray icon and a control page.
fn cmd_app(args: &[String], quiet: bool) -> Result<(), String> {
    let f = parse_flags(args, &[], &["background"])?;
    let background = f.on("background");
    let path = config::default_path()?;
    let log_file = config::sibling(&path, "bridge.log");
    let log_path = match open_log(&log_file) {
        Ok(file) => {
            log::to_file(file, quiet);
            log_file.to_string_lossy().to_string()
        }
        Err(_) => String::new(),
    };
    let server = env_or("POCKETWIRE_SERVER", DEFAULT_SERVER);
    let quit = CancellationToken::new();
    let app = desktop::App::new(path, log_path, server, quit.clone())?;
    let rt = runtime();
    let Some(ln) = rt.block_on(app.listen())? else { return Ok(()) };
    logf!("Pocketwire Bridge {} app started; control page on 127.0.0.1:{}", net::version(), desktop::PANEL_PORT);
    let work = {
        let app = app.clone();
        async move {
            tokio::spawn(on_signal(app.quit.clone()));
            app.serve(ln, !background).await;
        }
    };
    run_ui(app, rt, work);
    Ok(())
}

/// The tray needs the main thread on Windows and macOS, so the Bridge runs on another one.
#[cfg(all(feature = "tray", any(windows, target_os = "macos")))]
fn run_ui(app: std::sync::Arc<desktop::App>, rt: tokio::runtime::Runtime, work: impl std::future::Future<Output = ()> + Send + 'static) {
    let handle = rt.handle().clone();
    let bg = std::thread::spawn(move || rt.block_on(work));
    desktop::tray::run(app.clone(), &handle);
    app.quit.cancel();
    let _ = bg.join();
}

#[cfg(all(feature = "tray", unix, not(target_os = "macos")))]
fn run_ui(app: std::sync::Arc<desktop::App>, rt: tokio::runtime::Runtime, work: impl std::future::Future<Output = ()> + Send + 'static) {
    rt.block_on(async move {
        let served = tokio::spawn(work);
        desktop::tray::run(app.clone()).await;
        app.quit.cancel();
        let _ = served.await;
    });
}

#[cfg(not(feature = "tray"))]
fn run_ui(_app: std::sync::Arc<desktop::App>, rt: tokio::runtime::Runtime, work: impl std::future::Future<Output = ()> + Send + 'static) {
    rt.block_on(work);
}
