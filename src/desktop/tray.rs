//! The tray icon: the notification area on Windows, the menu bar on macOS and a
//! StatusNotifierItem on Linux desktops.

use std::sync::Arc;

use super::{App, State};

const ICON_ON: &[u8] = include_bytes!("../../assets/icon.rgba");
const ICON_OFF: &[u8] = include_bytes!("../../assets/icon-off.rgba");
const ICON_SIZE: u32 = 64;

#[derive(Clone, Copy)]
enum Action {
    Open,
    Approvals,
    Autostart,
    Log,
    Quit,
}

fn act(app: &Arc<App>, a: Action) {
    match a {
        Action::Open => app.open(&app.panel_url()),
        Action::Approvals => app.open(&app.snapshot().approval_url),
        Action::Autostart => {
            let on = !app.snapshot().autostart;
            if let Err(e) = app.set_autostart(on) {
                crate::logf!("app: start at sign-in: {e}");
            }
        }
        Action::Log => app.open(&app.log_path),
        Action::Quit => app.quit.cancel(),
    }
}

#[cfg(any(windows, target_os = "macos"))]
mod imp {
    use super::*;
    use tao::event::Event;
    use tao::event_loop::{ControlFlow, EventLoopBuilder};
    use tao::platform::run_return::EventLoopExtRunReturn;
    use tray_icon::menu::{CheckMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem};
    use tray_icon::{Icon, TrayIconBuilder};

    enum Ev {
        Refresh,
        Menu(MenuEvent),
        Quit,
    }

    /// Shows the tray icon and blocks until the user quits or the app stops. Must run on the
    /// main thread; `rt` runs the app's async side meanwhile.
    pub fn run(app: Arc<App>, rt: &tokio::runtime::Handle) {
        let mut el = EventLoopBuilder::<Ev>::with_user_event().build();
        #[cfg(target_os = "macos")]
        {
            use tao::platform::macos::{ActivationPolicy, EventLoopExtMacOS};
            el.set_activation_policy(ActivationPolicy::Accessory);
        }
        let proxy = el.create_proxy();
        {
            let p = proxy.clone();
            MenuEvent::set_event_handler(Some(move |e| {
                let _ = p.send_event(Ev::Menu(e));
            }));
        }
        {
            let (p, app) = (proxy.clone(), app.clone());
            rt.spawn(async move {
                let mut ch = app.changes();
                loop {
                    tokio::select! {
                        r = ch.changed() => if r.is_err() { break },
                        _ = app.quit.cancelled() => break,
                    }
                    let _ = p.send_event(Ev::Refresh);
                }
                let _ = p.send_event(Ev::Quit);
            });
        }
        let icon = |on: bool| Icon::from_rgba((if on { ICON_ON } else { ICON_OFF }).to_vec(), ICON_SIZE, ICON_SIZE).ok();
        let status = MenuItem::new("Starting…", false, None);
        let open = MenuItem::new("Open Pocketwire Bridge", true, None);
        let approvals = MenuItem::new("Open approvals", false, None);
        let auto = CheckMenuItem::new("Start when I sign in", true, false, None);
        let logs = MenuItem::new("Show log", true, None);
        let exit = MenuItem::new("Quit", true, None);
        let menu = Menu::new();
        let sep = || PredefinedMenuItem::separator();
        let _ = menu.append_items(&[&status, &sep(), &open, &approvals, &sep(), &auto]);
        if !app.log_path.is_empty() {
            let _ = menu.append(&logs);
        }
        let _ = menu.append_items(&[&sep(), &exit]);
        let ids = [
            (open.id().clone(), Action::Open),
            (approvals.id().clone(), Action::Approvals),
            (auto.id().clone(), Action::Autostart),
            (logs.id().clone(), Action::Log),
            (exit.id().clone(), Action::Quit),
        ];
        let mut tray = None;
        let refresh = |tray: &Option<tray_icon::TrayIcon>| {
            let s = app.snapshot();
            status.set_text(s.state.label());
            approvals.set_enabled(!s.approval_url.is_empty());
            auto.set_checked(s.autostart);
            if let Some(t) = tray {
                let _ = t.set_icon(icon(s.state == State::Connected));
                let _ = t.set_tooltip(Some(format!("Pocketwire Bridge: {}", s.state.label())));
            }
        };
        el.run_return(|ev, _, flow| {
            *flow = ControlFlow::Wait;
            match ev {
                Event::NewEvents(tao::event::StartCause::Init) => {
                    tray =
                        TrayIconBuilder::new().with_menu(Box::new(menu.clone())).with_tooltip("Pocketwire Bridge").with_icon(icon(false).unwrap()).build().ok();
                    if tray.is_none() {
                        crate::logf!("app: no tray icon");
                    }
                    refresh(&tray);
                }
                Event::UserEvent(Ev::Refresh) => refresh(&tray),
                Event::UserEvent(Ev::Menu(e)) => {
                    if let Some((_, a)) = ids.iter().find(|(id, _)| *id == e.id) {
                        act(&app, *a);
                        refresh(&tray);
                    }
                }
                Event::UserEvent(Ev::Quit) => {
                    tray = None;
                    *flow = ControlFlow::Exit;
                }
                _ => {}
            }
        });
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
mod imp {
    use super::*;
    use ksni::menu::{CheckmarkItem, StandardItem};
    use ksni::{MenuItem, TrayMethods};

    struct Tray(Arc<App>);

    fn argb(rgba: &[u8]) -> Vec<u8> {
        rgba.as_chunks::<4>().0.iter().flat_map(|p| [p[3], p[0], p[1], p[2]]).collect()
    }

    fn item(label: &str, enabled: bool, a: Action) -> MenuItem<Tray> {
        StandardItem { label: label.into(), enabled, activate: Box::new(move |t: &mut Tray| act(&t.0, a)), ..Default::default() }.into()
    }

    impl ksni::Tray for Tray {
        fn id(&self) -> String {
            "pocketwire-bridge".into()
        }
        fn title(&self) -> String {
            "Pocketwire Bridge".into()
        }
        fn icon_pixmap(&self) -> Vec<ksni::Icon> {
            let on = self.0.snapshot().state == State::Connected;
            vec![ksni::Icon { width: ICON_SIZE as i32, height: ICON_SIZE as i32, data: argb(if on { ICON_ON } else { ICON_OFF }) }]
        }
        fn tool_tip(&self) -> ksni::ToolTip {
            ksni::ToolTip { title: format!("Pocketwire Bridge: {}", self.0.snapshot().state.label()), ..Default::default() }
        }
        fn activate(&mut self, _x: i32, _y: i32) {
            act(&self.0, Action::Open);
        }
        fn menu(&self) -> Vec<MenuItem<Self>> {
            let s = self.0.snapshot();
            let mut m = vec![
                StandardItem { label: s.state.label().into(), enabled: false, ..Default::default() }.into(),
                MenuItem::Separator,
                item("Open Pocketwire Bridge", true, Action::Open),
                item("Open approvals", !s.approval_url.is_empty(), Action::Approvals),
                MenuItem::Separator,
                CheckmarkItem {
                    label: "Start when I sign in".into(),
                    checked: s.autostart,
                    activate: Box::new(|t: &mut Tray| act(&t.0, Action::Autostart)),
                    ..Default::default()
                }
                .into(),
            ];
            if !s.log_path.is_empty() {
                m.push(item("Show log", true, Action::Log));
            }
            m.push(MenuItem::Separator);
            m.push(item("Quit", true, Action::Quit));
            m
        }
    }

    /// Shows the tray icon until the app stops. Without a desktop session (a server, or a
    /// terminal over SSH) the control page is enough.
    pub async fn run(app: Arc<App>) {
        if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").filter(|v| !v.is_empty()).is_none() {
            return app.quit.cancelled().await;
        }
        let handle = match Tray(app.clone()).spawn().await {
            Ok(h) => h,
            Err(e) => {
                crate::logf!("app: no tray icon: {e}");
                return app.quit.cancelled().await;
            }
        };
        let mut ch = app.changes();
        loop {
            tokio::select! {
                r = ch.changed() => if r.is_err() { break },
                _ = app.quit.cancelled() => break,
            }
            handle.update(|_| {}).await;
        }
        handle.shutdown().await;
    }
}

pub use imp::run;
