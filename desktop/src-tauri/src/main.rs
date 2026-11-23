// No console window on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! agent-vault companion: a menu bar icon that shows what the vault has open,
//! says when something needs the user, and puts the everyday actions one click
//! away. It never grants access itself: anything that widens what an agent may
//! do opens the vault's own web UI, where the human proves presence.
//! See docs/desktop-companion.md.

mod cli;
mod model;
mod notices;

use std::io::BufReader;
use std::path::PathBuf;
use std::process::Child;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use chrono::Utc;
use serde_json::{json, Value};
use tauri::image::Image;
use tauri::menu::{CheckMenuItem, IsMenuItem, Menu, MenuItem, PredefinedMenuItem, Submenu};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Manager, Wry};
use tauri_plugin_autostart::ManagerExt as _;
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
use tauri_plugin_notification::NotificationExt;

use model::{Action, AgentLink, Item, Missing, Prefs, Reach, Snapshot};
use notices::Memo;

const TRAY_ID: &str = "agent-vault";
const TRAY_ICON: &[u8] = include_bytes!("../icons/tray-template.png");
const REFRESH_EVERY: Duration = Duration::from_secs(15);

struct Companion {
    refresh: Mutex<mpsc::Sender<()>>,
    snapshot: Mutex<Snapshot>,
    prefs: Mutex<Prefs>,
    prefs_path: Option<PathBuf>,
    memo: Mutex<Memo>,
    ui: Mutex<Option<Child>>,
    watch: Mutex<Option<Child>>,
    stopping: AtomicBool,
}

impl Companion {
    fn poke(&self) {
        if let Ok(tx) = self.refresh.lock() {
            let _ = tx.send(());
        }
    }

    fn prefs(&self) -> Prefs {
        self.prefs.lock().map(|p| *p).unwrap_or_default()
    }

    fn snapshot(&self) -> Snapshot {
        self.snapshot
            .lock()
            .map(|s| s.clone())
            .unwrap_or_else(|_| Snapshot::loading())
    }

    fn shutdown(&self) {
        self.stopping.store(true, Ordering::SeqCst);
        for slot in [&self.ui, &self.watch] {
            if let Some(mut child) = slot.lock().ok().and_then(|mut c| c.take()) {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}

fn main() {
    let (tx, rx) = mpsc::channel::<()>();
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .setup(move |app| {
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            let prefs_path = app
                .path()
                .app_config_dir()
                .ok()
                .map(|d| d.join("settings.json"));
            let mut prefs = load_prefs(prefs_path.as_deref());
            prefs.autostart = app.autolaunch().is_enabled().unwrap_or(false);

            let state = Arc::new(Companion {
                refresh: Mutex::new(tx),
                snapshot: Mutex::new(Snapshot::loading()),
                prefs: Mutex::new(prefs),
                prefs_path,
                memo: Mutex::new(Memo::default()),
                ui: Mutex::new(None),
                watch: Mutex::new(None),
                stopping: AtomicBool::new(false),
            });
            app.manage(state.clone());

            let handle = app.handle().clone();
            let first = render(
                &handle,
                &model::menu(&Snapshot::loading(), prefs, Utc::now()),
            )?;
            TrayIconBuilder::with_id(TRAY_ID)
                .icon(Image::from_bytes(TRAY_ICON)?)
                .icon_as_template(true)
                .tooltip("agent-vault")
                .menu(&first)
                .on_menu_event(|app, event| on_menu(app, event.id().as_ref()))
                .build(app)?;

            #[cfg(unix)]
            spawn_signal_handler(handle.clone(), state.clone());
            spawn_refresher(handle, state.clone(), rx);
            spawn_watcher(state.clone());
            state.poke();
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("the companion could not start");

    app.run(|app, event| match event {
        // No windows to close, so only an explicit Quit ends the app.
        tauri::RunEvent::ExitRequested { api, code, .. } if code.is_none() => api.prevent_exit(),
        tauri::RunEvent::Exit => {
            if let Some(state) = app.try_state::<Arc<Companion>>() {
                state.shutdown();
            }
        }
        _ => {}
    });
}

/// A terminate signal (logout, `kill`) would otherwise leave the companion's
/// `watch` and `ui` processes running on their own.
#[cfg(unix)]
fn spawn_signal_handler(app: AppHandle, state: Arc<Companion>) {
    use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
    let Ok(mut signals) = signal_hook::iterator::Signals::new([SIGTERM, SIGINT, SIGHUP]) else {
        return;
    };
    thread::spawn(move || {
        if signals.forever().next().is_some() {
            state.shutdown();
            app.exit(0);
        }
    });
}

// ---- settings --------------------------------------------------------------

fn load_prefs(path: Option<&std::path::Path>) -> Prefs {
    let mut prefs = Prefs::default();
    let read = path
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| serde_json::from_str::<Value>(&s).ok());
    if let Some(v) = read {
        if let Some(on) = v.get("notifications").and_then(Value::as_bool) {
            prefs.notifications = on;
        }
        if let Some(done) = v.get("welcomed").and_then(Value::as_bool) {
            prefs.welcomed = done;
        }
    }
    prefs
}

fn save_prefs(state: &Companion) {
    let Some(path) = &state.prefs_path else {
        return;
    };
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let prefs = state.prefs();
    let body = json!({ "notifications": prefs.notifications, "welcomed": prefs.welcomed });
    let _ = std::fs::write(path, format!("{body:#}\n"));
}

// ---- keeping the menu current --------------------------------------------

fn gather() -> Snapshot {
    let cli = match cli::Cli::locate() {
        Ok(cli) => cli,
        Err(why) => return Snapshot::only(Reach::Missing(why)),
    };
    let status = match cli.run(&["status"]) {
        Ok(v) => match model::parse_status(&v) {
            Some(s) => s,
            None => return Snapshot::only(Reach::Down("unexpected status reply".into())),
        },
        Err(why) => return Snapshot::only(Reach::Down(why)),
    };
    let now = Utc::now();
    let mut snap = Snapshot::only(Reach::Up(status));
    match cli.run(&["session", "list"]) {
        Ok(v) => snap.sessions = model::parse_sessions(&v, now),
        Err(_) => snap.unread.sessions = true,
    }
    match cli.run(&["approvals"]) {
        Ok(v) => snap.pending = model::parse_pending(&v),
        Err(_) => snap.unread.pending = true,
    }
    match cli.run(&["template", "list"]) {
        Ok(v) => snap.templates = model::parse_templates(&v),
        Err(_) => snap.unread.templates = true,
    }
    match cli.run(&["cred", "list"]) {
        Ok(v) => snap.keys = model::parse_keys(&v),
        Err(_) => snap.unread.keys = true,
    }
    if let Ok(v) = cli.run(&["doctor"]) {
        snap.setup = model::parse_setup(&v);
    }
    snap.agents = agents(&cli);
    snap
}

/// Agents found on this computer, and whether the vault is already written
/// into each one's config. `mcp install --print` reports that without writing.
fn agents(cli: &cli::Cli) -> Vec<AgentLink> {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return Vec::new();
    };
    let marker = |id: &str| match id {
        "claude-code" => ".claude",
        "codex" => ".codex",
        "cursor" => ".cursor",
        _ => ".gemini",
    };
    model::AGENTS
        .iter()
        .filter(|(id, _)| home.join(marker(id)).is_dir())
        .filter_map(|(id, name)| {
            let v = cli
                .run(&[
                    "mcp", "install", "--agent", id, "--scope", "user", "--print",
                ])
                .ok()?;
            Some(AgentLink {
                id: (*id).into(),
                name: (*name).into(),
                connected: model::parse_connected(&v)?,
            })
        })
        .collect()
}

fn spawn_refresher(app: AppHandle, state: Arc<Companion>, rx: mpsc::Receiver<()>) {
    thread::spawn(move || loop {
        match rx.recv_timeout(REFRESH_EVERY) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        }
        while rx.try_recv().is_ok() {} // several pokes in a row: one refresh
        if state.stopping.load(Ordering::SeqCst) {
            return;
        }
        let snap = gather();
        let before = state.snapshot();
        let said = match state.memo.lock() {
            Ok(mut memo) => notices::notices(&before, &snap, Utc::now(), &mut memo),
            Err(_) => Vec::new(),
        };
        for notice in said {
            tell(&app, &state, &notice.text());
        }
        if let Ok(mut s) = state.snapshot.lock() {
            *s = snap.clone();
        }
        welcome_once(&app, &state, &snap);
        let prefs = state.prefs();
        let app2 = app.clone();
        let _ = app.run_on_main_thread(move || show(&app2, &snap, prefs));
    });
}

/// The first time the companion ever runs, say where it lives and what it
/// found, and offer the one next step (setting the vault up, if it is missing).
fn welcome_once(app: &AppHandle, state: &Arc<Companion>, snap: &Snapshot) {
    if state.prefs().welcomed {
        return;
    }
    let Some(welcome) = model::welcome(snap) else {
        return;
    };
    if let Ok(mut prefs) = state.prefs.lock() {
        prefs.welcomed = true;
    }
    save_prefs(state);
    let (app, state) = (app.clone(), state.clone());
    thread::spawn(move || {
        let dialog = app
            .dialog()
            .message(&welcome.body)
            .title(&welcome.title)
            .kind(MessageDialogKind::Info);
        match welcome.next {
            Some((label, action)) => {
                let go = dialog
                    .buttons(MessageDialogButtons::OkCancelCustom(label, "Later".into()))
                    .blocking_show();
                if go {
                    if let Err(why) = act(&app, &state, &action) {
                        alert(&app, MessageDialogKind::Error, "That did not work", &why);
                    }
                    state.poke();
                }
            }
            None => {
                dialog.blocking_show();
            }
        }
    });
}

fn show(app: &AppHandle, snap: &Snapshot, prefs: Prefs) {
    let Some(tray) = app.tray_by_id(TRAY_ID) else {
        return;
    };
    if let Ok(menu) = render(app, &model::menu(snap, prefs, Utc::now())) {
        let _ = tray.set_menu(Some(menu));
    }
    let _ = tray.set_title(model::tray_title(snap));
    let _ = tray.set_tooltip(Some(model::tooltip(snap)));
}

fn render(app: &AppHandle, items: &[Item]) -> tauri::Result<Menu<Wry>> {
    let menu = Menu::new(app)?;
    for item in items {
        menu.append(build(app, item)?.as_ref())?;
    }
    Ok(menu)
}

fn build(app: &AppHandle, item: &Item) -> tauri::Result<Box<dyn IsMenuItem<Wry>>> {
    Ok(match item {
        Item::Text(text) => Box::new(MenuItem::new(app, text, false, None::<&str>)?),
        Item::Action { action, text } => Box::new(MenuItem::with_id(
            app,
            action.id(),
            text,
            true,
            None::<&str>,
        )?),
        Item::Check { action, text, on } => Box::new(CheckMenuItem::with_id(
            app,
            action.id(),
            text,
            true,
            *on,
            None::<&str>,
        )?),
        Item::Separator => Box::new(PredefinedMenuItem::separator(app)?),
        Item::Submenu { text, items } => {
            let sub = Submenu::new(app, text, true)?;
            for child in items {
                sub.append(build(app, child)?.as_ref())?;
            }
            Box::new(sub)
        }
    })
}

/// Wakes the refresher the moment the daemon reports a new request, so the
/// badge does not wait for the next 15-second tick.
fn spawn_watcher(state: Arc<Companion>) {
    thread::spawn(move || {
        while !state.stopping.load(Ordering::SeqCst) {
            // Looked up each time: the vault may be installed while we run.
            if let Some(mut child) = cli::Cli::locate().ok().and_then(|cli| cli.watch().ok()) {
                let stdout = child.stdout.take();
                if let Ok(mut slot) = state.watch.lock() {
                    *slot = Some(child);
                }
                // Quit may have run while the process was starting.
                if state.stopping.load(Ordering::SeqCst) {
                    state.shutdown();
                    return;
                }
                if let Some(stdout) = stdout {
                    let mut reader = BufReader::new(stdout);
                    let mut json = cli::JsonLines::default();
                    while let Ok(Some(line)) = cli::read_line_capped(&mut reader, cli::LINE_CAP) {
                        let Some(v) = json.push(&line) else { continue };
                        if v.get("data")
                            .and_then(|d| d.get("event"))
                            .and_then(Value::as_str)
                            == Some("pending")
                        {
                            state.poke();
                        }
                    }
                }
                if let Some(mut child) = state.watch.lock().ok().and_then(|mut c| c.take()) {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
            // Not installed, locked or down: try again shortly.
            for _ in 0..10 {
                if state.stopping.load(Ordering::SeqCst) {
                    return;
                }
                thread::sleep(Duration::from_secs(1));
            }
        }
    });
}

// ---- menu clicks ----------------------------------------------------------

fn on_menu(app: &AppHandle, id: &str) {
    let Some(action) = Action::parse(id) else {
        return;
    };
    let state = app.state::<Arc<Companion>>().inner().clone();
    if action == Action::Quit {
        state.shutdown();
        app.exit(0);
        return;
    }
    if action == Action::Refresh {
        state.poke();
        return;
    }
    // Everything else may block (a CLI call, a dialog): never on the UI thread.
    let app = app.clone();
    thread::spawn(move || {
        if let Err(why) = act(&app, &state, &action) {
            alert(&app, MessageDialogKind::Error, "That did not work", &why);
        }
        state.poke();
    });
}

fn act(app: &AppHandle, state: &Companion, action: &Action) -> Result<(), String> {
    match action {
        Action::ToggleNotifications => {
            let on = {
                let mut prefs = state.prefs.lock().map_err(|_| "busy".to_string())?;
                prefs.notifications = !prefs.notifications;
                prefs.notifications
            };
            save_prefs(state);
            if on {
                tell(
                    app,
                    state,
                    "Notifications are on. This is what they look like.",
                );
            }
            return Ok(());
        }
        Action::ToggleAutostart => {
            let launcher = app.autolaunch();
            let on = !launcher.is_enabled().unwrap_or(false);
            let done = if on {
                launcher.enable()
            } else {
                launcher.disable()
            };
            done.map_err(|e| format!("Could not change the login setting: {e}"))?;
            if let Ok(mut prefs) = state.prefs.lock() {
                prefs.autostart = on;
            }
            return Ok(());
        }
        _ => {}
    }
    if let Some(script) = action.terminal_script() {
        return cli::run_in_terminal(&script);
    }
    if let Some(fragment) = action.ui_fragment() {
        return open_ui(state, &fragment);
    }
    let Some(args) = action.cli_args() else {
        return Ok(());
    };
    let snap = state.snapshot();
    if let Some(ask) = action.confirm(&snap) {
        if !confirm(app, &ask) {
            return Ok(());
        }
    }
    let cli =
        cli::Cli::locate().map_err(|_| "agent-vault is not available right now.".to_string())?;
    let ending: Vec<String> = match action {
        Action::Revoke(sid) => vec![sid.clone()],
        Action::Panic => snap.sessions.iter().map(|s| s.id.clone()).collect(),
        _ => Vec::new(),
    };
    if let Ok(mut memo) = state.memo.lock() {
        memo.ended_by_user(ending.iter().cloned());
    }
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let limit = if *action == Action::TestKeys {
        cli::SLOW
    } else {
        Duration::from_secs(20)
    };
    let reply = match cli.run_within(&argv, limit) {
        Ok(reply) => reply,
        Err(why) => {
            if let Ok(mut memo) = state.memo.lock() {
                memo.not_ended(&ending);
            }
            return Err(why);
        }
    };
    if *action == Action::TestKeys {
        // From this run's own results, never from the stored health, which
        // can be older than the check the user just asked for.
        let report = match model::parse_key_test(&reply) {
            Some(results) => model::key_report(&results),
            None => "The check ran, but its results could not be read. Open the vault to see them."
                .into(),
        };
        alert(app, MessageDialogKind::Info, "Key check", &report);
    } else if let Some(text) = action.done(&snap) {
        tell(app, state, &text);
    }
    Ok(())
}

/// Open the vault's web UI on one page. Each link works once, so a fresh UI
/// process is started each time and the previous one is stopped.
fn open_ui(state: &Companion, fragment: &str) -> Result<(), String> {
    let cli = cli::Cli::locate().map_err(|why| match why {
        Missing::NotInstalled => "agent-vault is not set up on this computer yet.".to_string(),
        Missing::Unsupported => {
            "agent-vault does not run on this operating system yet.".to_string()
        }
        Missing::Untrusted(why) => why,
    })?;
    // Hold the lock only to swap processes, never while waiting on the UI or
    // the browser, so Quit is never stuck behind a slow start.
    let old = state.ui.lock().ok().and_then(|mut slot| slot.take());
    if let Some(mut old) = old {
        let _ = old.kill();
        let _ = old.wait();
    }
    let (mut child, url) = cli.ui().map_err(|why| {
        if why.contains("in use") {
            "The vault is already open from a terminal. Use that browser tab, or close it and try again.".to_string()
        } else {
            why
        }
    })?;
    {
        let mut slot = state.ui.lock().map_err(|_| "busy".to_string())?;
        if state.stopping.load(Ordering::SeqCst) {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(());
        }
        if let Some(mut other) = slot.replace(child) {
            let _ = other.kill();
            let _ = other.wait();
        }
    }
    cli::open_in_browser(&format!("{url}{fragment}"))
}

fn confirm(app: &AppHandle, ask: &model::Confirm) -> bool {
    app.dialog()
        .message(&ask.body)
        .title(&ask.title)
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancelCustom(
            ask.ok.clone(),
            "Cancel".into(),
        ))
        .blocking_show()
}

/// A dialog, for results and errors the user must not miss whatever their
/// notification settings are.
fn alert(app: &AppHandle, kind: MessageDialogKind, title: &str, body: &str) {
    app.dialog()
        .message(body)
        .title(title)
        .kind(kind)
        .blocking_show();
}

/// A notification, when the user has them on.
fn tell(app: &AppHandle, state: &Companion, body: &str) {
    if !state.prefs().notifications {
        return;
    }
    let _ = app
        .notification()
        .builder()
        .title("agent-vault")
        .body(body)
        .show();
}
