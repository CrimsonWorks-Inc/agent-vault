// No console window on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! agent-vault companion: a menu bar icon that shows what the vault has open,
//! says when something is waiting, and puts the actions that only *narrow*
//! access one click away. Anything that widens access opens the vault's own
//! web UI, where the human proves presence. See docs/desktop-companion.md.

mod cli;
mod model;

use std::collections::HashSet;
use std::io::BufReader;
use std::process::Child;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use chrono::Utc;
use serde_json::Value;
use tauri::image::Image;
use tauri::menu::{IsMenuItem, Menu, MenuItem, PredefinedMenuItem, Submenu};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Manager, Wry};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
use tauri_plugin_notification::NotificationExt;

use model::{Action, Item, Reach, Snapshot};

const TRAY_ID: &str = "agent-vault";
const TRAY_ICON: &[u8] = include_bytes!("../icons/tray-template.png");
const REFRESH_EVERY: Duration = Duration::from_secs(15);

struct Companion {
    cli: Result<cli::Cli, String>,
    refresh: Mutex<mpsc::Sender<()>>,
    snapshot: Mutex<Snapshot>,
    seen: Mutex<Option<HashSet<String>>>,
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
        .setup(move |app| {
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            let state = Arc::new(Companion {
                cli: cli::Cli::locate(),
                refresh: Mutex::new(tx),
                snapshot: Mutex::new(Snapshot::loading()),
                seen: Mutex::new(None),
                ui: Mutex::new(None),
                watch: Mutex::new(None),
                stopping: AtomicBool::new(false),
            });
            app.manage(state.clone());

            let handle = app.handle().clone();
            let first = render(&handle, &model::menu(&Snapshot::loading(), Utc::now()))?;
            TrayIconBuilder::with_id(TRAY_ID)
                .icon(Image::from_bytes(TRAY_ICON)?)
                .icon_as_template(true)
                .tooltip("agent-vault")
                .menu(&first)
                .on_menu_event(|app, event| on_menu(app, event.id().as_ref()))
                .build(app)?;

            #[cfg(unix)]
            spawn_signal_handler(handle.clone(), state.clone());
            spawn_refresher(handle.clone(), state.clone(), rx);
            if state.cli.is_ok() {
                spawn_watcher(handle, state.clone());
            }
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

// ---- keeping the menu current --------------------------------------------

fn gather(cli: &Result<cli::Cli, String>) -> Snapshot {
    let cli = match cli {
        Ok(cli) => cli,
        Err(why) => return Snapshot::only(Reach::Missing(why.clone())),
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
    snap
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
        let snap = gather(&state.cli);
        announce_new(&app, &state, &snap);
        if let Ok(mut s) = state.snapshot.lock() {
            *s = snap.clone();
        }
        let app2 = app.clone();
        let _ = app.run_on_main_thread(move || show(&app2, &snap));
    });
}

/// A notification when something new is waiting. It says only that, never
/// what the agent wrote: the same rule as the daemon's minimal webhook.
fn announce_new(app: &AppHandle, state: &Companion, snap: &Snapshot) {
    let Reach::Up(_) = snap.reach else { return };
    let now: HashSet<String> = snap.pending.iter().map(|p| p.id.clone()).collect();
    let Ok(mut seen) = state.seen.lock() else { return };
    let fresh = match seen.as_ref() {
        Some(before) => now.difference(before).count(),
        None => now.len(), // first look: mention anything already waiting
    };
    *seen = Some(now);
    if fresh > 0 {
        let body = if fresh == 1 {
            "Something is waiting for your approval.".to_string()
        } else {
            format!("{fresh} things are waiting for your approval.")
        };
        notify(app, &body);
    }
}

fn show(app: &AppHandle, snap: &Snapshot) {
    let Some(tray) = app.tray_by_id(TRAY_ID) else { return };
    if let Ok(menu) = render(app, &model::menu(snap, Utc::now())) {
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
fn spawn_watcher(app: AppHandle, state: Arc<Companion>) {
    thread::spawn(move || {
        let _ = &app;
        while !state.stopping.load(Ordering::SeqCst) {
            let Ok(cli) = &state.cli else { return };
            if let Ok(mut child) = cli.watch() {
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
                        if v.get("data").and_then(|d| d.get("event")).and_then(Value::as_str)
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
            // Locked or down: try again shortly.
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
    let Some(action) = Action::parse(id) else { return };
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
        let result = act(&app, &state, &action);
        if let Err(why) = result {
            notify(&app, &why);
        }
        state.poke();
    });
}

fn act(app: &AppHandle, state: &Companion, action: &Action) -> Result<(), String> {
    if let Some(fragment) = action.ui_fragment() {
        return open_ui(state, &fragment);
    }
    let cli = state.cli.as_ref().map_err(Clone::clone)?;
    match action {
        Action::Revoke(sid) => {
            let label = state
                .snapshot
                .lock()
                .ok()
                .and_then(|s| s.session(sid).map(|s| s.label.clone()))
                .unwrap_or_else(|| sid.clone());
            if confirm(
                app,
                "Revoke this session?",
                &format!("“{label}” ends now. Any agent using it loses access straight away."),
                "Revoke",
            ) {
                cli.run(&["session", "revoke", sid])?;
                notify(app, &format!("Revoked “{label}”."));
            }
            Ok(())
        }
        Action::Lock => {
            cli.run(&["lock"])?;
            notify(app, "The vault is locked. Unlock it in the vault when you need it again.");
            Ok(())
        }
        Action::Panic => {
            if confirm(
                app,
                "Revoke everything?",
                "Every session ends and every waiting request is denied. Agents lose all access until you open a new session.",
                "Revoke everything",
            ) {
                cli.run(&["panic", "--reason", "panic from the menu bar companion"])?;
                notify(app, "Every session is revoked and everything waiting was denied.");
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Open the vault's web UI on one page. Each link works once, so a fresh UI
/// process is started each time and the previous one is stopped.
fn open_ui(state: &Companion, fragment: &str) -> Result<(), String> {
    let cli = state.cli.as_ref().map_err(Clone::clone)?;
    // Hold the lock only to swap processes, never while waiting on the UI or
    // the browser, so Quit is never stuck behind a slow start.
    let old = state.ui.lock().ok().and_then(|mut slot| slot.take());
    if let Some(mut old) = old {
        let _ = old.kill();
        let _ = old.wait();
    }
    let (mut child, url) = cli.ui().map_err(|why| {
        if why.contains("in use") {
            "The vault UI is already open from a terminal. Use that browser tab, or stop it and try again.".to_string()
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

fn confirm(app: &AppHandle, title: &str, body: &str, ok: &str) -> bool {
    app.dialog()
        .message(body)
        .title(title)
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancelCustom(ok.into(), "Cancel".into()))
        .blocking_show()
}

fn notify(app: &AppHandle, body: &str) {
    let _ = app
        .notification()
        .builder()
        .title("agent-vault")
        .body(body)
        .show();
}
