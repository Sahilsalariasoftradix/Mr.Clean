//! Menu bar / tray icon, keep-running-when-closed, and automatic scans.
//! Decisions (what to show, when to scan, what to notify) live in
//! `mrclean_core::background`; this file only wires them to Tauri.

use std::sync::Mutex;
use std::time::Duration;

use mrclean_core::background::{self, Settings};
use mrclean_core::security;
use mrclean_core::system;
use mrclean_core::{Cancel, Env};
use serde::Serialize;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Emitter, Manager, Runtime, State, WebviewWindow};
use tauri_plugin_notification::NotificationExt;

use crate::AppState;

/// The three status lines in the tray menu, kept so the timer can update them.
pub struct Tray<R: Runtime> {
    lines: [MenuItem<R>; 3],
}

/// Whether a tray icon could be created (some Linux desktops have none).
#[derive(Default)]
pub struct TrayAvailable(pub Mutex<bool>);

pub fn main_window<R: Runtime>(app: &AppHandle<R>) -> Option<WebviewWindow<R>> {
    app.get_webview_window("main")
}

pub fn show_main<R: Runtime>(app: &AppHandle<R>) {
    if let Some(w) = main_window(app) {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

/// Build the menu bar / tray icon. Returns false if the platform has no tray.
pub fn create_tray<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<bool> {
    let line = |id: &str| MenuItem::with_id(app, id, "…", false, None::<&str>);
    let lines = [line("status-disk")?, line("status-memory")?, line("status-security")?];
    let item = |id: &str, text: &str| MenuItem::with_id(app, id, text, true, None::<&str>);
    let menu = Menu::with_items(
        app,
        &[
            &lines[0],
            &lines[1],
            &lines[2],
            &PredefinedMenuItem::separator(app)?,
            &item("open", "Open Mr.Clean")?,
            &item("scan", "Scan everything")?,
            &item("clean", "Free up space…")?,
            &item("security", "Check security…")?,
            &PredefinedMenuItem::separator(app)?,
            &item("quit", "Quit Mr.Clean")?,
        ],
    )?;
    let Some(icon) = app.default_window_icon().cloned() else {
        return Ok(false);
    };
    let built = TrayIconBuilder::with_id("main")
        .icon(icon)
        .tooltip("Mr.Clean")
        .menu(&menu)
        .show_menu_on_left_click(true)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open" => show_main(app),
            "scan" | "clean" | "security" => {
                show_main(app);
                // The window runs the action, so it shows progress as usual.
                let _ = app.emit("tray-action", event.id.as_ref());
            }
            "quit" => app.exit(0),
            _ => {}
        })
        .build(app);
    if built.is_err() {
        return Ok(false);
    }
    app.manage(Tray { lines });
    if let Some(t) = app.try_state::<TrayAvailable>() {
        *t.0.lock().unwrap_or_else(|e| e.into_inner()) = true;
    }
    refresh_status(app);
    Ok(true)
}

/// Update the tray's disk / memory / security lines.
pub fn refresh_status<R: Runtime>(app: &AppHandle<R>) {
    let Some(tray) = app.try_state::<Tray<R>>() else { return };
    let state = app.state::<AppState>();
    let (disk, memory) = match state.sys.lock() {
        Ok(mut sys) => {
            sys.refresh_memory();
            let info = system::info(&sys);
            (
                info.disk.map(|d| (d.free_bytes, d.total_bytes)),
                Some((info.memory.used_bytes, info.memory.total_bytes)),
            )
        }
        Err(_) => (None, None),
    };
    let threats = state
        .security
        .lock()
        .ok()
        .and_then(|r| r.as_ref().map(|r| r.counts.high + r.counts.medium));
    for (item, text) in tray.lines.iter().zip(background::status_lines(disk, memory, threats)) {
        let _ = item.set_text(text);
    }
}

/// Keep the tray status fresh, and run automatic scans when they're due.
pub fn start_timer<R: Runtime>(app: AppHandle<R>) {
    std::thread::spawn(move || {
        // Give the app a couple of minutes to settle before any automatic scan.
        let mut ticks: u64 = 0;
        loop {
            std::thread::sleep(Duration::from_secs(60));
            ticks += 1;
            refresh_status(&app);
            if ticks >= 2 && ticks % 10 == 2 {
                run_if_due(&app);
            }
        }
    });
}

fn run_if_due<R: Runtime>(app: &AppHandle<R>) {
    let env = Env::detect();
    let settings = background::load(&env);
    let now = mrclean_core::fsutil::now_secs();
    if !background::is_due(&settings, now) {
        return;
    }
    let report = security::scan(&env, std::slice::from_ref(&env.home), &Cancel::new());
    let state = app.state::<AppState>();
    let disk_pct = state.sys.lock().ok().and_then(|sys| {
        system::info(&sys)
            .disk
            .filter(|d| d.total_bytes > 0)
            .map(|d| (d.total_bytes - d.free_bytes) as f64 * 100.0 / d.total_bytes as f64)
    });
    let (alerts, next) = background::after_scan(&settings, Some(&report), disk_pct, now);
    let _ = background::save(&env, &next);
    if let Ok(mut s) = state.security.lock() {
        *s = Some(report.clone());
    }
    let _ = app.emit("security-updated", &report);
    refresh_status(app);
    for a in alerts {
        let _ = app.notification().builder().title(&a.title).body(&a.body).show();
    }
}

/// Settings for the UI, plus whether a tray icon exists on this system.
#[derive(Serialize)]
pub struct BackgroundInfo {
    #[serde(flatten)]
    settings: Settings,
    tray_available: bool,
}

#[tauri::command]
pub fn background_settings(tray: State<'_, TrayAvailable>) -> BackgroundInfo {
    BackgroundInfo {
        settings: background::load(&Env::detect()),
        tray_available: *tray.0.lock().unwrap_or_else(|e| e.into_inner()),
    }
}

/// Save the user's choices; bookkeeping fields (last scan, known threats) are kept.
#[tauri::command]
pub fn set_background_settings(choice: Settings) -> Result<(), String> {
    let env = Env::detect();
    let current = background::load(&env);
    background::save(
        &env,
        &Settings {
            keep_in_menu_bar: choice.keep_in_menu_bar,
            auto_scan: choice.auto_scan,
            notify_threats: choice.notify_threats,
            notify_disk: choice.notify_disk,
            ..current
        },
    )
}

/// Closing the window hides it instead, when the user wants Mr.Clean in the menu bar.
pub fn keep_running_on_close<R: Runtime>(window: &tauri::Window<R>, api: &tauri::CloseRequestApi) {
    let app = window.app_handle();
    let tray = app
        .try_state::<TrayAvailable>()
        .map(|t| *t.0.lock().unwrap_or_else(|e| e.into_inner()))
        .unwrap_or(false);
    if tray && background::load(&Env::detect()).keep_in_menu_bar {
        api.prevent_close();
        let _ = window.hide();
    }
}
