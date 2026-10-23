//! The main window: made when needed, hidden by its close button (only «Выход» in the tray menu
//! ends the app, spec 4.2).

use tauri::{AppHandle, Manager as _, WebviewUrl, WebviewWindowBuilder};

pub const MAIN: &str = "main";

/// Brings the window up, making it first if it is gone. A new one starts hidden: the page shows
/// it once it has drawn, so it never flashes white.
pub fn show(app: &AppHandle) {
    if let Some(window) = app.get_webview_window(MAIN) {
        let shown = window
            .unminimize()
            .and_then(|()| window.show())
            .and_then(|()| window.set_focus());
        if let Err(err) = shown {
            log::warn!("cannot show the window: {err}");
        }
        return;
    }
    // Off the main thread on Windows: building a webview from a main-thread handler deadlocks
    // there, and tray clicks and the second-instance callback run there. On Linux GTK is strict
    // about one thread: the window is born on the main thread, and visible — WebKitGTK freezes
    // the page's JavaScript while the window is unmapped (`main.ts` is the one who shows it).
    let handle = app.clone();
    #[cfg(target_os = "windows")]
    std::thread::spawn(move || {
        if let Err(err) = build(&handle) {
            log::error!("cannot create the window: {err:#}");
        }
    });
    #[cfg(not(target_os = "windows"))]
    if let Err(err) = app.run_on_main_thread(move || {
        if let Err(err) = build(&handle) {
            log::error!("cannot create the window: {err:#}");
        }
    }) {
        log::error!("cannot schedule the window: {err}");
    }
}

fn build(app: &AppHandle) -> anyhow::Result<()> {
    let profile = crate::state::Paths::current()?.data().join("webview");
    let builder = WebviewWindowBuilder::new(app, MAIN, WebviewUrl::default())
        .title(crate::texts::APP)
        .inner_size(1100.0, 720.0)
        .min_inner_size(900.0, 560.0)
        .center()
        // Hidden on Windows (`main.ts` shows it once it has drawn); on Linux the window must be
        // mapped from its first frame: WebKitGTK does not run an unmapped window's page, and
        // `main.ts` — the one who would show it — would never run.
        .visible(!cfg!(target_os = "windows"))
        // The inspector is the one way to see the webview's errors (F12, debug builds).
        .devtools(cfg!(debug_assertions))
        .data_directory(profile);
    let window = builder.build()?;
    log::info!(
        "window built: visible={:?} minimized={:?}",
        window.is_visible(),
        window.is_minimized()
    );
    Ok(())
}
