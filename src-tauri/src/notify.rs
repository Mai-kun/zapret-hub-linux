//! Desktop notifications through `notify-send` (spec 9.3).

use tauri::AppHandle;

/// Nothing to register: the desktop environment picks the app name up on its own.
pub fn register() {}

pub fn show(app: &AppHandle, title: &str, body: &str) {
    log::info!("notification: {title}: {body}");
    let title = title.to_owned();
    let body = body.to_owned();
    let sent = app.run_on_main_thread(move || {
        let mut cmd = std::process::Command::new("notify-send");
        cmd.arg("-a").arg(crate::texts::APP).arg(title).arg(body);
        let _ = cmd.spawn();
    });
    if let Err(err) = sent {
        log::warn!("cannot show a notification: {err}");
    }
}
