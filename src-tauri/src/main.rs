#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // WebKitGTK's DMA-BUF renderer and compositor kill the window on CachyOS (Mesa/Nvidia,
    // Wayland): without these the app dies a second in with "Error 71 dispatching to Wayland".
    // The software path is the one that always paints.
    if cfg!(target_os = "linux") {
        // SAFETY: the very first step of `main`, before any thread or GTK starts.
        unsafe {
            std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
            std::env::set_var("WEBKIT_DISABLE_COMPOSITING_MODE", "1");
        }
    }
    if let Err(err) = zapret_hub_lib::run() {
        zapret_hub_lib::report(&err);
    }
}
