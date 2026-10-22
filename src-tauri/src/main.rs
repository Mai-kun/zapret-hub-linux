#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // WebKitGTK's DMA-BUF renderer kills the window on CachyOS (Mesa/Nvidia, Wayland): without
    // this the app dies a second in with "Error 71 dispatching to Wayland".
    // The DMABUF-less path is the one that always paints. COMPOSITING_MODE stays untouched:
    // disabling it would push every scroll through slow CPU rendering.
    if cfg!(target_os = "linux") {
        // SAFETY: the very first step of `main`, before any thread or GTK starts.
        unsafe {
            std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
        }
    }
    if let Err(err) = zapret_hub_lib::run() {
        zapret_hub_lib::report(&err);
    }
}
