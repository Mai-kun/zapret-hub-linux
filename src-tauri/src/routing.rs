//! The router in the app (router spec 3, 7): its setup from the settings, and the pause for what
//! changes the engines underneath it.

use std::sync::Mutex;

use router::{RouterStatus, Setup, parse_proxy};
use tauri::AppHandle;

use crate::actions::{self, state};
use crate::settings::Settings;
use crate::state::{AppState, lock};

/// The proxy from the settings; the engine underneath needs no part of the setup: the nftables
/// table and the acceptor are entirely the hub's own.
pub fn setup(state: &AppState) -> anyhow::Result<Setup> {
    let settings = state.settings();
    let proxy = parse_proxy(settings.socks5.as_deref())?;
    Ok(Setup { proxy })
}

/// The router as `router_enabled` says, with the proxy in force now. A failed start is already
/// in the router's status.
pub fn sync(app: &AppHandle) {
    let state = state(app);
    if !state.settings().router_enabled {
        state.router.stop();
        return;
    }
    match setup(&state) {
        Ok(setup) => {
            let _ = state.router.start(setup);
        }
        Err(err) => state.router.fail(format!("{err:#}")),
    }
}

/// The only writer of `router_enabled`. Turning on starts the router first: when that fails the
/// setting stays off (spec 6) and so does the router.
pub fn set_enabled(app: &AppHandle, enabled: bool) -> anyhow::Result<RouterStatus> {
    let state = state(app);
    let saved = {
        let _saving = state.saving();
        let switched = if enabled {
            setup(&state).and_then(|setup| state.router.start(setup))
        } else {
            state.router.stop();
            Ok(())
        };
        let settings = Settings {
            router_enabled: enabled,
            ..state.settings()
        };
        let saved =
            switched.and_then(|()| crate::settings::save(&state.paths.settings(), &settings));
        if saved.is_err() && enabled {
            state.router.stop();
        }
        // In memory the setting follows the router even when the file write failed: a stopped
        // router left `true` there would come back on the next `sync`.
        state.set_settings(Settings {
            router_enabled: enabled && saved.is_ok(),
            ..settings
        });
        saved
    };
    actions::changed(app);
    saved.map(|()| state.router.status())
}

/// Pauses going at once: what may change the engines and routing may overlap, and routing comes
/// back only when the last one ends.
static PAUSES: Mutex<usize> = Mutex::new(0);

/// `f` with routing paused (spec 7): its sockets are closed, so the engines can change under it.
/// On every way out of `f`, a panic included, the router resumes with the settings in force then
/// and, once the last pause ends, unpauses.
pub fn paused<T>(app: &AppHandle, f: impl FnOnce() -> T) -> T {
    struct Resume<'a>(&'a AppHandle);
    impl Drop for Resume<'_> {
        fn drop(&mut self) {
            let mut pauses = lock(&PAUSES);
            *pauses -= 1;
            sync(self.0);
            if *pauses == 0 {
                state(self.0).router.resume();
            }
        }
    }
    {
        let mut pauses = lock(&PAUSES);
        *pauses += 1;
        state(app).router.pause();
    }
    let _resume = Resume(app);
    f()
}
