//! The one-time moves an older version's layout needs: engines an old download put right in the
//! data home go into `~/.local/share/zapret-hub/`, and the settings and the services follow them.
//! Everything here is a no-op once the hub layout is in place.

use std::path::{Path, PathBuf};

use tauri::AppHandle;

use crate::actions::{self, state};
use crate::dto::NoticeLevel;
use crate::texts;

/// Called once from `startup`, before anything raises a service: an ExecStart still pointing at
/// the old paths would fail a service that is otherwise fine.
pub fn run(app: &AppHandle) {
    zapret2_folders(app);
    crate::tgws::migrate_unit(&state(app).settings());
}

/// Where a data-home folder belongs now: the same name inside the hub.
fn hub_slot(old: &Path) -> Option<PathBuf> {
    let name = old.file_name()?.to_str()?;
    name.starts_with("zapret2")
        .then(|| zapret::release::default_parent().join(name))
}

/// Every `zapret2*` release folder still in the data home root moves into the hub.
fn move_legacy_folders() {
    let legacy = zapret::release::legacy_parent();
    let Ok(entries) = std::fs::read_dir(&legacy) else {
        return;
    };
    for entry in entries.flatten() {
        if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            continue;
        }
        let old = entry.path();
        let Some(new) = hub_slot(&old) else {
            continue;
        };
        if old == new || new.exists() {
            continue;
        }
        match std::fs::rename(&old, &new) {
            Ok(()) => log::info!("{} moved into the hub: {}", old.display(), new.display()),
            Err(err) => log::warn!("{} did not move into the hub: {err}", old.display()),
        }
    }
}

/// The folder into the hub, `zapret2_dir` after it and, for the strategy in force, the service:
/// its `ExecStart` has the old binary's path baked in, so the strategy applies again.
fn zapret2_folders(app: &AppHandle) {
    move_legacy_folders();
    let app_state = state(app);
    let old = app_state
        .settings()
        .zapret2_dir
        .map(PathBuf::from)
        .and_then(|old| hub_slot(&old).map(|new| (old, new)));
    let Some((old, new)) = old else {
        return;
    };
    // The setting follows the folder: either it just moved, or a previous start moved it and
    // stopped before the setting was saved.
    if old.is_dir() || !new.is_dir() {
        return;
    }
    {
        let _saving = app_state.saving();
        let mut settings = app_state.settings();
        settings.zapret2_dir = Some(new.display().to_string());
        if let Err(err) = crate::settings::save(&app_state.paths.settings(), &settings) {
            log::warn!("zapret2_dir не обновлён на путь в zapret-hub: {err:#}");
            return;
        }
        app_state.set_settings(settings);
    }
    app_state.migrate_strategies();
    actions::changed(app);
    log::info!("zapret2_dir переключён на путь в zapret-hub: {}", new.display());
    // The engine is where the service's ExecStart still looks: apply again so the unit, the
    // nftables queue and the running nfqws2 all come from the new folder.
    if let Some(name) = zapret::service::strategy()
        && zapret2::strip_prefix(&name).is_some()
        && let Err(err) = actions::apply(app, &name)
    {
        actions::notice(
            app,
            NoticeLevel::Error,
            texts::MIGRATE_APPLY_FAILED,
            format!("{err:#}"),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_release_folder_moves_by_its_own_name_into_the_hub() {
        let old = Path::new("/home/me/.local/share/zapret2-v1.0.5.2");
        assert_eq!(
            hub_slot(old),
            Some(PathBuf::from(
                "/home/me/.local/share/zapret-hub/zapret2-v1.0.5.2"
            ))
        );
        assert_eq!(hub_slot(Path::new("/home/me/.local/share/tg-ws-proxy")), None);
        assert_eq!(hub_slot(Path::new("/home/me/.local/share/zapret-hub")), None);
        assert_eq!(hub_slot(Path::new("relative")), None);
    }
}
