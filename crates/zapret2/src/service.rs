//! The check that runs winws2 and the `zapret2` service (zapret2 spec 5.3, 6). `zapret::service`
//! does the `sc` work; this module knows what zapret2 needs from it.

use anyhow::Context as _;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use zapret::folder::Folder;
use zapret::service::{self, QuickCheck, SERVICE, SERVICE2, SvcState};

use crate::strategies::{self, Strategy};
use crate::{Engine, PREFIX};

/// `--dry-run` goes last: before an option it does not know, it ends with code 1 and says
/// nothing. The Windows build gets `--wf-dup-check=0` next to a running winws2 with the same
/// filter; the Linux build's filter is an nftables table, and `--dry-run` alone suffices.
pub fn dry_run_args(is_nfqws: bool, tail: &str) -> String {
    if is_nfqws {
        format!("{tail} --dry-run")
    } else {
        format!("{tail} --wf-dup-check=0 --dry-run")
    }
}

/// Lua starts for real behind an empty WinDivert filter: traffic is not touched.
pub fn intercept_args(tail: &str) -> String {
    format!("{tail} --intercept=0")
}

/// The service's `binPath`: `"<winws2.exe>" <tail>`.
pub fn bin_path(engine: &Engine, tail: &str) -> String {
    format!("\"{}\" {tail}", engine.exe().display())
}

/// The whole check (spec 5.3), to the first failure: the static one, `--dry-run`,
/// `--intercept=0`. Runs the engine, so it needs the rights its build asks for. An error carries
/// the whole output. For `nfqws2` the arguments come out as he reads them: the `--wf-*` options
/// are WinDivert's, `nft::translate` swaps them for `--qnum`.
pub fn validate(engine: &Engine, tail: &str) -> anyhow::Result<()> {
    strategies::check(engine, tail)?;
    let (tail, _) = real_args(engine, tail);
    let is_nfqws = engine.is_nfqws();
    let dry = run(engine, &dry_run_args(is_nfqws, &tail))?;
    let verified = [&dry.stdout, &dry.stderr]
        .iter()
        .any(|text| text.contains("command line parameters verified"));
    anyhow::ensure!(
        dry.success() && verified,
        "winws2 --dry-run did not accept the strategy:\n{}",
        dry.describe()
    );
    let init = run(engine, &intercept_args(&tail))?;
    anyhow::ensure!(
        init.success(),
        "winws2 --intercept=0 failed{}:\n{}",
        if init.code == Some(87) {
            " to start the Lua code"
        } else {
            ""
        },
        init.describe()
    );
    Ok(())
}

/// The tail as the engine's build reads it, and for `nfqws2` the `(tcp, udp)` port lists its
/// nftables queue takes over from the `--wf-*out=` options (zapret2 spec 5.1).
fn real_args(engine: &Engine, tail: &str) -> (String, Option<(String, String)>) {
    if engine.is_nfqws() {
        let (tail, tcp, udp) = crate::nft::translate(tail);
        (tail, Some((tcp, udp)))
    } else {
        (tail.to_owned(), None)
    }
}

fn run(engine: &Engine, args: &str) -> anyhow::Result<exec::Output> {
    let mut cmd = Command::new(engine.exe());
    cmd.args(zapret::custom::spawn_tokens(args))
        .current_dir(engine.root());
    exec::run(&mut cmd, Duration::from_secs(30), None)
        .with_context(|| format!("starting {} {args}", engine.exe().display()))
}

/// Steps 2–5 of spec 6: Flowseal's service and winws gone, the previous `zapret2` gone, TCP
/// timestamps on (as Flowseal does), `zapret2` created and started, its strategy recorded. One
/// engine at a time: a `zapret` service with yet another copy does nothing (zapret2 spec 6). For
/// `nfqws2` the ports go to the nftables config the unit's `ExecStartPre` applies (spec 6).
pub fn install(engine: &Engine, strategy: &Strategy, tail: &str) -> anyhow::Result<()> {
    service::stop_and_delete(SERVICE)?;
    zapret::procs::kill_all("winws.exe")?;
    zapret::procs::kill_all("nfqws2")?;
    service::stop_and_delete(SERVICE2)?;
    zapret::procs::kill_all(service::WINWS2)?;
    let _ = service::enable_tcp_timestamps();
    let (tail, nft_ports) = real_args(engine, tail);
    if let Some((tcp, udp)) = &nft_ports {
        crate::nft::write_config(tcp, udp).with_context(|| {
            format!(
                "cannot set up the nftables table file {}, which the zapret2 service applies",
                crate::nft::CONFIG
            )
        })?;
    }
    service::create(SERVICE2, &bin_path(engine, &tail), true)?;
    service::start(SERVICE2)?;
    service::set_strategy_of(SERVICE2, &strategy.full_name())
}

/// The check of «Применить» (spec 6), run before any snapshot so that a failure changes nothing.
pub fn prepare(
    engine: &Engine,
    folder: Option<&Folder>,
    home: &Path,
    name: &str,
) -> anyhow::Result<(Strategy, String)> {
    let strategy = strategies::find(home, name)?;
    let tail = strategies::tail(engine, folder, &strategy.text)?;
    validate(engine, &tail)?;
    Ok((strategy, tail))
}

/// «Применить» after `prepare`: the service, and after 2 s the quick check (spec 6).
pub fn install_checked(
    engine: &Engine,
    folder: Option<&Folder>,
    strategy: &Strategy,
    tail: &str,
) -> anyhow::Result<QuickCheck> {
    install(engine, strategy, tail)?;
    std::thread::sleep(Duration::from_secs(2));
    Ok(service::quick_check(folder))
}

/// «Применить» for `zapret2:<name>`: the check while nothing has changed yet, then the service.
pub fn apply(
    engine: &Engine,
    folder: Option<&Folder>,
    home: &Path,
    name: &str,
) -> anyhow::Result<QuickCheck> {
    let (strategy, tail) = prepare(engine, folder, home, name)?;
    install_checked(engine, folder, &strategy, &tail)
}

/// After a game filter change: the active zapret2 strategy installed again, its ports are in the
/// service's arguments (spec 6). Nothing to do while `zapret2` is not installed.
pub fn reinstall_active(
    engine: Option<&Engine>,
    folder: &Folder,
    home: &Path,
) -> anyhow::Result<()> {
    if service::state(SERVICE2) == SvcState::NotInstalled {
        return Ok(());
    }
    let engine = engine.ok_or_else(|| {
        anyhow::anyhow!(
            "the zapret2 service is installed, but the zapret2 folder is not usable, so the service cannot be installed again with the new game filter: check the folder in Settings"
        )
    })?;
    let name = service::strategy_of(SERVICE2)
        .and_then(|name| name.strip_prefix(PREFIX).map(str::to_owned))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "the zapret2 service has no zapret2 strategy name in the registry, so it cannot be installed again with the new game filter: apply a strategy first"
            )
        })?;
    let strategy = strategies::find(home, &name)?;
    let tail = strategies::tail(engine, Some(folder), &strategy.text)?;
    validate(engine, &tail)?;
    install(engine, &strategy, &tail)
}

/// `save_zapret2` before the file (spec 5.2): the name, `create` against what exists, the whole
/// check. Returns the claimed name and the command line.
pub fn check_save(
    engine: &Engine,
    folder: Option<&Folder>,
    home: &Path,
    name: &str,
    text: &str,
    create: bool,
) -> anyhow::Result<(String, String)> {
    let name = strategies::claim(home, name, create)?;
    let tail = strategies::tail(engine, folder, text)?;
    validate(engine, &tail)?;
    Ok((name, tail))
}

/// `save_zapret2` up to the file (spec 5.2): `check_save`, then the file. Returns what was saved
/// and its command line, for a service that runs it.
pub fn save(
    engine: &Engine,
    folder: Option<&Folder>,
    home: &Path,
    name: &str,
    text: &str,
    create: bool,
) -> anyhow::Result<(Strategy, String)> {
    let (name, tail) = check_save(engine, folder, home, name, text, create)?;
    strategies::write(home, &name, text)?;
    let saved = Strategy {
        name,
        text: text.to_owned(),
        builtin: false,
        flowseal_copy: false,
    };
    Ok((saved, tail))
}
