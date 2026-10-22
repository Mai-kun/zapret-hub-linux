//! The check that runs winws2 and the `zapret2` service (zapret2 spec 5.3, 6). `zapret::service`
//! does the `sc` work; this module knows what zapret2 needs from it.

use anyhow::Context as _;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use zapret::service::{self, QuickCheck, SERVICE2};

use crate::Engine;
use crate::strategies::{self, Strategy};

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
    cmd.args(zapret::spawn_tokens(args))
        .current_dir(engine.root());
    exec::run(&mut cmd, Duration::from_secs(30), None)
        .with_context(|| format!("starting {} {args}", engine.exe().display()))
}

/// Steps 2–5 of spec 6: the previous `zapret2` gone, TCP timestamps on, `zapret2` created and
/// started, its strategy recorded (spec 6). For `nfqws2` the ports go to the nftables config the
/// unit's `ExecStartPre` applies (spec 6), together with the excluded ports (the exclusions card).
pub fn install(
    engine: &Engine,
    strategy: &Strategy,
    tail: &str,
    excluded_ports: &str,
) -> anyhow::Result<()> {
    service::stop_and_delete(SERVICE2)?;
    zapret::procs::kill_all("nfqws2")?;
    service::stop_and_delete(SERVICE2)?;
    zapret::procs::kill_all(service::WINWS2)?;
    let _ = service::enable_tcp_timestamps();
    let (tail, nft_ports) = real_args(engine, tail);
    if let Some((tcp, udp)) = &nft_ports {
        crate::nft::write_config(tcp, udp, excluded_ports).with_context(|| {
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
    home: &Path,
    name: &str,
    game_filter: bool,
) -> anyhow::Result<(Strategy, String)> {
    let strategy = strategies::find(home, name)?;
    let tail = strategies::tail(engine, &strategy.text, game_filter)?;
    validate(engine, &tail)?;
    Ok((strategy, tail))
}

/// «Применить» after `prepare`: the service, and after 2 s the quick check (spec 6).
pub fn install_checked(
    engine: &Engine,
    strategy: &Strategy,
    tail: &str,
    excluded_ports: &str,
) -> anyhow::Result<QuickCheck> {
    install(engine, strategy, tail, excluded_ports)?;
    std::thread::sleep(Duration::from_secs(2));
    Ok(service::quick_check())
}

/// «Применить» for `zapret2:<name>`: the check while nothing has changed yet, then the service.
pub fn apply(
    engine: &Engine,
    home: &Path,
    name: &str,
    game_filter: bool,
    excluded_ports: &str,
) -> anyhow::Result<QuickCheck> {
    let (strategy, tail) = prepare(engine, home, name, game_filter)?;
    install_checked(engine, &strategy, &tail, excluded_ports)
}

/// `save_zapret2` before the file (spec 5.2): the name, `create` against what exists, the whole
/// check. Returns the claimed name and the command line.
pub fn check_save(
    engine: &Engine,
    home: &Path,
    name: &str,
    text: &str,
    create: bool,
    game_filter: bool,
) -> anyhow::Result<(String, String)> {
    let name = strategies::claim(home, name, create)?;
    let tail = strategies::tail(engine, text, game_filter)?;
    validate(engine, &tail)?;
    Ok((name, tail))
}

/// `save_zapret2` up to the file (spec 5.2): `check_save`, then the file. Returns what was saved
/// and its command line, for a service that runs it.
pub fn save(
    engine: &Engine,
    home: &Path,
    name: &str,
    text: &str,
    create: bool,
    game_filter: bool,
) -> anyhow::Result<(Strategy, String)> {
    let (name, tail) = check_save(engine, home, name, text, create, game_filter)?;
    strategies::write(home, &name, text)?;
    Ok((strategies::find(home, &name)?, tail))
}
