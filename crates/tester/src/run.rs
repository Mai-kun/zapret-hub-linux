//! A test run (spec 7.3): snapshot, zapret stopped, each strategy started as winws (or winws2,
//! zapret2 spec 7) directly with the arguments «Применить» would install, the checks, everything
//! put back.

use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use probe::curl::CheckKind;
use zapret::procs::Winws;
use zapret::service::{SERVICE2, WINWS2};
use zapret::snapshot::{Snapshot, pending_path};
use zapret::targets::Target;
use zapret2::Engine;

use crate::dpi::DpiTarget;
use crate::model::{DpiTargetResult, Score, StrategyResult, Suite, TargetResult, TestRun};

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, specta::Type)]
pub struct Request {
    pub suite: Suite,
    /// Strategy names, in the order to run them.
    pub strategies: Vec<String>,
    /// Passes over the list, `1..=MAX_REPEATS`; a request from before repeats has one.
    #[serde(default = "one")]
    pub repeats: u32,
}

fn one() -> u32 {
    1
}

pub const MAX_REPEATS: u32 = 5;

impl Request {
    /// What `run` refuses before it touches anything.
    pub fn check(&self) -> anyhow::Result<()> {
        anyhow::ensure!(!self.strategies.is_empty(), "no strategies to test");
        anyhow::ensure!(
            (1..=MAX_REPEATS).contains(&self.repeats),
            "repeats must be from 1 to {MAX_REPEATS}, not {}",
            self.repeats
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, specta::Type)]
#[serde(tag = "kind")]
pub enum Progress {
    /// Strategy `index` (from 0) of `total` starts, in pass `pass` (from 0) of `passes`.
    Strategy {
        index: u32,
        total: u32,
        name: String,
        pass: u32,
        passes: u32,
    },
    /// A strategy's passes so far, aggregated (`rank::aggregate`).
    Done {
        result: Box<StrategyResult>,
    },
    Restoring,
}

/// winws gets this long to report `capture is started` (spec 7.3). Linux `nfqws2` answers the same
/// wait through its NFQUEUE instead (`Winws::wait_ready`), so the whole `max` is wasted rarely.
const READY: Duration = Duration::from_secs(5);
/// The pause the engines get after `wait_ready` said ready: enough for `nfqws2` to settle its last
/// messages, a shorter one also costs the tests nothing meaningful.
const SETTLE: Duration = Duration::from_millis(200);
/// winws2 reports capture started before its Lua starts: a wait with only the line gets this long
/// more, and must still run then (zapret2 spec 7). A queue-said-ready `nfqws2` needs no such
/// pause: it binds its NFQUEUE after the Lua.
const LUA_SETTLE: Duration = Duration::from_secs(2);

/// What can fail is checked and fetched first, while zapret still works; then the state is saved,
/// zapret stopped and the strategies run. The state is put back even when something panics (the
/// panic goes on afterwards). Only `zapret2:` strategies run (`engine2`): a run needs a working
/// zapret2 folder or it stops here, before anything changes.
pub fn run(
    engine2: Option<&Engine>,
    data_dir: &Path,
    request: &Request,
    socks5: Option<&str>,
    cancel: &AtomicBool,
    progress: &(dyn Fn(Progress) + Sync),
) -> anyhow::Result<TestRun> {
    request.check()?;
    let zapret2_version = zapret2_version(engine2, request)?;
    anyhow::ensure!(
        probe::curl::available(),
        "curl was not found: the tests need the system's curl",
    );
    let id = exec::LocalTime::now().stamp();
    // A Cancel or Exit while the DPI suite downloads: zapret is not touched at all.
    let not_canceled = || -> anyhow::Result<()> {
        anyhow::ensure!(
            !cancel.load(Ordering::Relaxed),
            "the test run was canceled before anything changed"
        );
        Ok(())
    };
    not_canceled()?;
    let work = prepare(data_dir, request, socks5)?;
    not_canceled()?;
    let pending = pending_path(data_dir);
    // An earlier pending.json is restored first; when that fails nothing starts (spec 10).
    let snapshot = zapret::snapshot::begin("tests", &pending)?;
    let ran = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let outcome = run_strategies(engine2, request, &work, cancel, progress);
        let canceled = cancel.load(Ordering::Relaxed);
        progress(Progress::Restoring);
        (outcome, canceled)
    }));
    let restore_error = snapshot.restore().err().map(|err| format!("{err:#}"));
    match &restore_error {
        // Put back: the file has done its job.
        None => {
            if let Err(err) = Snapshot::clear(&pending) {
                log::error!("{} not removed: {err:#}", pending.display());
            }
        }
        // Not put back: the file stays, the next start or the next operation restores it.
        Some(err) => log::error!(
            "the state before the tests is not back, {} stays: {err}",
            pending.display()
        ),
    }
    let (outcome, canceled) = match ran {
        Ok(done) => done,
        Err(panic) => std::panic::resume_unwind(panic),
    };
    let mut strategies = match outcome {
        Ok(strategies) => strategies,
        Err(err) => {
            return Err(match restore_error {
                Some(restore) => anyhow::anyhow!(
                    "{err:#}\n\nthe previous state was not restored either: {restore}"
                ),
                None => err,
            });
        }
    };
    crate::rank::sort(request.suite, &mut strategies);
    let run = TestRun {
        id,
        suite: request.suite,
        zapret2_version,
        canceled,
        restore_error,
        strategies,
    };
    crate::history::save(&crate::history::dir(data_dir), &run)?;
    Ok(run)
}

/// The engine version for the run's record. A `zapret2:` strategy without a working engine stops
/// the run here, before anything changes (zapret2 spec 7).
pub fn zapret2_version(
    engine2: Option<&Engine>,
    request: &Request,
) -> anyhow::Result<Option<String>> {
    if !request
        .strategies
        .iter()
        .any(|name| zapret2::strip_prefix(name).is_some())
    {
        return Ok(None);
    }
    let engine = engine2
        .ok_or_else(|| anyhow::anyhow!("the zapret2 folder is not set: choose it in Settings"))?;
    Ok(Some(engine.version()?.text))
}

/// What every strategy is checked against.
enum Work {
    /// Targets with their `extra` flag.
    Standard(Vec<(Target, bool)>),
    Dpi(Vec<DpiTarget>, PathBuf),
}

/// Reads or downloads what the checks need. The DPI suite takes up to a minute to fetch and needs
/// the bypass, so this runs before zapret is stopped, and a failure leaves nothing to restore.
fn prepare(data_dir: &Path, request: &Request, socks5: Option<&str>) -> anyhow::Result<Work> {
    Ok(match request.suite {
        Suite::Standard => {
            let extra = crate::rank::extra_targets(&zapret::targets::defaults());
            Work::Standard(
                zapret::targets::defaults()
                    .into_iter()
                    .map(|t| (t, false))
                    .chain(extra.into_iter().map(|t| (t, true)))
                    .collect(),
            )
        }
        Suite::Dpi => {
            let cache = data_dir.join("cache");
            let targets = crate::dpi::load(&cache, socks5)?;
            let payload = cache.join("dpi-payload.bin");
            probe::curl::write_payload(&payload)?;
            Work::Dpi(targets, payload)
        }
    })
}

fn run_strategies(
    engine2: Option<&Engine>,
    request: &Request,
    work: &Work,
    cancel: &AtomicBool,
    progress: &(dyn Fn(Progress) + Sync),
) -> anyhow::Result<Vec<StrategyResult>> {
    // Both engines: a run may mix them (zapret2 spec 7).
    zapret::service::stop(SERVICE2)?;
    stop_engines()?;
    // As «Применить» does (`service::install`): strategies with `fooling=ts` need them.
    if zapret::service::tcp_timestamps() == Some(false)
        && let Err(err) = zapret::service::enable_tcp_timestamps()
    {
        log::warn!("TCP timestamps stay off for the tests: {err:#}");
    }
    warm_dns(work);
    let total = request.strategies.len() as u32;
    let mut done: Vec<Vec<StrategyResult>> = vec![Vec::new(); request.strategies.len()];
    // N whole passes over the list, not N runs of one strategy back to back: the network drifts
    // over minutes, and interleaving spreads that drift over every strategy instead of handing a
    // bad minute to whichever one ran then.
    'passes: for pass in 0..request.repeats {
        for (index, name) in request.strategies.iter().enumerate() {
            if cancel.load(Ordering::Relaxed) {
                break 'passes;
            }
            progress(Progress::Strategy {
                index: index as u32,
                total,
                name: name.clone(),
                pass,
                passes: request.repeats,
            });
            // Nothing of either engine may filter while this one is measured: the previous
            // strategy's process has exited (`Winws::stop` waits), and this catches any other.
            stop_engines()?;
            let result = run_one(engine2, name, work, cancel);
            if cancel.load(Ordering::Relaxed) {
                break 'passes; // cut short: not a result
            }
            done[index].push(result);
            progress(Progress::Done {
                result: Box::new(crate::rank::aggregate(done[index].clone())),
            });
        }
    }
    Ok(whole_passes(done)
        .into_iter()
        .map(crate::rank::aggregate)
        .collect())
}

/// Every winws.exe and winws2.exe ended, and gone (their WinDivert handles closed); `nfqws2`
/// the same, and nftables is done with it: the queue only steals packets.
fn stop_engines() -> anyhow::Result<()> {
    for image in ["winws.exe", WINWS2, "nfqws2"] {
        zapret::procs::kill_all(image)?;
    }
    zapret2::nft::clear();
    Ok(())
}

/// The passes of a canceled run that count: a strategy with one pass more than another would sum
/// more checks, so a pass cut short is dropped, unless it is the first (then the strategies it
/// reached are the run, as without repeats). Strategies without a pass are left out.
pub fn whole_passes(mut done: Vec<Vec<StrategyResult>>) -> Vec<Vec<StrategyResult>> {
    let whole = done.iter().map(Vec::len).min().unwrap_or(0);
    if whole > 0 {
        for passes in &mut done {
            passes.truncate(whole);
        }
    }
    done.retain(|passes| !passes.is_empty());
    done
}

/// curl's `time_total` includes the name lookup, and Windows caches names for every process: the
/// first strategy to ask would pay it alone. Resolved once here, with neither engine running.
/// ponytail: an entry whose TTL ends mid-run is looked up again by whichever strategy runs then;
/// repeats spread that.
fn warm_dns(work: &Work) {
    use std::net::ToSocketAddrs as _;
    let hosts: Vec<String> = match work {
        Work::Standard(targets) => targets
            .iter()
            .filter_map(|(target, _)| target.url.as_deref())
            .map(|url| zapret::targets::url_host(url).to_owned())
            .collect(),
        Work::Dpi(targets, _) => targets.iter().map(|t| t.host.clone()).collect(),
    };
    par_map(&hosts, parallelism(), |host| {
        let _ = (host.as_str(), 443).to_socket_addrs();
    });
}

/// How a strategy starts: the program, its working folder, the arguments and their hash, and for
/// `nfqws2` the `(tcp, udp)` ports the nftables queue takes from `--wf-*out=` before it runs.
struct Launch {
    exe: PathBuf,
    cwd: PathBuf,
    tail: String,
    sha256: String,
    nft_ports: Option<(String, String)>,
}

/// The one place a test run tells the strategies apart (zapret2 spec 3.1): by the name's prefix.
/// Only `zapret2:` strategies run: anything else is a launch error with the reason.
fn launch(engine2: Option<&Engine>, name: &str) -> anyhow::Result<Launch> {
    let Some(name) = zapret2::strip_prefix(name) else {
        anyhow::bail!("{name} is a Flowseal strategy: the tests run zapret2 strategies only");
    };
    let engine = engine2
        .ok_or_else(|| anyhow::anyhow!("the zapret2 folder is not set: choose it in Settings"))?;
    let strategy = zapret2::strategies::find(engine.root(), name)?;
    let tail = zapret2::strategies::tail(engine, &strategy.text)?;
    // The hash is of the tail before `nft::translate`: the same line «Стратегии» hashes
    // (catalog.rs). The queue's `--qnum=` and dropped `--wf-*` are launch bookkeeping, not an
    // argument change, and would mark just-tested zapret2 strategies stale.
    let sha256 = zapret::sha256_hex(tail.as_bytes());
    // nfqws2 does not know the `--wf-*out=` ports: the nftables queue takes them over.
    let (tail, nft_ports) = if engine.is_nfqws() {
        let (tail, tcp, udp) = zapret2::nft::translate(&tail);
        (tail, Some((tcp, udp)))
    } else {
        (tail, None)
    };
    zapret2::strategies::check(engine, &tail)?;
    Ok(Launch {
        exe: engine.exe().to_path_buf(),
        cwd: engine.root().to_path_buf(),
        // ponytail: the engine version is not in the hash (the run keeps it); add it if old
        // results start to mislead (zapret2 spec 12).
        sha256,
        tail,
        nft_ports,
    })
}

fn run_one(
    engine2: Option<&Engine>,
    name: &str,
    work: &Work,
    cancel: &AtomicBool,
) -> StrategyResult {
    let mut result = StrategyResult {
        name: name.to_owned(),
        args_sha256: String::new(),
        launch_error: None,
        targets: Vec::new(),
        dpi: Vec::new(),
        score: Score::default(),
        passes: Vec::new(),
    };
    let launch = match launch(engine2, name) {
        Ok(launch) => launch,
        Err(err) => {
            result.launch_error = Some(format!("{err:#}"));
            return result;
        }
    };
    result.args_sha256 = launch.sha256;
    // The queue comes up just before the engine: without it, tests measure nothing filtered.
    if let Some((tcp, udp)) = &launch.nft_ports {
        if let Err(err) = zapret2::nft::apply(tcp, udp) {
            result.launch_error = Some(format!("nftables: {err:#}"));
            return result;
        }
    }
    let mut winws = match Winws::start(&launch.exe, &launch.cwd, &launch.tail) {
        Ok(winws) => winws,
        Err(err) => {
            if launch.nft_ports.is_some() {
                zapret2::nft::clear();
            }
            let image = launch
                .exe
                .file_name()
                .map_or_else(|| "winws".into(), |n| n.to_string_lossy());
            result.launch_error = Some(format!("{image} did not start: {err}"));
            return result;
        }
    };
    let queue_ready = match winws.wait_ready(READY) {
        Ok(queue_ready) => queue_ready,
        Err(output) => {
            if launch.nft_ports.is_some() {
                zapret2::nft::clear();
            }
            result.launch_error = Some(output);
            return result;
        }
    };
    // `queue_ready` is a Linux `nfqws2` with its queue bound, after the Lua init: a short settle
    // does. The other way ready (`winws2`'s line comes before its Lua) gets the pause.
    std::thread::sleep(if queue_ready { SETTLE } else { LUA_SETTLE });
    // A winws2 whose Lua failed is gone by now: nothing to check.
    if winws.exited().is_none() {
        let workers = parallelism();
        match work {
            Work::Standard(targets) => {
                result.targets = par_map(targets, workers, |(target, extra)| {
                    check_target(target, *extra, cancel)
                });
                result.score = crate::rank::score_standard(&result.targets);
            }
            Work::Dpi(targets, payload) => {
                result.dpi = par_map(targets, workers, |target| {
                    check_dpi(target, payload, cancel)
                });
                result.score = crate::rank::score_dpi(&result.dpi);
            }
        }
    }
    // Read after `stop`, which waits for the readers: the output is whole.
    let exited = winws.exited();
    let output = winws.stop();
    if launch.nft_ports.is_some() {
        zapret2::nft::clear();
    }
    result.launch_error = lua_failure(exited, &output);
    result
}

/// winws2 prints its ready line before its Lua starts. One that has ended, or printed `LUA ERROR`
/// (a strategy that fails on every packet does nothing), did not run the strategy: a launch error
/// with its whole output, or a strategy that did nothing would rank above working ones (zapret2
/// spec 7). Exit code 87 is a failed Lua start.
pub fn lua_failure(exited: Option<ExitStatus>, output: &str) -> Option<String> {
    if let Some(status) = exited {
        return Some(format!("winws2 exited ({status}):\n{output}"));
    }
    output
        .contains("LUA ERROR")
        .then(|| format!("winws2 printed LUA ERROR:\n{output}"))
}

/// The DbD game server: its AWS host drops ICMP (a guaranteed 1 s timeout) and does not speak
/// TLS 1.3 (a guaranteed UNSUP) — HTTP and TLS 1.2 are all it answers, so only those are asked.
const DBD_HOST: &str = "steam.live.bhvrdbd.com";

fn check_target(target: &Target, extra: bool, cancel: &AtomicBool) -> TargetResult {
    let dbd = extra
        && target
            .url
            .as_deref()
            .is_some_and(|url| zapret::targets::url_host(url).eq_ignore_ascii_case(DBD_HOST));
    // The three curl probes and the ping are pure network waits: together they take the longest
    // one, not their sum.
    let kinds: &[CheckKind] = if dbd {
        &[CheckKind::Http, CheckKind::Tls12]
    } else {
        &CheckKind::ALL
    };
    let (checks, ping_ms) = match &target.url {
        Some(url) => std::thread::scope(|scope| {
            let probes: Vec<_> = kinds
                .iter()
                .map(|kind| scope.spawn(|| probe::curl::check(url, *kind, Some(cancel))))
                .collect();
            // The DbD server's ping stays out: the firewall drops ICMP, the wait would burn a
            // full second to record the `None` a dropped ping is anyway.
            let ping = (!dbd).then(|| scope.spawn(|| probe::ping::ping(&target.ping, 1000)));
            (
                probes
                    .into_iter()
                    .map(|probe| probe.join().unwrap())
                    .collect(),
                ping.map(|ping| ping.join().unwrap()).flatten(),
            )
        }),
        None => (Vec::new(), probe::ping::ping(&target.ping, 1000)),
    };
    TargetResult {
        name: target.name.clone(),
        url: target.url.clone(),
        extra,
        checks,
        ping_ms,
    }
}

fn check_dpi(target: &DpiTarget, payload: &Path, cancel: &AtomicBool) -> DpiTargetResult {
    let checks = CheckKind::ALL
        .iter()
        .map(|kind| probe::curl::dpi_check(&target.host, *kind, payload, Some(cancel)))
        .collect();
    DpiTargetResult {
        id: target.id.clone(),
        provider: target.provider.clone(),
        country: target.country.clone(),
        host: target.host.clone(),
        checks,
    }
}

/// `min(32, max(16, cores × 2))` targets at a time (spec 7.1): the workers only wait on the
/// checks' network I/O, so more of them than cores still cut the wall time.
pub fn parallelism() -> usize {
    std::thread::available_parallelism()
        .map_or(4, |n| n.get())
        .saturating_mul(2)
        .clamp(16, 32)
}

/// `f` over `items` on `workers` threads; the results keep the input order.
pub fn par_map<T: Sync, R: Send>(
    items: &[T],
    workers: usize,
    f: impl Fn(&T) -> R + Sync,
) -> Vec<R> {
    let next = AtomicUsize::new(0);
    let slots: Vec<Mutex<Option<R>>> = items.iter().map(|_| Mutex::new(None)).collect();
    std::thread::scope(|scope| {
        for _ in 0..workers.clamp(1, items.len().max(1)) {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(item) = items.get(i) else { break };
                    *slots[i].lock().unwrap() = Some(f(item));
                }
            });
        }
    });
    slots
        .into_iter()
        .map(|slot| slot.into_inner().unwrap().expect("every slot is filled"))
        .collect()
}
