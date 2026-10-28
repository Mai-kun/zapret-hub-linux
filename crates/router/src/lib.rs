pub mod dns;
pub mod doh;
pub mod flows;
mod live_tcp;
pub mod nft;
pub mod owner;
pub mod packet;
pub mod rules;
pub mod sniff;
pub mod socks;
pub mod tcp;

use std::collections::HashMap;
use std::mem::discriminant;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock, Weak};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};

use dns::Names;
use flows::{FlowKey, ProxyState, Stats, Totals};
use owner::Images;
use rules::Table;
use socks::OPEN_TIMEOUT;

const PROXY_CHECK: Duration = Duration::from_secs(10);
const HOUSEKEEPING: Duration = Duration::from_secs(1);
const RULES_CHECK_TICKS: u32 = 4;

#[derive(Debug, Clone, PartialEq)]
pub struct Setup {
    pub proxy: SocketAddrV4,
}

pub fn parse_proxy(socks5: Option<&str>) -> Result<SocketAddrV4> {
    let text = socks5
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("set the SOCKS5 proxy in Settings first"))?;
    let addr: SocketAddrV4 = text.parse().map_err(|_| {
        anyhow!("the router needs an IPv4 SOCKS5 address like 127.0.0.1:2080: {text}")
    })?;
    // The relay sockets are bound to loopback (spec 1: a local proxy).
    if !addr.ip().is_loopback() {
        bail!("the router needs a local SOCKS5 proxy like 127.0.0.1:2080: {text}");
    }
    Ok(addr)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(tag = "state")]
pub enum RouterState {
    Off,
    Running,
    Paused,
    Unavailable { reason: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
pub struct RouterStatus {
    pub state: RouterState,
    pub proxy: ProxyState,
    pub totals: Totals,
    pub rules_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
pub struct RuleRow {
    pub rule: rules::Rule,
    pub traffic: flows::Traffic,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
pub struct RoutesView {
    pub rules: Vec<RuleRow>,
    pub error: Option<String>,
    /// The system resolves names over encrypted DNS: the sniffer sees no answers and domain
    /// rules match nothing until an app resolves them in the clear.
    pub system_doh: bool,
}

#[derive(Clone)]
pub struct Router(Arc<Inner>);

type Callback = Arc<dyn Fn() + Send + Sync>;

struct Inner {
    path: PathBuf,
    on_change: Mutex<Option<Callback>>,
    ctl: Mutex<Ctl>,
    /// State and session as `control` left them: `status` and `flows` never wait for a launch.
    snapshot: Mutex<(RouterState, Option<Arc<Live>>)>,
    rules: Mutex<RulesFile>,
    /// The table in force; a launch starts from it.
    table: Mutex<Table>,
    /// Outlives sessions: programs keep resolved addresses cached across a pause.
    names: Arc<Mutex<Names>>,
    /// Outlives sessions too: a program seen before a pause still counts as running.
    images: Arc<Images>,
}

struct Ctl {
    state: RouterState,
    setup: Option<Setup>,
    /// Set by `pause` in any state, cleared only by `resume`: a test run stays unrouted.
    paused: bool,
    live: Option<Arc<Live>>,
}

struct RulesFile {
    list: Vec<rules::Rule>,
    modified: Option<SystemTime>,
    file_error: Option<String>,
    filter_error: Option<String>,
}

impl RulesFile {
    fn error(&self) -> Option<String> {
        self.file_error
            .clone()
            .or_else(|| self.filter_error.clone())
    }
}

fn modified(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// Re-reads the file when its write time changed (or `force`); a broken file keeps the rules.
/// True when the rules were replaced.
fn reload(path: &Path, file: &mut RulesFile, force: bool) -> bool {
    let now = modified(path);
    if !force && now == file.modified {
        return false;
    }
    file.modified = now;
    match rules::load(path) {
        Ok(list) => {
            file.list = list;
            file.file_error = None;
            true
        }
        Err(e) => {
            file.file_error = Some(e.to_string());
            false
        }
    }
}

impl Router {
    pub fn new(routes: PathBuf) -> Router {
        let mut file = RulesFile {
            list: Vec::new(),
            modified: None,
            file_error: None,
            filter_error: None,
        };
        reload(&routes, &mut file, true);
        let table = Mutex::new(Table::new(&file.list));
        Router(Arc::new(Inner {
            table,
            names: Arc::default(),
            images: Arc::default(),
            path: routes,
            on_change: Mutex::new(None),
            ctl: Mutex::new(Ctl {
                state: RouterState::Off,
                setup: None,
                paused: false,
                live: None,
            }),
            snapshot: Mutex::new((RouterState::Off, None)),
            rules: Mutex::new(file),
        }))
    }

    pub fn on_change(&self, f: impl Fn() + Send + Sync + 'static) {
        *self.0.on_change.lock().unwrap() = Some(Arc::new(f));
    }

    /// Runs `op` on the control block, then calls back (no lock held) if the state changed.
    fn control<T>(&self, op: impl FnOnce(&Arc<Inner>, &mut Ctl) -> T) -> T {
        let mut ctl = self.0.ctl.lock().unwrap();
        let before = ctl.state.clone();
        let out = op(&self.0, &mut ctl);
        let changed = ctl.state != before;
        *self.0.snapshot.lock().unwrap() = (ctl.state.clone(), ctl.live.clone());
        drop(ctl);
        if changed {
            self.0.notify();
        }
        out
    }

    pub fn start(&self, setup: Setup) -> Result<()> {
        self.control(|inner, ctl| {
            if ctl.paused {
                halt(ctl);
                ctl.setup = Some(setup);
                ctl.state = RouterState::Paused;
                return Ok(());
            }
            if ctl.state == RouterState::Running && ctl.setup.as_ref() == Some(&setup) {
                return Ok(());
            }
            ctl.setup = Some(setup.clone());
            launch(inner, ctl, &setup)
        })
    }

    pub fn fail(&self, reason: String) {
        self.control(|_, ctl| {
            halt(ctl);
            ctl.setup = None;
            ctl.state = RouterState::Unavailable { reason };
        });
    }

    /// The pause flag survives: only `resume` clears it (ruling F4).
    pub fn stop(&self) {
        self.control(|_, ctl| {
            halt(ctl);
            ctl.setup = None;
            ctl.state = RouterState::Off;
        });
    }

    pub fn pause(&self) {
        self.control(|_, ctl| {
            ctl.paused = true;
            if ctl.state == RouterState::Running {
                halt(ctl);
                ctl.state = RouterState::Paused;
            }
        });
    }

    pub fn resume(&self) {
        self.control(|inner, ctl| {
            ctl.paused = false;
            if ctl.state == RouterState::Paused
                && let Some(setup) = ctl.setup.clone()
            {
                let _ = launch(inner, ctl, &setup);
            }
        });
    }

    pub fn status(&self) -> RouterStatus {
        let (state, live) = self.0.snapshot.lock().unwrap().clone();
        RouterStatus {
            state,
            proxy: live.as_ref().map_or(ProxyState::Unknown, |l| {
                l.proxy_state.lock().unwrap().clone()
            }),
            totals: live
                .map(|l| l.stats.lock().unwrap().totals())
                .unwrap_or_default(),
            rules_error: self.0.rules.lock().unwrap().error(),
        }
    }

    pub fn rules(&self) -> RoutesView {
        self.0.refresh();
        let live = self.0.live();
        let file = self.0.rules.lock().unwrap();
        let traffic = |name: &str| {
            live.as_ref()
                .map(|l| l.stats.lock().unwrap().rule_traffic(name))
                .unwrap_or_default()
        };
        RoutesView {
            rules: file
                .list
                .iter()
                .map(|r| RuleRow {
                    rule: r.clone(),
                    traffic: traffic(&r.name),
                })
                .collect(),
            error: file.error(),
            system_doh: doh::system_doh(),
        }
    }

    pub fn flows(&self, all: bool) -> Vec<flows::FlowRow> {
        let live = self.0.snapshot.lock().unwrap().1.clone();
        match live {
            Some(l) => l.stats.lock().unwrap().rows(Instant::now(), all),
            None => Vec::new(),
        }
    }

    /// The match table in force (what the nftables table was built from).
    #[doc(hidden)]
    pub fn table(&self) -> Table {
        self.0.table.lock().unwrap().clone()
    }

    pub fn edit<T>(&self, f: impl FnOnce(&mut Vec<rules::Rule>) -> Result<T>) -> Result<T> {
        // An outside change takes effect even if this edit then fails.
        self.0.refresh();
        let mut file = self.0.rules.lock().unwrap();
        if reload(&self.0.path, &mut file, false) {
            // Changed again since `refresh`: apply it too (not under the rules lock).
            let table = Table::new(&file.list);
            drop(file);
            self.0.apply(table);
            file = self.0.rules.lock().unwrap();
        }
        if let Some(e) = &file.file_error {
            bail!("routes.toml has an error, fix or delete it first: {e}");
        }
        let mut list = file.list.clone();
        let out = f(&mut list)?;
        for rule in &list {
            if let Some(e) = rules::check(rule).first() {
                bail!("{}: {}: {}", rule.name, e.field, e.message);
            }
        }
        rules::save(&self.0.path, &list)?;
        file.modified = modified(&self.0.path);
        file.list = list;
        let table = Table::new(&file.list);
        drop(file);
        self.0.apply(table);
        Ok(out)
    }
}

fn halt(ctl: &mut Ctl) {
    if let Some(live) = ctl.live.take() {
        live.shut();
    }
}

/// Counters start from zero: every launch is a new `Live`.
fn launch(inner: &Arc<Inner>, ctl: &mut Ctl, setup: &Setup) -> Result<()> {
    halt(ctl);
    let table = inner.table.lock().unwrap().clone();
    match Live::open(inner, setup, table) {
        Ok(live) => {
            ctl.live = Some(live);
            ctl.state = RouterState::Running;
            inner.rules.lock().unwrap().filter_error = None;
            Ok(())
        }
        Err(e) => {
            ctl.state = RouterState::Unavailable {
                reason: format!("{e:#}"),
            };
            Err(e)
        }
    }
}

impl Inner {
    fn notify(&self) {
        let f = self.on_change.lock().unwrap().clone();
        if let Some(f) = f {
            f();
        }
    }

    fn live(&self) -> Option<Arc<Live>> {
        self.ctl.lock().unwrap().live.clone()
    }

    fn refresh(&self) {
        let mut file = self.rules.lock().unwrap();
        if reload(&self.path, &mut file, false) {
            let table = Table::new(&file.list);
            drop(file);
            self.apply(table);
        }
    }

    fn apply(&self, table: Table) {
        *self.table.lock().unwrap() = table.clone();
        let Some(live) = self.live() else { return };
        let error = live.apply(Some(table)).err();
        self.rules.lock().unwrap().filter_error = error;
    }
}

/// One running session: the acceptor, the nftables table, the DNS sniffer and the counters;
/// dropped whole on stop or pause.
struct Live {
    inner: Weak<Inner>,
    proxy: SocketAddrV4,
    stopped: AtomicBool,
    acceptor: TcpListener,
    acceptor_port: u16,
    /// The rules without resolved names; `table` is it with them.
    base: Mutex<Table>,
    table: RwLock<Arc<Table>>,
    names: Arc<Mutex<Names>>,
    images: Arc<Images>,
    /// Both sockets of each proxied TCP connection, shut down when the session ends.
    conns: Mutex<HashMap<FlowKey, (TcpStream, TcpStream)>>,
    tcp_owners: owner::Owners,
    stats: Mutex<Stats>,
    proxy_state: Mutex<ProxyState>,
    proxy_pid: Mutex<Option<u32>>,
    /// The acceptor's sockets could carry the nftables mark (loop protection): false means
    /// no-rule and loop flows must not try their own direct way out.
    mark_ok: AtomicBool,
}

fn spawn(f: impl FnOnce() + Send + 'static) {
    std::thread::spawn(f);
}

impl Live {
    fn open(inner: &Arc<Inner>, setup: &Setup, table: Table) -> Result<Arc<Live>> {
        let acceptor = TcpListener::bind("0.0.0.0:0")
            .map_err(|e| anyhow!("cannot open the local TCP acceptor: {e}"))?;
        let acceptor_port = acceptor.local_addr()?.port();
        inner.names.lock().unwrap().expire(Instant::now(), &[]);
        let live = Arc::new(Live {
            inner: Arc::downgrade(inner),
            proxy: setup.proxy,
            stopped: AtomicBool::new(false),
            acceptor,
            acceptor_port,
            base: Mutex::new(Table::default()),
            table: RwLock::new(Arc::new(Table::default())),
            names: inner.names.clone(),
            images: inner.images.clone(),
            conns: Mutex::new(HashMap::new()),
            tcp_owners: owner::Owners::default(),
            stats: Mutex::new(Stats::default()),
            proxy_state: Mutex::new(ProxyState::Unknown),
            proxy_pid: Mutex::new(None),
            // The loop protection is only as good as the mark: probe the rights once.
            mark_ok: AtomicBool::new(nft::mark_probe()),
        });
        if let Err(e) = live.apply(Some(table)) {
            live.shut();
            bail!(e);
        }
        let l = live.clone();
        spawn(move || l.dns_loop());
        let l = live.clone();
        spawn(move || l.accept_loop());
        let l = live.clone();
        spawn(move || l.housekeeping());
        let l = live.clone();
        spawn(move || l.check_proxy());
        Ok(live)
    }

    fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }

    /// Works after a panic poisoned the locks.
    fn shut(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        // The redirected connections end (programs reconnect).
        let conns: Vec<_> = self
            .conns
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .drain()
            .collect();
        for (_, (a, b)) in &conns {
            let _ = a.shutdown(std::net::Shutdown::Both);
            let _ = b.shutdown(std::net::Shutdown::Both);
        }
        // Wakes the acceptor, which then sees `stopped`.
        let _ = TcpStream::connect_timeout(
            &SocketAddr::from((Ipv4Addr::LOCALHOST, self.acceptor_port)),
            Duration::from_secs(1),
        );
        // The table goes first, so nothing new is redirected while the sockets die.
        nft::remove();
        self.stats
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        self.tcp_owners.clear();
    }

    /// New rules (`None`: the same ones with the names known now) take effect at once: the whole
    /// `nft -f` transaction replaces the table, keeping the redirections of live connections
    /// (conntrack holds them). A refused script is not retried until the rules change; the error
    /// is the router's rules error.
    fn apply(self: &Arc<Self>, base: Option<Table>) -> Result<(), String> {
        let base = match base {
            Some(b) => {
                *self.base.lock().unwrap() = b.clone();
                b
            }
            None => self.base.lock().unwrap().clone(),
        };
        let table = base.with_names(&self.names.lock().unwrap().entries());
        let script = nft::script(&table, self.proxy, self.acceptor_port);
        nft::apply(&script).map_err(|e| format!("{e:#}"))?;
        *self.table.write().unwrap() = Arc::new(table);
        Ok(())
    }

    /// Re-applies the rules with the names known now; a refused script shows as the rules error.
    pub(crate) fn recompose(self: &Arc<Self>) {
        if self.is_stopped() {
            return;
        }
        let error = self.apply(None).err();
        if let Some(inner) = self.inner.upgrade() {
            inner.rules.lock().unwrap().filter_error = error;
        }
    }

    /// Sniffs DNS answers off the wire; a domain of some rule resolving adds its address to the
    /// table. Ends when the session stops (the read times out and sees it).
    fn dns_loop(self: &Arc<Self>) {
        let Some(capture) = sniff::Capture::open() else {
            log::warn!("no raw packet socket: domain rules get no resolved addresses");
            return;
        };
        let mut buf = vec![0u8; 65_536];
        while !self.is_stopped() {
            let Some(payload) = capture.dns_answer(&mut buf) else {
                continue;
            };
            let Some(answer) = dns::parse(payload) else {
                continue;
            };
            if !self.base.lock().unwrap().wants(&answer.name) {
                continue;
            }
            if self.names.lock().unwrap().record(&answer, Instant::now()) {
                self.recompose();
            }
        }
    }

    /// Ends on the first connection after the session stopped (`shut` makes one).
    pub(crate) fn accept_loop(self: &Arc<Self>) {
        for conn in self.acceptor.incoming() {
            if self.is_stopped() {
                return;
            }
            match conn {
                Ok(stream) => {
                    let l = self.clone();
                    spawn(move || l.handle_conn(stream));
                }
                Err(_) => std::thread::sleep(Duration::from_millis(50)),
            }
        }
    }

    /// Calls back only when the kind changes (ok -> down), not on every latency update.
    fn set_proxy(&self, new: ProxyState) {
        self.update_proxy(|_| Some(new));
    }

    /// Decides and writes under one lock, so a concurrent writer cannot be overwritten.
    fn update_proxy(&self, f: impl FnOnce(&ProxyState) -> Option<ProxyState>) {
        let mut state = self.proxy_state.lock().unwrap();
        let Some(new) = f(&state) else {
            return;
        };
        let changed = discriminant(&*state) != discriminant(&new);
        *state = new;
        drop(state);
        // Live connections keep their way (spec 7); the next ones decide afresh.
        if changed && !self.is_stopped()
            && let Some(inner) = self.inner.upgrade()
        {
            inner.notify();
        }
    }

    /// Sleeps `total` in short steps; false once the session stopped.
    fn sleep(&self, total: Duration) -> bool {
        let end = Instant::now() + total;
        while !self.is_stopped() {
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return true;
            }
            std::thread::sleep(left.min(Duration::from_millis(100)));
        }
        false
    }

    /// Right at start and every 10 s, debounced by `flows::checked`.
    fn check_proxy(&self) {
        let mut failures = 0;
        loop {
            let new = match socks::check(self.proxy, OPEN_TIMEOUT) {
                Ok(took) => ProxyState::Ok {
                    latency_ms: took.as_millis() as u32,
                },
                Err(socks::SocksError::AuthRequired) => ProxyState::AuthRequired,
                Err(e) => ProxyState::Down {
                    error: e.to_string(),
                },
            };
            *self.proxy_pid.lock().unwrap() = owner::listener_pid(self.proxy.port());
            self.update_proxy(|current| flows::checked(current, new, &mut failures));
            if !self.sleep(PROXY_CHECK) {
                return;
            }
        }
    }

    /// Every tick: expire names (not those of live flows), drop old closed rows; every 2 s:
    /// forget exited programs, re-read the rules.
    fn housekeeping(self: &Arc<Self>) {
        let mut tick = 0u32;
        while self.sleep(HOUSEKEEPING) {
            tick += 1;
            let now = Instant::now();
            self.stats.lock().unwrap().prune(now);
            self.names.lock().unwrap().expire(now, &self.live_ips());
            if tick.is_multiple_of(RULES_CHECK_TICKS) {
                self.images.prune(owner::process_start);
                match self.inner.upgrade() {
                    Some(inner) => inner.refresh(),
                    None => return,
                }
            }
        }
    }

    fn live_ips(&self) -> Vec<Ipv4Addr> {
        self.conns
            .lock()
            .unwrap()
            .keys()
            .map(|k| *k.dst.ip())
            .collect()
    }
}
