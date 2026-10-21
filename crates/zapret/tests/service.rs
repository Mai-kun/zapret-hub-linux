use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use zapret::procs::Winws;
use zapret::service::{SvcState, config, parse_timestamps, state};

#[test]
fn reads_the_timestamps_value_as_the_kernel_keeps_it() {
    assert_eq!(parse_timestamps("1\n"), Some(true));
    assert_eq!(parse_timestamps("0\n"), Some(false));
    assert_eq!(parse_timestamps(" GARAGE "), None);
}

#[test]
fn reads_service_states_through_systemd() {
    assert_eq!(state("systemd-journald"), SvcState::Running);
    assert_eq!(state("zapret-hub-no-such-service"), SvcState::NotInstalled);
    assert!(!zapret::service::active_services().is_empty());
}

#[test]
fn reads_a_service_config_from_the_unit_file() {
    // systemd-timesyncd's ExecStart is one binary, and it is wanted at boot.
    let cfg = config("systemd-timesyncd").expect("the unit file has an ExecStart");
    assert!(
        cfg.image_path.contains("systemd-timesyncd"),
        "{}",
        cfg.image_path
    );
    assert!(cfg.auto_start);
    assert_eq!(config("zapret-hub-no-such-service"), None);
}

#[test]
fn a_service_without_a_recorded_strategy_has_none() {
    assert_eq!(
        zapret::service::strategy_of("zapret-hub-no-such-service"),
        None
    );
}

fn shell() -> PathBuf {
    PathBuf::from("/bin/sh")
}

#[test]
fn a_started_engine_is_ready_when_capture_starts() {
    // winws2 prints `windivert initialized. capture is started.`; sh stands in for it.
    let dir = tempfile::tempdir().unwrap();
    let mut winws = Winws::start(
        &shell(),
        dir.path(),
        r#"/c "pwd&echo windivert initialized. capture is started.&sleep 3""#,
    )
    .unwrap();
    winws.wait_ready(Duration::from_secs(5)).unwrap();
    assert!(winws.exited().is_none());
    let output = winws.stop();
    assert!(output.contains("capture is started."), "{output}");
    let dir_name = dir.path().file_name().unwrap().to_string_lossy();
    assert!(
        output.contains(&*dir_name),
        "runs in the given folder: {output}"
    );
}

#[test]
fn an_engine_that_exits_is_a_launch_error_naming_its_image() {
    let dir = tempfile::tempdir().unwrap();
    let mut winws = Winws::start(
        &shell(),
        dir.path(),
        r#"/c "echo LUA ERROR: no such function&exit 87""#,
    )
    .unwrap();
    let err = winws.wait_ready(Duration::from_secs(5)).unwrap_err();
    assert!(err.to_lowercase().starts_with("sh exited"), "{err}");
    assert!(err.contains("87") && err.contains("LUA ERROR"), "{err}");
}

#[test]
#[ignore = "needs root rights and /opt/zapret; replaces the zapret and zapret2 services"]
fn a_flowseal_install_takes_zapret2_down() {
    use zapret::service::{SERVICE, SERVICE2, active, create};
    let folder = zapret::folder::Folder::open("/opt/zapret").unwrap();
    // What `apply` does before `install` removes anything: a missing or broken `general` fails here,
    // not with the stand-in left installed.
    let file = zapret::strategies::find(&folder, "general").unwrap();
    zapret::batparse::parse_file(&folder, &file.path).unwrap();
    // A stand-in zapret2: the install removes it whatever it runs.
    create(SERVICE2, "/bin/sh -c exit", false).unwrap();
    assert_eq!(active().0, SERVICE2);
    let check = zapret::service::apply(&folder, "general").unwrap();
    eprintln!("{check:?}");
    assert_eq!(state(SERVICE2), SvcState::NotInstalled);
    assert_eq!(active(), (SERVICE, "winws.exe"));
}

#[test]
fn finds_a_process_with_its_arguments() {
    let mut child = Command::new("ping")
        .args(["-c", "20", "127.0.0.1"])
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(300));
    let found = zapret::procs::find("PING.EXE");

    let ours = found
        .iter()
        .find(|p| p.pid == child.id())
        .expect("our ping is listed");
    assert_eq!(ours.args, ["-c", "20", "127.0.0.1"]);
    assert!(
        ours.exe
            .as_ref()
            .is_some_and(|e| e.to_string_lossy().ends_with("ping")),
        "{:?}",
        ours.exe
    );
    child.kill().unwrap();
    child.wait().unwrap();
}

#[test]
#[ignore = "needs root rights and the zapret service installed from /opt/zapret"]
fn live_status_of_the_zapret_service() {
    let status = zapret::service::status(zapret::service::SERVICE);
    let config = zapret::service::config(zapret::service::SERVICE);
    let strategy = zapret::service::strategy_of(zapret::service::SERVICE);
    let timestamps = zapret::service::tcp_timestamps();
    let candidates = zapret::folder::candidates();
    eprintln!(
        "zapret: {status:?}\nconfig: {config:?}\nstrategy: {strategy:?}\ntimestamps: {timestamps:?}\ncandidates: {candidates:?}"
    );
    assert!(status.is_some(), "the zapret service is not installed");
    let config = config.expect("the service has a configuration");
    assert!(
        config.image_path.contains("winws.exe"),
        "{}",
        config.image_path
    );
    assert!(
        strategy.is_some(),
        "service.bat records the installed strategy next to the service"
    );
    assert!(
        timestamps.is_some(),
        "/proc keeps the TCP timestamps setting"
    );
    assert!(
        candidates
            .iter()
            .any(|root| root.to_string_lossy().ends_with("/opt/zapret")),
        "{candidates:?}"
    );
}

#[test]
fn reads_service_logs_without_panicking() {
    let logs = zapret::service::logs();
    assert!(!logs.is_empty());
}
