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
fn reads_service_logs_without_panicking() {
    let logs = zapret::service::logs();
    assert!(!logs.is_empty());
}
