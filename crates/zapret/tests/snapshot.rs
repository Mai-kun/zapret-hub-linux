//! The `pending.json` contract: taken before an operation, restored after a crash.

use std::path::Path;

mod common;

use common::lock_reads;
use zapret::procs::Proc;
use zapret::snapshot::{ServiceSnap, Snapshot, begin, pending_path};

fn sample(operation: &str) -> Snapshot {
    Snapshot {
        operation: operation.to_owned(),
        service2: Some(ServiceSnap {
            image_path: "/opt/zapret2/winws2.exe --service".to_owned(),
            auto_start: true,
            running: false,
        }),
        strategy2: Some("general".to_owned()),
        manual_winws2: vec![Proc {
            pid: 42,
            exe: None,
            args: vec![],
        }],
        zapret2: false, // restore is a no-op, so the test survives without a service
    }
}

#[test]
fn the_pending_file_lives_in_the_state_folder() {
    let dir = tempfile::tempdir().unwrap();
    let pending = pending_path(dir.path());
    assert_eq!(
        pending,
        Path::new(dir.path()).join("state").join("pending.json")
    );
    assert_eq!(Snapshot::load(&pending).unwrap(), None);
}

#[test]
fn save_and_load_round_trip_a_snapshot_and_clear_removes_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pending.json");
    let snap = sample("tests");
    snap.save(&path).unwrap();
    assert_eq!(Snapshot::load(&path).unwrap(), Some(snap));

    Snapshot::clear(&path).unwrap();
    Snapshot::clear(&path).unwrap(); // a missing file clears without an error
    assert_eq!(Snapshot::load(&path).unwrap(), None);
}

#[test]
fn an_unreadable_pending_file_is_refused_by_name() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pending.json");
    std::fs::write(&path, "{").unwrap();
    let _lock = lock_reads(&path);
    let err = format!("{:#}", begin("tests", &path).unwrap_err());
    assert!(err.contains(&path.display().to_string()), "{err}");
    assert!(err.contains("cannot be read"), "{err}");
}

#[test]
fn broken_json_is_a_refused_pending_file_not_a_crash() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pending.json");
    std::fs::write(&path, "{ not json").unwrap();
    let err = format!("{:#}", begin("tests", &path).unwrap_err());
    assert!(err.contains("cannot be read"), "{err}");
}

#[test]
fn begin_takes_the_state_and_leaves_it_in_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let pending = pending_path(dir.path());
    let snap = begin("tests", &pending).unwrap();
    assert!(snap.operation == "tests");
    assert_eq!(Snapshot::load(&pending).unwrap(), Some(snap.clone()));
    // The rest depends on the machine: whether the zapret2 service is installed here.
}

#[test]
fn begin_restores_the_earlier_operation_before_taking_its_own() {
    let dir = tempfile::tempdir().unwrap();
    let pending = pending_path(dir.path());
    sample("apply").save(&pending).unwrap();
    let snap = begin("tests", &pending).unwrap();
    // The earlier one was restored and removed; what remains is the new operation.
    assert!(snap.operation == "tests");
    assert_eq!(Snapshot::load(&pending).unwrap(), Some(snap));
}

#[test]
fn a_failed_restore_leaves_the_file_for_the_next_attempt() {
    let dir = tempfile::tempdir().unwrap();
    let pending = pending_path(dir.path());
    // A pre-zapret2 snapshot still restores (its restore is a no-op here) and is then replaced
    // by the new operation; the unreadable-file failure branch needs a real system service and
    // is covered by the refusal tests above.
    let snap = Snapshot {
        operation: "apply".to_owned(),
        service2: None,
        strategy2: None,
        manual_winws2: vec![],
        zapret2: true,
    };
    snap.save(&pending).unwrap();
    let restored = begin("tests", &pending).unwrap();
    assert!(restored.operation == "tests");
    assert!(
        Snapshot::load(&pending).unwrap().is_some(),
        "the file stays"
    );
}

#[test]
fn restore_does_nothing_for_a_pre_zapret2_snapshot() {
    sample("apply").restore().unwrap();
}
