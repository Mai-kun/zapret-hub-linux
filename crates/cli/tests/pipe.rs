//! The socket in one process, without elevation: a socket made by the current user changes
//! nothing in the system and goes away with the test.

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use cli::pipe::{self, Server};

const BUSY: Duration = Duration::from_secs(10);

/// Tests run in parallel: a name each.
fn unique() -> String {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    format!(
        "/tmp/zapret-hub-cli-test-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    )
}

fn serve(name: &str, handler: impl Fn(&[u8]) -> String + Send + Sync + 'static) {
    let server = Server::bind(name).unwrap();
    std::thread::spawn(move || server.serve(handler));
}

#[test]
fn a_client_gets_the_answer_to_its_line() {
    let name = unique();
    serve(&name, |line| String::from_utf8_lossy(line).to_uppercase());
    assert_eq!(pipe::request(&name, b"hello", BUSY).unwrap(), b"HELLO");
    assert_eq!(
        pipe::request(&name, "ещё".as_bytes(), BUSY).unwrap(),
        "ЕЩЁ".as_bytes(),
        "one connection per request"
    );
}

#[test]
fn a_second_server_cannot_take_the_name() {
    let name = unique();
    let _first = Server::bind(&name).unwrap();
    let Err(second) = Server::bind(&name) else {
        panic!("the lock file let a second server in");
    };
    assert_eq!(second.raw_os_error(), Some(13), "{second}");
}

#[test]
fn no_server_means_file_not_found() {
    let err = pipe::request(&unique(), b"{}", BUSY).unwrap_err();
    assert_eq!(err.raw_os_error(), Some(2), "{err}");
}

#[test]
fn a_slow_client_does_not_hold_up_the_others() {
    let name = unique();
    serve(&name, |line| {
        if line == b"slow" {
            std::thread::sleep(Duration::from_secs(2));
        }
        String::from_utf8_lossy(line).into_owned()
    });
    let slow = {
        let name = name.clone();
        std::thread::spawn(move || pipe::request(&name, b"slow", BUSY).unwrap())
    };
    std::thread::sleep(Duration::from_millis(300));
    let started = Instant::now();
    assert_eq!(pipe::request(&name, b"fast", BUSY).unwrap(), b"fast");
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(slow.join().unwrap(), b"slow");
}

#[test]
fn a_client_that_leaves_before_its_answer_does_not_stop_the_server() {
    use std::io::Write as _;

    let name = unique();
    serve(&name, |line| {
        std::thread::sleep(Duration::from_millis(300));
        String::from_utf8_lossy(line).into_owned()
    });
    let mut gone = std::os::unix::net::UnixStream::connect(&name).unwrap();
    gone.write_all(b"bye\n").unwrap();
    drop(gone);
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(
        pipe::request(&name, b"still here", BUSY).unwrap(),
        b"still here"
    );
}

#[test]
fn a_line_its_client_never_finished_reaches_no_handler() {
    use std::io::Write as _;
    use std::sync::mpsc;

    let name = unique();
    let (ran, lines) = mpsc::channel();
    serve(&name, move |line| {
        let _ = ran.send(line.to_vec());
        String::new()
    });
    // The server waits in accept by now, so it does read what the client wrote.
    std::thread::sleep(Duration::from_millis(300));
    let mut gone = std::os::unix::net::UnixStream::connect(&name).unwrap();
    gone.write_all(b"x").unwrap();
    drop(gone);
    assert_eq!(
        lines.recv_timeout(Duration::from_millis(500)),
        Err(mpsc::RecvTimeoutError::Timeout),
        "a line without its \\n ran"
    );
    pipe::request(&name, b"y", BUSY).unwrap();
    assert_eq!(lines.recv().unwrap(), b"y", "a whole line still runs");
}

#[test]
fn an_app_that_closes_without_an_answer_is_an_unexpected_eof() {
    let name = unique();
    serve(&name, |_| panic!("the handler fails"));
    let err = pipe::request(&name, b"{}", BUSY).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof, "{err}");
}

#[test]
fn an_oversized_line_is_cut_and_still_answered() {
    let name = unique();
    serve(&name, |line| line.len().to_string());
    let line = vec![b'a'; cli::MAX_REQUEST + 100_000];
    assert_eq!(
        pipe::request(&name, &line, BUSY).unwrap(),
        (cli::MAX_REQUEST + 1).to_string().as_bytes()
    );
}

#[test]
fn the_descriptor_names_this_user() {
    let sid = pipe::current_user_sid().unwrap();
    assert!(sid.starts_with("S-1-5-"), "{sid}");
    assert_eq!(
        pipe::sddl(&sid),
        format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;{sid})S:(ML;;NWNR;;;ME)")
    );
}

#[test]
fn the_socket_only_this_user_may_reach() {
    use std::os::unix::fs::PermissionsExt as _;

    let name = unique();
    serve(&name, |_| String::new());
    let mode = std::fs::metadata(&name).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600, "rwx for the owner only, got {mode:o}");
}
