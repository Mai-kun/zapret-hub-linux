use router::tcp;
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::{
    Arc, atomic::{AtomicBool, Ordering::SeqCst},
};
use std::time::{Duration, Instant};

fn pair() -> (TcpStream, TcpStream) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
    (c, l.accept().unwrap().0)
}

#[test]
fn pipe_copies_until_eof_and_counts() {
    let ((mut app, hub_in), (hub_out, mut far)) = (pair(), pair());
    let worker = std::thread::spawn(move || {
        let mut n = 0;
        tcp::pipe(&hub_in, &hub_out, &|| false, &mut |b| n += b).unwrap();
        n
    });
    app.write_all(b"hello").unwrap();
    app.shutdown(Shutdown::Write).unwrap();
    let mut got = Vec::new();
    far.read_to_end(&mut got).unwrap();
    assert_eq!((got.as_slice(), worker.join().unwrap()), (&b"hello"[..], 5));
}

#[test]
fn pipe_ends_when_the_session_stops() {
    let ((_app, hub_in), (hub_out, _far)) = (pair(), pair());
    let stop = Arc::new(AtomicBool::new(false));
    let s = stop.clone();
    let worker =
        std::thread::spawn(move || tcp::pipe(&hub_in, &hub_out, &|| s.load(SeqCst), &mut |_| {}));
    stop.store(true, SeqCst);
    let started = Instant::now();
    worker.join().unwrap().unwrap();
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[test]
fn reset_sends_an_rst() {
    let (mut app, hub) = pair();
    tcp::reset(hub);
    assert_eq!(
        app.read(&mut [0u8; 1]).unwrap_err().kind(),
        ErrorKind::ConnectionReset
    );
}
