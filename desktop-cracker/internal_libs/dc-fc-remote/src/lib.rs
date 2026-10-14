//! **Remote X on the Firecracker path**.
//!
//! The project's other guest-initiated service is the same shape: the guest dials a
//! port, the host accepts a connection, and a small forwarder runs over it.
//! Before this machine the host's listener was an **`AF_VSOCK` socket** (the machine's `vhost-vsock` made
//! one possible); Firecracker has no such thing, and its host side of a guest-initiated
//! connection is a **unix socket named after the port** (`<uds_path>_<port>`) — which is
//! [`dc_vsock::Service`]'s job.
//!
//! So this crate is the *seam*, and nothing more: it owns the listener (`1026`)
//! and hands each accepted connection to something that knows what to do with it.  What it does
//! **not** do is re-implement the service: the connection is a
//! [`std::os::unix::net::UnixStream`] on both paths, so the X forwarding is the project's own
//! code, untouched.
//!
//! Remote X needs a **new thread per connection** (an X client's session is its own), which is
//! the acceptor it is given.
//!
//! ```text
//! guest ── vsock 1026 ──▶ <uds>_1026 ──▶ this crate ──▶ dc-xremote's forwarder ──▶ the X socket
//! ```

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use dc_common::milestone;
use dc_vsock::{Service, VsockError};

/// What a service does with one connection: the whole of what this crate knows about it.
pub trait Accept: Send + Sync {
    /// Handle one connection until it ends.  The connection is a unix socket on this path and
    /// was one before this machine too, so nothing above this trait changed.
    fn accept(&self, stream: std::os::unix::net::UnixStream);
}

/// One listener, one service: the ports a run answers.
pub struct Endpoint {
    service: Service,
    accept: Arc<dyn Accept>,
    connected: Arc<AtomicBool>,
    /// Connections accepted, for the run's own counters.
    connections: Arc<AtomicU64>,
    /// Told to stop: the run is over, or a test is finished.  A blocking `accept` would leave
    /// the thread waiting for a guest that is never coming (`dc-xremote`'s own listener polls
    /// for exactly this reason), so this is what the loop checks.
    stop: Arc<AtomicBool>,
    name: String,
}

impl Endpoint {
    /// Bind `port` for `accept`, **before the machine starts** — the project's rule for every
    /// channel: a guest that dials a port nobody listens on gets a
    /// reset, and the failure looks like a guest that never came up.
    pub fn bind(
        uds_path: &std::path::Path,
        port: u32,
        name: &str,
        accept: Arc<dyn Accept>,
    ) -> Result<Endpoint, VsockError> {
        Ok(Endpoint {
            service: Service::bind(uds_path, port)?,
            accept,
            connected: Arc::new(AtomicBool::new(false)),
            connections: Arc::new(AtomicU64::new(0)),
            stop: Arc::new(AtomicBool::new(false)),
            name: name.to_string(),
        })
    }

    pub fn port(&self) -> u32 {
        self.service.port()
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// How many connections the guest has made since the run started.
    pub fn connections(&self) -> u64 {
        self.connections.load(Ordering::Relaxed)
    }

    /// Whether a connection is being served right now.
    pub fn connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    /// Ask the loop to stop: the run is over, and a listener that is still waiting for a guest
    /// must not hold the thread that serves it.
    pub fn shutdown(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    /// Serve, one connection after another, until the endpoint is shut down.
    ///
    /// The accept is **non-blocking with a short wait**, and that is the project's own shape for
    /// a listener whose owner may want to end (`dc-xremote`'s forwarder polls for the same
    /// reason): a thread stuck in `accept` is a thread that outlives the run.
    pub fn serve(&self) -> Result<(), VsockError> {
        let _ = self.service.set_nonblocking(true);
        loop {
            if self.stop.load(Ordering::Relaxed) {
                return Ok(());
            }
            let stream = match self.service.accept() {
                Ok(stream) => stream,
                Err(VsockError::Io { ref source, .. })
                    if source.kind() == std::io::ErrorKind::WouldBlock =>
                {
                    // Nobody is dialling right now: the moment the shutdown flag is checked.
                    std::thread::sleep(std::time::Duration::from_millis(20));
                    continue;
                }
                Err(_) => {
                    // The listener itself is gone: the run is over.
                    return Ok(());
                }
            };
            self.connections.fetch_add(1, Ordering::Relaxed);
            milestone!(
                "channel: {} — the guest connected ({} connection(s) so far)",
                self.name,
                self.connections.load(Ordering::Relaxed)
            );
            self.connected.store(true, Ordering::Relaxed);
            self.accept.accept(stream);
            self.connected.store(false, Ordering::Relaxed);
        }
    }
}

/// The two endpoints of one run, in the order the port map lists them.
pub struct Endpoints {
    endpoints: Vec<Arc<Endpoint>>,
}

impl Endpoints {
    /// One endpoint per service that asked for one.
    pub fn listen(
        uds_path: &std::path::Path,
        wanted: Vec<(u32, &str, Arc<dyn Accept>)>,
    ) -> Result<Endpoints, VsockError> {
        let mut endpoints = Vec::with_capacity(wanted.len());
        for (port, name, accept) in wanted {
            endpoints.push(Arc::new(Endpoint::bind(uds_path, port, name, accept)?));
        }
        Ok(Endpoints { endpoints })
    }

    pub fn endpoints(&self) -> &[Arc<Endpoint>] {
        &self.endpoints
    }

    /// Serve every endpoint on a thread of its own: each is independent of the others. The
    /// threads hold their own endpoint
    /// (`Arc`), so nothing here is tied to how long the set is kept — and
    /// [`Endpoints::shutdown`] is what ends them.
    pub fn serve_in_background(&self) -> Vec<std::thread::JoinHandle<()>> {
        self.endpoints
            .iter()
            .map(|endpoint| {
                let endpoint = endpoint.clone();
                std::thread::spawn(move || {
                    let _ = endpoint.serve();
                })
            })
            .collect()
    }

    /// Ask every endpoint to stop, and wait for the threads: what a run does when it is over.
    pub fn shutdown(&self, threads: Vec<std::thread::JoinHandle<()>>) {
        for endpoint in &self.endpoints {
            endpoint.shutdown();
        }
        for thread in threads {
            let _ = thread.join();
        }
    }
}

/// **Remote X**: a connection becomes a session with the host's X server, on a thread of its own
/// (an X client's session is its own, and two clients must not wait for each other).
///
/// The forwarding itself is `dc-xremote`'s — this only says *when*: one thread per connection,
/// which is what the forwarder's own accept loop did.
pub struct ForwardTo {
    /// The X socket to pass a connection to (`dc-xremote`'s `Forwarder::target`).
    target: std::path::PathBuf,
}

impl ForwardTo {
    pub fn new(target: impl Into<std::path::PathBuf>) -> ForwardTo {
        ForwardTo {
            target: target.into(),
        }
    }
}

impl Accept for ForwardTo {
    fn accept(&self, stream: std::os::unix::net::UnixStream) {
        let target = self.target.clone();
        let _ = std::thread::spawn(move || {
            // A host with no X server at that socket has nothing to forward to: the connection
            // is dropped and the guest's client sees its own error.  (This is `dc-xremote`'s
            // own rule, and its own reason.)
            if let Ok(server) = std::os::unix::net::UnixStream::connect(&target) {
                pump(stream, server);
            }
        });
    }
}

/// Copy bytes both ways until either end closes — the same pump the forwarder already uses.
fn pump(a: std::os::unix::net::UnixStream, b: std::os::unix::net::UnixStream) {
    use std::io::{Read, Write};
    let Ok(mut a_read) = a.try_clone() else {
        return;
    };
    let Ok(mut b_read) = b.try_clone() else {
        return;
    };
    let mut a_write = a;
    let mut b_write = b;
    let up = std::thread::spawn(move || {
        let mut buffer = [0u8; 16 * 1024];
        loop {
            match b_read.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if a_write.write_all(&buffer[..n]).is_err() {
                        break;
                    }
                }
            }
        }
        let _ = a_write.shutdown(std::net::Shutdown::Both);
    });
    let mut buffer = [0u8; 16 * 1024];
    loop {
        match a_read.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if b_write.write_all(&buffer[..n]).is_err() {
                    break;
                }
            }
        }
    }
    let _ = b_write.shutdown(std::net::Shutdown::Both);
    let _ = up.join();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::sync::Mutex;

    /// A service that remembers what it was given, so the test asserts on the **seam**.
    #[derive(Default)]
    struct Recorder {
        seen: Mutex<Vec<Vec<u8>>>,
    }

    impl Accept for Recorder {
        fn accept(&self, mut stream: std::os::unix::net::UnixStream) {
            let mut buffer = Vec::new();
            let _ = stream.read_to_end(&mut buffer);
            self.seen.lock().unwrap().push(buffer);
        }
    }

    #[test]
    fn a_listener_answers_for_its_port_and_hands_the_connection_over() {
        let dir = tempfile::tempdir().unwrap();
        let recorder = Arc::new(Recorder::default());
        let endpoints = Arc::new(
            Endpoints::listen(
                &dir.path().join("v.sock"),
                vec![(
                    dc_vsock::ports::REMOTE_X,
                    "remote X",
                    recorder.clone() as Arc<dyn Accept>,
                )],
            )
            .unwrap(),
        );
        let port = endpoints.endpoints()[0].port();
        assert_eq!(port, dc_vsock::ports::REMOTE_X);
        let threads = endpoints.serve_in_background();
        // A guest dials the port, says something, and goes away.
        let mut guest = std::os::unix::net::UnixStream::connect(dc_vsock::listener_path(
            &dir.path().join("v.sock"),
            port,
        ))
        .unwrap();
        guest
            .write_all(b"the first thing an X client says")
            .unwrap();
        guest.flush().unwrap();
        drop(guest);
        for _ in 0..200 {
            if !recorder.seen.lock().unwrap().is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(
            recorder.seen.lock().unwrap()[0],
            b"the first thing an X client says"
        );
        assert_eq!(endpoints.endpoints()[0].connections(), 1);
        // The listener is still there for the next client: a session is not the run.
        let mut second = std::os::unix::net::UnixStream::connect(dc_vsock::listener_path(
            &dir.path().join("v.sock"),
            port,
        ))
        .unwrap();
        second.write_all(b"and a second").unwrap();
        second.flush().unwrap();
        drop(second);
        for _ in 0..200 {
            if recorder.seen.lock().unwrap().len() >= 2 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(recorder.seen.lock().unwrap().len(), 2);
        assert_eq!(endpoints.endpoints()[0].connections(), 2);
        endpoints.shutdown(threads);
    }

    #[test]
    fn a_forwarder_passes_a_connection_to_the_x_socket_and_both_ways() {
        let dir = tempfile::tempdir().unwrap();
        // Something that stands in for the host's X server: it answers what it is told.
        let x = dir.path().join("X0");
        let server = std::os::unix::net::UnixListener::bind(&x).unwrap();
        let echo = std::thread::spawn(move || {
            let (mut stream, _) = server.accept().unwrap();
            let mut buffer = [0u8; 64];
            let n = stream.read(&mut buffer).unwrap();
            stream.write_all(&buffer[..n]).unwrap();
            stream.flush().unwrap();
        });

        let endpoints = Arc::new(
            Endpoints::listen(
                &dir.path().join("v.sock"),
                vec![(
                    dc_vsock::ports::REMOTE_X,
                    "remote X",
                    Arc::new(ForwardTo::new(&x)) as Arc<dyn Accept>,
                )],
            )
            .unwrap(),
        );
        let port = endpoints.endpoints()[0].port();
        let threads = endpoints.serve_in_background();
        let mut guest = std::os::unix::net::UnixStream::connect(dc_vsock::listener_path(
            &dir.path().join("v.sock"),
            port,
        ))
        .unwrap();
        guest
            .set_read_timeout(Some(std::time::Duration::from_millis(2000)))
            .unwrap();
        guest.write_all(b"a request to the X server").unwrap();
        guest.flush().unwrap();
        let mut answer = [0u8; 64];
        let n = guest.read(&mut answer).unwrap();
        assert_eq!(&answer[..n], b"a request to the X server");
        drop(guest);
        let _ = echo.join();
        endpoints.shutdown(threads);
    }

    #[test]
    fn a_host_with_no_x_server_drops_the_connection_and_keeps_the_listener() {
        let dir = tempfile::tempdir().unwrap();
        let endpoints = Arc::new(
            Endpoints::listen(
                &dir.path().join("v.sock"),
                vec![(
                    dc_vsock::ports::REMOTE_X,
                    "remote X",
                    Arc::new(ForwardTo::new(dir.path().join("no-such-X"))) as Arc<dyn Accept>,
                )],
            )
            .unwrap(),
        );
        let port = endpoints.endpoints()[0].port();
        let threads = endpoints.serve_in_background();
        let guest = std::os::unix::net::UnixStream::connect(dc_vsock::listener_path(
            &dir.path().join("v.sock"),
            port,
        ))
        .unwrap();
        drop(guest);
        // The listener answered the connection and is still there for the next one.
        for _ in 0..200 {
            if endpoints.endpoints()[0].connections() == 1 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(endpoints.endpoints()[0].connections(), 1);
        assert!(
            !endpoints.endpoints()[0].connected(),
            "the connection is over"
        );
        endpoints.shutdown(threads);
    }

    #[test]
    fn every_endpoint_is_its_own_port_and_its_own_thread() {
        let dir = tempfile::tempdir().unwrap();
        let audio = Arc::new(Recorder::default());
        let x = Arc::new(Recorder::default());
        let endpoints = Arc::new(
            Endpoints::listen(
                &dir.path().join("v.sock"),
                vec![
                    (
                        dc_vsock::ports::AUDIO,
                        "the audio channel",
                        audio.clone() as Arc<dyn Accept>,
                    ),
                    (
                        dc_vsock::ports::REMOTE_X,
                        "remote X",
                        x.clone() as Arc<dyn Accept>,
                    ),
                ],
            )
            .unwrap(),
        );
        assert_eq!(endpoints.endpoints()[0].port(), dc_vsock::ports::AUDIO);
        assert_eq!(endpoints.endpoints()[1].port(), dc_vsock::ports::REMOTE_X);
        // And the ports are the project's own numbers: the guest's tools look for them.
        assert_eq!(dc_vsock::ports::AUDIO, 55000);
        assert_eq!(dc_vsock::ports::REMOTE_X, 1026);
        let threads = endpoints.serve_in_background();
        let mut guest = std::os::unix::net::UnixStream::connect(dc_vsock::listener_path(
            &dir.path().join("v.sock"),
            dc_vsock::ports::AUDIO,
        ))
        .unwrap();
        guest.write_all(b"the first frame").unwrap();
        guest.flush().unwrap();
        drop(guest);
        for _ in 0..200 {
            if !audio.seen.lock().unwrap().is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(audio.seen.lock().unwrap()[0], b"the first frame");
        assert!(
            x.seen.lock().unwrap().is_empty(),
            "the other port heard nothing"
        );
        endpoints.shutdown(threads);
    }
}
