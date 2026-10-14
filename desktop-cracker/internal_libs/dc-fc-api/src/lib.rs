//! **The Firecracker API client.**
//!
//! Firecracker has no command line for the machine it runs and no QMP: the
//! machine is *defined* by HTTP requests on the unix socket it was started with
//! (`--api-sock`), and started by one more of them.  This crate is that client
//! and nothing else — a deliberately small thing, because it is the control
//! plane only (measured on this host, 2026-10-09: a whole definition is seven
//! requests and 1.0 ms; `InstanceStart` itself is 22 ms; *data* never travels
//! here, that is what `virtio-vsock` is for).
//!
//! Two details of the API are the ones a caller gets wrong:
//!
//! * **it is a real HTTP/1.1 server**, so a request is a request line, a
//!   `Content-Type`, a `Content-Length` and a body, and the answer is a status
//!   and a JSON body — `PUT`/`GET`/`PATCH`, never `POST` (a `POST` is answered
//!   with "Invalid HTTP Method");
//! * **an unknown field is an error, not something ignored** (VMM's serde is
//!   `deny_unknown_fields`): a drive with a `serial` — which a conventional virtio-blk
//!   has and Firecracker's does not — is a `400` with a sentence, so the structs
//!   here name exactly what the API takes and nothing else.
//!
//! The client is one connection per request.  The API is a control plane that
//! answers in microseconds and this process owns the socket: keeping a
//! connection alive would buy a handful of microseconds and cost a state
//! machine, and a request that does not answer is a machine that did not start.
//!
//! What talks to the socket sits behind [`Wire`], so the unit tests drive every
//! method against a stub and never need Firecracker or a unix socket at all.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

pub mod model;

pub use model::*;

/// What can go wrong while talking to the API.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("the Firecracker API socket: {0}")]
    Transport(#[from] std::io::Error),
    #[error("the Firecracker API did not answer {call} in time")]
    Timeout { call: String },
    #[error("Firecracker refused {call}: {message}")]
    Refused { call: String, message: String },
    #[error("Firecracker answered {call} with something that is not the API's JSON: {detail}")]
    Malformed { call: String, detail: String },
}

pub type Result<T> = std::result::Result<T, ApiError>;

/// The socket the API is on, and how a request is carried.
///
/// One implementation, [`SocketWire`], talks to a real Firecracker; the tests
/// supply their own, which is the whole point of the trait.
pub trait Wire: Send + Sync {
    /// One request: the method, the path, and the body as JSON (or none).
    /// The answer is the status and the body as text — exactly what the API
    /// answers.
    fn request(
        &mut self,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> std::io::Result<(u16, String)>;
}

/// The API's own socket, one connection per request.
pub struct SocketWire {
    path: PathBuf,
    timeout: Duration,
    patience: Duration,
}

impl SocketWire {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        SocketWire {
            path: path.into(),
            timeout: Duration::from_secs(5),
            // Short, and only for the `EAGAIN` of a socket between `bind` and
            // `listen`: a refusal, which is what a socket nobody listens on
            // gives, is not waited on at all.
            patience: Duration::from_millis(250),
        }
    }

    /// How long a request may take before the socket is given up on.  The API
    /// answers in microseconds; a request that does not is a Firecracker that is
    /// not there, and the caller should be told rather than waited for.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// Connect to the API socket, tolerating the moment Firecracker is between
/// `bind` and `listen`.
///
/// Measured on this host (2026-10-09): `bind` and `listen` are two steps, and a
/// connect into that window fails with `EAGAIN` ("Resource temporarily
/// unavailable") rather than with a refusal — which is a *transient* error that
/// looks like a permanent one.  A few milliseconds of patience is the honest
/// answer, and the deadline is short enough that a firewall or a socket nobody
/// listens on is still reported at once.
pub fn connect_api(path: &Path, patience: Duration) -> std::io::Result<UnixStream> {
    let deadline = std::time::Instant::now() + patience;
    loop {
        match UnixStream::connect(path) {
            Ok(stream) => return Ok(stream),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if std::time::Instant::now() >= deadline {
                    return Err(e);
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(e) => return Err(e),
        }
    }
}

impl Wire for SocketWire {
    fn request(
        &mut self,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> std::io::Result<(u16, String)> {
        let mut stream = connect_api(&self.path, self.patience)?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;
        stream.write_all(&request_bytes(method, path, body))?;
        stream.flush()?;
        let raw = read_answer(&mut stream, self.timeout)?;
        Ok(parse_response(&raw))
    }
}

/// Read one answer off the API socket.
///
/// **Not `read_to_end`.**  Firecracker answers `Connection: close` with
/// `Connection: keep-alive` and keeps the socket open (measured on this host,
/// 2026-10-09), so a client that reads until the peer hangs up waits for a close
/// that never comes and then reports its own read timeout as a failure.  The
/// answer is read for what it is: headers to the blank line, then exactly
/// `Content-Length` bytes (or to end of stream when it does not say).  The
/// timeout is a bound on the *waiting*, not the way the read ends.
pub fn read_answer(stream: &mut impl Read, timeout: Duration) -> std::io::Result<Vec<u8>> {
    let mut raw: Vec<u8> = Vec::with_capacity(512);
    let mut buf = [0u8; 4096];
    let mut body_left: Option<usize> = None;
    let started = std::time::Instant::now();
    loop {
        // Everything the answer has already given us: is it complete?
        if let Some(left) = body_left {
            if raw.len() >= left {
                return Ok(raw);
            }
        }
        if std::time::Instant::now().duration_since(started) > timeout {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "the API did not answer in time",
            ));
        }
        let n = match stream.read(&mut buf) {
            Ok(0) => return Ok(raw), // the peer did close: the answer is what it gave
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            // A socket with a read timeout reports the wait as `WouldBlock` or
            // `TimedOut` depending on the platform and the call; both mean "no
            // answer yet", which is what the deadline above is for.  A real
            // failure (a closed peer, a broken socket) is still reported as it is.
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue
            }
            Err(e) => return Err(e),
        };
        raw.extend_from_slice(&buf[..n]);
        if body_left.is_none() {
            if let Some(head) = header_end(&raw) {
                body_left = Some(head + content_length(&raw[..head]));
            }
        }
    }
}

/// Where the headers end: the offset of the blank line, plus four.
pub fn header_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|at| at + 4)
}

/// The `Content-Length` a header block declares, or 0 when it says nothing.
pub fn content_length(head: &[u8]) -> usize {
    let text = String::from_utf8_lossy(head);
    for line in text.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("content-length") {
            return value.trim().parse().unwrap_or(0);
        }
    }
    0
}

/// The bytes of one request: an HTTP/1.1 request with a JSON body.
///
/// `Connection: close` is deliberate: this client reads the answer to its end,
/// and a server that keeps the connection open would leave it reading forever.
pub fn request_bytes(method: &str, path: &str, body: Option<&str>) -> Vec<u8> {
    let body = body.unwrap_or("");
    let mut out = String::new();
    out.push_str(&format!("{method} {path} HTTP/1.1\r\n"));
    out.push_str("Host: localhost\r\n");
    out.push_str("Accept: application/json\r\n");
    if !body.is_empty() {
        out.push_str("Content-Type: application/json\r\n");
    }
    out.push_str(&format!("Content-Length: {}\r\n", body.len()));
    out.push_str("Connection: close\r\n\r\n");
    out.push_str(body);
    out.into_bytes()
}

/// The status and body of an answer, as far as this client cares.
///
/// The body is the part after the blank line, as text: the API's answers are
/// small JSON documents, and the one a person reads in an error is the
/// `fault_message` inside them (parsed by [`message_of`], not by the caller).
pub fn parse_response(raw: &[u8]) -> (u16, String) {
    let text = String::from_utf8_lossy(raw);
    let status = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);
    let body = match text.find("\r\n\r\n") {
        Some(at) => text[at + 4..].to_string(),
        None => String::new(),
    };
    (status, body)
}

/// The sentence inside an error answer: `{"fault_message": "…"}` in every shape
/// the API uses (`fault_message`, and the older bare-string form).
pub fn message_of(body: &str) -> String {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return "(no message)".into();
    }
    if let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(trimmed) {
        if let Some(serde_json::Value::String(s)) = map.get("fault_message") {
            return s.clone();
        }
        if let Some(serde_json::Value::String(s)) = map.get("error") {
            return s.clone();
        }
    }
    if let Ok(serde_json::Value::String(s)) = serde_json::from_str::<serde_json::Value>(trimmed) {
        return s;
    }
    trimmed.to_string()
}

/// The client.  Holds the wire, counts what it did (which is what a milestone
/// line and a test both want to see) and turns every refusal into one sentence.
pub struct Api {
    wire: Box<dyn Wire>,
    calls: usize,
}

impl Api {
    /// Talk to the API socket at `path`.
    pub fn connect(path: impl AsRef<Path>) -> Api {
        Api::over(Box::new(SocketWire::new(path.as_ref().to_path_buf())))
    }

    /// Talk over whatever the caller has — the seam the tests use.
    pub fn over(wire: Box<dyn Wire>) -> Api {
        Api { wire, calls: 0 }
    }

    /// How many requests this client has made: the definition of a machine is a
    /// handful, and a milestone line says how many.
    pub fn calls(&self) -> usize {
        self.calls
    }

    fn text(&mut self, method: &str, path: &str, body: Option<String>) -> Result<String> {
        let call = format!("{method} {path}");
        self.calls += 1;
        let (status, body) = self.wire.request(method, path, body.as_deref())?;
        match status {
            200..=299 => Ok(body),
            0 => Err(ApiError::Malformed {
                call,
                detail: "no HTTP status in the answer".into(),
            }),
            _ => Err(ApiError::Refused {
                call,
                message: message_of(&body),
            }),
        }
    }

    /// One request that carries a JSON body and returns nothing.
    fn put<T: Serialize>(&mut self, path: &str, body: &T) -> Result<()> {
        self.send("PUT", path, body)
    }

    /// One **partial** update: the API takes it as `PATCH`, and a `PUT` of the same
    /// path is a different request with a different body (measured 2026-10-09: a
    /// `PUT /balloon` with only `amount_mib` is refused with
    /// "missing field `deflate_on_oom`" — the balloon's `PUT` defines the device, and
    /// the `PATCH` moves it).
    fn patch<T: Serialize>(&mut self, path: &str, body: &T) -> Result<()> {
        self.send("PATCH", path, body)
    }

    fn send<T: Serialize>(&mut self, method: &str, path: &str, body: &T) -> Result<()> {
        let json = serde_json::to_string(body).map_err(|e| ApiError::Malformed {
            call: path.into(),
            detail: e.to_string(),
        })?;
        self.text(method, path, Some(json))?;
        Ok(())
    }

    fn get<T: for<'d> Deserialize<'d>>(&mut self, path: &str) -> Result<T> {
        let body = self.text("GET", path, None)?;
        if body.trim().is_empty() {
            return Err(ApiError::Malformed {
                call: path.into(),
                detail: "an empty body".into(),
            });
        }
        serde_json::from_str(&body).map_err(|e| ApiError::Malformed {
            call: path.into(),
            detail: e.to_string(),
        })
    }

    // ---- defining the machine ------------------------------------------------

    /// The kernel, its initramfs and the kernel's own command line.
    pub fn put_boot_source(&mut self, boot: &BootSource) -> Result<()> {
        self.put("/boot-source", boot)
    }

    /// vCPUs, memory, SMT, the CPU template and huge pages.
    pub fn put_machine_config(&mut self, machine: &MachineConfiguration) -> Result<()> {
        self.put("/machine-config", machine)
    }

    /// One block device.  The first one is the root; the rest are `/dev/vdb`…
    /// in the order they are configured.
    pub fn put_drive(&mut self, drive: &Drive) -> Result<()> {
        self.put(&format!("/drives/{}", drive.drive_id), drive)
    }

    /// The guest's network interface.  Firecracker's only backend is a tap.
    pub fn put_network_interface(&mut self, iface: &NetworkInterface) -> Result<()> {
        self.put(&format!("/network-interfaces/{}", iface.iface_id), iface)
    }

    /// The virtio-vsock device: one device, and the unix socket the host's end
    /// of every port is named after (`<uds_path>_<port>`).
    pub fn put_vsock(&mut self, vsock: &Vsock) -> Result<()> {
        self.put("/vsock", vsock)
    }

    /// Whether the machine has a balloon at all, and where it starts.
    pub fn put_balloon(&mut self, balloon: &Balloon) -> Result<()> {
        self.put("/balloon", balloon)
    }

    /// Where the balloon goes now.  This is the one request the memory policy makes
    /// while the machine runs, and it is a **`PATCH`**: the balloon's `PUT` defines the
    /// device (and needs every field of it), while a `PATCH` moves the target.
    pub fn patch_balloon(&mut self, amount_mib: u64) -> Result<()> {
        self.patch("/balloon", &BalloonUpdate { amount_mib })
    }

    /// What the guest says about its own memory right now.
    pub fn balloon_stats(&mut self) -> Result<BalloonStats> {
        self.get("/balloon/statistics")
    }

    /// The virtio-rng device: free, native, and the guest's `systemd` is happier
    /// for it.
    pub fn put_entropy(&mut self) -> Result<()> {
        self.put("/entropy", &serde_json::json!({}))
    }

    /// A region of memory the guest can plug and unplug (virtio-mem).  The
    /// balloon reclaims; this one *changes how much the guest has*.
    pub fn put_memory_hotplug(&mut self, hotplug: &MemoryHotplug) -> Result<()> {
        self.put("/hotplug/memory", hotplug)
    }

    /// Start the machine.  After this the definition is frozen: a drive, the
    /// boot source and the machine's shape can no longer be added.
    pub fn start(&mut self) -> Result<()> {
        self.put(
            "/actions",
            &Action {
                action_type: "InstanceStart".into(),
            },
        )
    }

    /// Ask the guest to power off, through its own power button.  The process
    /// then exits by itself.
    pub fn send_ctrl_alt_del(&mut self) -> Result<()> {
        self.put(
            "/actions",
            &Action {
                action_type: "SendCtrlAltDel".into(),
            },
        )
    }

    /// Write the metrics out now, rather than at the interval.
    pub fn flush_metrics(&mut self) -> Result<()> {
        self.put(
            "/actions",
            &Action {
                action_type: "FlushMetrics".into(),
            },
        )
    }

    /// The instance's own report.  The path is `/` — Firecracker has no
    /// `/instance-info`, and it says so with a `400` (measured 2026-10-09).
    pub fn instance_info(&mut self) -> Result<InstanceInfo> {
        self.get("/")
    }

    /// The VMM's version, as the API reports it.
    pub fn version(&mut self) -> Result<Version> {
        self.get("/version")
    }

    /// Is the machine running yet?  `InstanceInfo::state` is `Not started`,
    /// `Running` or `Paused`.
    pub fn state(&mut self) -> Result<String> {
        Ok(self.instance_info()?.state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// What a stub was asked: method, path, body.
    type Calls = Arc<Mutex<Vec<(String, String, Option<String>)>>>;

    /// A wire that answers from a script and remembers what it was asked.
    struct Stub {
        answers: Vec<(u16, String)>,
        seen: Calls,
    }

    impl Stub {
        fn scripted(answers: Vec<(u16, String)>) -> (Api, Calls) {
            let seen = Arc::new(Mutex::new(Vec::new()));
            let stub = Stub {
                answers,
                seen: seen.clone(),
            };
            (Api::over(Box::new(stub)), seen)
        }
    }

    impl Wire for Stub {
        fn request(
            &mut self,
            method: &str,
            path: &str,
            body: Option<&str>,
        ) -> std::io::Result<(u16, String)> {
            self.seen.lock().unwrap().push((
                method.to_string(),
                path.to_string(),
                body.map(|b| b.to_string()),
            ));
            if self.answers.is_empty() {
                return Ok((204, String::new()));
            }
            Ok(self.answers.remove(0))
        }
    }

    fn answered(status: u16, body: &str) -> (Api, Calls) {
        Stub::scripted(vec![(status, body.to_string())])
    }

    #[test]
    fn a_request_is_an_http_1_1_request_with_the_body_length() {
        let raw =
            String::from_utf8(request_bytes("PUT", "/boot-source", Some("{\"a\":1}"))).unwrap();
        assert!(raw.starts_with("PUT /boot-source HTTP/1.1\r\n"), "{raw}");
        assert!(raw.contains("Content-Type: application/json\r\n"));
        assert!(raw.contains("Content-Length: 7\r\n"), "{raw}");
        assert!(raw.ends_with("\r\n\r\n{\"a\":1}"), "{raw}");
    }

    #[test]
    fn a_request_without_a_body_carries_no_content_type() {
        let raw = String::from_utf8(request_bytes("GET", "/", None)).unwrap();
        assert!(raw.contains("Content-Length: 0\r\n"), "{raw}");
        assert!(!raw.contains("Content-Type"), "{raw}");
    }

    #[test]
    fn the_answer_is_split_at_its_blank_line() {
        let (status, body) =
            parse_response(b"HTTP/1.1 204 No Content\r\nServer: Firecracker\r\n\r\n");
        assert_eq!(status, 204);
        assert_eq!(body, "");
        let (status, body) = parse_response(
            b"HTTP/1.1 400 Bad Request\r\n\r\n{\"fault_message\":\"Drive config error\"}",
        );
        assert_eq!(status, 400);
        assert_eq!(body, "{\"fault_message\":\"Drive config error\"}");
    }

    #[test]
    fn an_answer_without_an_http_status_is_reported_as_malformed_not_as_a_code() {
        let (mut api, _) = answered(0, "");
        let err = api.version().unwrap_err();
        assert!(matches!(err, ApiError::Malformed { .. }), "{err:?}");
        assert!(err.to_string().contains("not the API's JSON"), "{err}");
    }

    #[test]
    fn a_refused_request_is_one_sentence_with_the_fault_message() {
        let (mut api, seen) = answered(
            400,
            "{\"fault_message\":\"Invalid HTTP Method: Unsupported HTTP method.\"}",
        );
        let err = api.send_ctrl_alt_del().unwrap_err();
        assert_eq!(
            err.to_string(),
            "Firecracker refused PUT /actions: Invalid HTTP Method: Unsupported HTTP method."
        );
        // The path is the one the API has, not the one a caller might guess.
        assert_eq!(seen.lock().unwrap()[0].1, "/actions");
    }

    #[test]
    fn the_instance_report_is_read_from_the_root_path() {
        let (mut api, seen) = answered(
            200,
            "{\"app_name\":\"Firecracker\",\"id\":\"anonymous-instance\",\
             \"state\":\"Running\",\"vmm_version\":\"1.17.0\"}",
        );
        let info = api.instance_info().unwrap();
        assert_eq!(info.state, "Running");
        assert_eq!(info.vmm_version, "1.17.0");
        assert_eq!(seen.lock().unwrap()[0].1, "/");
    }

    #[test]
    fn a_machine_is_defined_by_one_request_per_thing_that_exists() {
        let (mut api, seen) = Stub::scripted(vec![]);
        api.put_boot_source(&BootSource {
            kernel_image_path: "/k/vmlinux".into(),
            initrd_path: Some("/k/initramfs.gz".into()),
            boot_args: Some("console=ttyS0".into()),
        })
        .unwrap();
        api.put_machine_config(&MachineConfiguration {
            vcpu_count: 12,
            mem_size_mib: 6144,
            smt: Some(false),
            cpu_template: None,
            track_dirty_pages: None,
            huge_pages: None,
        })
        .unwrap();
        api.put_drive(&Drive {
            drive_id: "rootfs".into(),
            path_on_host: "/d/root.raw".into(),
            is_root_device: true,
            is_read_only: false,
            cache_type: Some("Unsafe".into()),
            io_engine: Some("Sync".into()),
            partuuid: None,
            socket: None,
            blk_size: None,
            rate_limiter: None,
        })
        .unwrap();
        api.put_vsock(&Vsock {
            guest_cid: 3,
            uds_path: "/r/v.sock".into(),
        })
        .unwrap();
        api.put_entropy().unwrap();
        api.start().unwrap();
        let seen = seen.lock().unwrap();
        let paths: Vec<&str> = seen.iter().map(|c| c.1.as_str()).collect();
        assert_eq!(
            paths,
            vec![
                "/boot-source",
                "/machine-config",
                "/drives/rootfs",
                "/vsock",
                "/entropy",
                "/actions"
            ]
        );
        assert_eq!(api.calls(), 6);
    }

    #[test]
    fn a_drive_carries_no_serial_because_the_api_refuses_fields_it_does_not_know() {
        let json = serde_json::to_string(&Drive {
            drive_id: "d".into(),
            path_on_host: "/p".into(),
            is_root_device: false,
            is_read_only: true,
            cache_type: None,
            io_engine: None,
            partuuid: None,
            socket: None,
            blk_size: None,
            rate_limiter: None,
        })
        .unwrap();
        assert!(!json.contains("serial"), "{json}");
        assert!(json.contains("\"is_read_only\":true"), "{json}");
    }

    #[test]
    fn the_balloon_is_read_from_the_statistics_endpoint_and_written_to_the_device() {
        let (mut api, seen) = answered(
            200,
            "{\"target_pages\":1048576,\"actual_pages\":82688,\"target_mib\":4096,\
             \"actual_mib\":323,\"free_memory\":6154436608,\"total_memory\":6193389568}",
        );
        let stats = api.balloon_stats().unwrap();
        assert_eq!(stats.target_mib, 4096);
        assert_eq!(stats.actual_mib, 323);
        assert_eq!(stats.free_memory, Some(6154436608));
        assert_eq!(seen.lock().unwrap()[0].1, "/balloon/statistics");

        let (mut api, seen) = Stub::scripted(vec![]);
        api.patch_balloon(2048).unwrap();
        let seen = seen.lock().unwrap();
        assert_eq!(
            seen[0].0, "PATCH",
            "the balloon's PUT defines the device; moving it is a PATCH"
        );
        assert_eq!(seen[0].1, "/balloon");
        assert_eq!(seen[0].2.as_deref(), Some("{\"amount_mib\":2048}"));
    }

    #[test]
    fn the_vsock_device_names_the_cid_and_the_socket_the_ports_hang_off() {
        let (mut api, seen) = Stub::scripted(vec![]);
        api.put_vsock(&Vsock {
            guest_cid: 7,
            uds_path: "/run/desktop-cracker/v.sock".into(),
        })
        .unwrap();
        let seen = seen.lock().unwrap();
        assert_eq!(seen[0].1, "/vsock");
        assert_eq!(
            seen[0].2.as_deref(),
            Some("{\"guest_cid\":7,\"uds_path\":\"/run/desktop-cracker/v.sock\"}")
        );
    }

    #[test]
    fn connecting_to_a_socket_between_bind_and_listen_is_patience_not_a_failure() {
        // The transient error the real thing gives: nobody is listening yet.
        // `std` cannot leave a socket half-bound, so what is asserted here is the
        // patience itself — a path that does not exist is reported at once, and a
        // listener that is there is connected to at once.
        let dir = tempfile::tempdir().unwrap();
        let none = dir.path().join("none.sock");
        let started = std::time::Instant::now();
        assert!(connect_api(&none, Duration::from_millis(250)).is_err());
        assert!(
            started.elapsed() < Duration::from_millis(100),
            "a path that is not there is not waited on"
        );

        let there = dir.path().join("there.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&there).unwrap();
        assert!(connect_api(&there, Duration::from_millis(250)).is_ok());
    }

    #[test]
    fn an_answer_is_read_by_its_content_length_and_not_to_the_end_of_the_stream() {
        // The measured shape: Firecracker answers `Connection: close` with
        // `Connection: keep-alive` and keeps the socket open.  Reading to the end
        // of the stream would wait for a close that never comes; the answer is
        // read for the length it declares, and the rest of the stream is left.
        let answer = b"HTTP/1.1 200 \r\nServer: Firecracker API\r\nConnection: keep-alive\r\
                      \nContent-Type: application/json\r\nContent-Length: 32\r\n\r\n\
                      {\"firecracker_version\":\"1.17.0\"}"
            .to_vec();
        // A reader that never ends: it gives the answer and then blocks.  A
        // correct reader returns before asking for more.
        struct NeverEnds {
            data: Vec<u8>,
            at: usize,
        }
        impl std::io::Read for NeverEnds {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.at < self.data.len() {
                    let n = (self.data.len() - self.at).min(buf.len());
                    buf[..n].copy_from_slice(&self.data[self.at..self.at + n]);
                    self.at += n;
                    return Ok(n);
                }
                Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "would block",
                ))
            }
        }
        let mut reader = NeverEnds {
            data: answer.clone(),
            at: 0,
        };
        let raw = read_answer(&mut reader, Duration::from_millis(200)).unwrap();
        assert_eq!(raw, answer);
        let (status, body) = parse_response(&raw);
        assert_eq!(status, 200);
        assert!(body.contains("1.17.0"), "{body}");
    }

    #[test]
    fn an_answer_with_no_body_is_an_answer_too() {
        // A `PUT` that worked: 204 and nothing after the headers.
        let answer = b"HTTP/1.1 204 \r\nServer: Firecracker API\r\nConnection: keep-alive\r\
                      \nContent-Length: 0\r\n\r\n"
            .to_vec();
        let mut reader = std::io::Cursor::new(answer.clone());
        let raw = read_answer(&mut reader, Duration::from_millis(200)).unwrap();
        assert_eq!(parse_response(&raw), (204, String::new()));
    }

    #[test]
    fn an_answer_whose_length_is_missing_ends_at_the_end_of_the_stream() {
        let answer = b"HTTP/1.1 200 \r\n\r\nhello";
        let mut reader = std::io::Cursor::new(answer.to_vec());
        let raw = read_answer(&mut reader, Duration::from_millis(200)).unwrap();
        assert_eq!(parse_response(&raw), (200, "hello".to_string()));
        assert_eq!(content_length(header_of(answer)), 0);
    }

    fn header_of(raw: &[u8]) -> &[u8] {
        &raw[..header_end(raw).unwrap()]
    }

    #[test]
    fn the_header_block_is_found_and_its_length_read_whatever_the_case() {
        let raw = b"HTTP/1.1 200 \r\ncontent-length: 5\r\n\r\nhello";
        let head = header_end(raw).unwrap();
        assert_eq!(&raw[head..], b"hello");
        assert_eq!(content_length(&raw[..head]), 5);
        assert_eq!(content_length(b"HTTP/1.1 200 \r\n\r\n"), 0);
    }

    #[test]
    fn an_api_that_never_answers_is_a_timeout_and_not_a_hang() {
        struct Silent;
        impl std::io::Read for Silent {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "would block",
                ))
            }
        }
        let started = std::time::Instant::now();
        let err = read_answer(&mut Silent, Duration::from_millis(50)).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert!(started.elapsed() >= Duration::from_millis(40));
    }

    #[test]
    fn a_socket_that_is_not_there_is_a_transport_error_not_a_refusal() {
        // The API socket of a machine that is not running: the caller has to be
        // able to tell "Firecracker said no" from "Firecracker is not there".
        let dir = tempfile::tempdir().unwrap();
        let mut api = Api::connect(dir.path().join("nothing.sock"));
        let err = api.start().unwrap_err();
        assert!(matches!(err, ApiError::Transport(_)), "{err:?}");
        assert!(err.to_string().contains("API socket"), "{err}");
    }

    #[test]
    fn a_malformed_answer_to_a_typed_call_says_which_call_it_was() {
        let (mut api, _) = answered(200, "not json at all");
        let err = api.balloon_stats().unwrap_err();
        assert!(matches!(err, ApiError::Malformed { .. }), "{err:?}");
        assert!(err.to_string().contains("/balloon/statistics"), "{err}");
    }

    #[test]
    fn an_empty_answer_to_a_typed_call_is_malformed_rather_than_a_default() {
        let (mut api, _) = answered(200, "");
        let err = api.instance_info().unwrap_err();
        assert!(err.to_string().contains("an empty body"), "{err}");
    }
}
