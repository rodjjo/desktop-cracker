//! **The plugin's HTTP and WebSocket server**: what the plugin's own contract describes, and
//! nothing else.
//!
//! It binds `127.0.0.1:$DESK_PLUGIN_PORT` — loopback only, never `0.0.0.0` — and serves
//! these things:
//!
//! | method | path | what it answers |
//! |---|---|---|
//! | GET | `/status` | the run's state and counters, and the microVM's vCPU pinning |
//! | GET | `/pin` | the pinning frame as CSV (`cpu,vcpu`), for a script that wants a table |
//! | POST | `/frame` | the frame the window is about to draw, as `image/png` (`409` before one) |
//! | WS | `/ws` | events down, answers up |
//!
//! A connection is one thread of its own, and the application never waits for it: the outgoing
//! queue is bounded and a client that falls behind it is dropped (and counted in `/status`).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::sync::mpsc::{sync_channel, TryRecvError};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use sha1::{Digest, Sha1};
use tungstenite::protocol::{Role, WebSocket};
use tungstenite::Message;

use serde_json::Value;

use crate::state::{Answer, Shared, PROTOCOL};

/// How many events may be queued for one client before it is considered too slow to serve.
const CLIENT_QUEUE: usize = 256;

/// How long a request head may take to arrive, and how long a socket write may take.
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a client thread waits before looking at its own state again.
const IDLE_POLL_MS: i32 = 100;

/// The plugin's server: the port it bound and the clients it feeds.
pub struct Server {
    shared: Arc<Shared>,
    stopping: Arc<std::sync::atomic::AtomicBool>,
}

/// Print a CPU list the way the kernel does, collapsing runs (`0-11`).  The plugin has no
/// `dc-common` to borrow it from (it is loaded *into* the application, not linked with it),
/// so it is four lines here.
fn format_cpu_list(cpus: &[u64]) -> String {
    let mut out = String::new();
    let mut i = 0;
    while i < cpus.len() {
        let start = cpus[i];
        let mut end = start;
        while i + 1 < cpus.len() && cpus[i + 1] == end + 1 {
            i += 1;
            end = cpus[i];
        }
        if !out.is_empty() {
            out.push(',');
        }
        if start == end {
            out.push_str(&start.to_string());
        } else {
            out.push_str(&format!("{start}-{end}"));
        }
        i += 1;
    }
    out
}

/// The pinning frame, as JSON.  The CPU list is printed the way the kernel prints one
/// (`0-11`), because that is what a person compares against `taskset`/`/proc`.
fn pinning_json(info: Option<&dc_plugin::PinningInfo>) -> Value {
    let info = match info {
        Some(i) => i,
        None => return serde_json::json!({"format": 0}),
    };
    let cpus: Vec<u64> = info.cpus[..info.cpus_len as usize]
        .iter()
        .map(|c| *c as u64)
        .collect();
    serde_json::json!({
        "format": info.format,
        "cpus": cpus,
        "cpus_list": format_cpu_list(&cpus),
        "vcpus": info.vcpus,
        "vcpus_pinned": info.vcpus_pinned,
        "host_cores": info.host_cores,
    })
}

impl Server {
    /// Bind the port the plugin was given and start serving.  The listeners are threads of their
    /// own; the application is never served inline.
    pub fn start(
        shared: Arc<Shared>,
        port: u16,
        stopping: Arc<std::sync::atomic::AtomicBool>,
    ) -> std::io::Result<Arc<Server>> {
        let listener = TcpListener::bind(("127.0.0.1", port))?;
        let server = Arc::new(Server { shared, stopping });
        let accepting = server.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if accepting
                    .stopping
                    .load(std::sync::atomic::Ordering::Relaxed)
                {
                    break;
                }
                let Ok(stream) = stream else { continue };
                let server = accepting.clone();
                std::thread::spawn(move || {
                    let _ = server.handle(stream);
                });
            }
        });
        Ok(server)
    }

    fn handle(&self, stream: TcpStream) -> std::io::Result<()> {
        let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
        let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
        let mut reader = BufReader::new(stream.try_clone()?);

        let Some(request) = read_request(&mut reader) else {
            return Ok(());
        };

        if request.path == "/ws" {
            // **One client**, and it is whoever got here first: a plugin serves a test, and a
            // second client would be a second answer to the same question.
            if self.shared.has_client() {
                let mut out = stream;
                let body = b"the plugin already has a client\n";
                let head = format!(
                    "HTTP/1.1 409 Conflict\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                out.write_all(head.as_bytes())?;
                out.write_all(body)?;
                return out.flush();
            }
            return self.websocket(stream, &request);
        }

        let (code, kind, body) = match (request.method.as_str(), request.path.as_str()) {
            ("GET", "/status") => (200, "application/json", self.status()),
            // **The pinning frame as CSV**: the one thing a study cannot read from a
            // milestone, for a script that wants a table (`cpu,vcpu` rows).  It is the same
            // fact `/status` reports, in the shape a shell wants.
            ("GET", "/pin") => (200, "text/csv", self.pin_csv()),
            ("POST", "/frame") => match self.frame_png() {
                Some(png) => (200, "image/png", png),
                None => (409, "text/plain", b"nothing has been drawn yet".to_vec()),
            },
            ("POST", "/action") => match self.action(&request.body) {
                Some(0) => (200, "application/json", b"{\"ran\":true}".to_vec()),
                Some(code) => (
                    200,
                    "application/json",
                    format!("{{\"ran\":false,\"code\":{code}}}").into_bytes(),
                ),
                None => (400, "text/plain", b"no action named\n".to_vec()),
            },
            _ => (
                404,
                "text/plain",
                b"try /status, /pin, /frame, /action, /ws\n".to_vec(),
            ),
        };

        let mut out = stream;
        let head = format!(
            "HTTP/1.1 {code} {}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            if code == 200 { "OK" } else { "Error" },
            body.len()
        );
        out.write_all(head.as_bytes())?;
        out.write_all(&body)?;
        out.flush()
    }

    fn status(&self) -> Vec<u8> {
        let counters = self.shared.counters();
        // **Where the microVM's vCPUs are pinned**: the fact, not the milestone.  A run with no
        // pinning reports `{"format":0}` rather than nothing, so a client can tell "not pinned"
        // from "the application does not answer".
        let pinning = self.shared.pull_pinning();
        serde_json::to_vec(&serde_json::json!({
            "protocol": PROTOCOL,
            "app": crate::APP_NAME,
            "version": crate::APP_VERSION,
            "pid": std::process::id(),
            "state": self.shared.state().as_str(),
            "frames": counters.frames,
            "dropped": self.shared.dropped(),
            "width": counters.width,
            "height": counters.height,
            "visible": counters.visible != 0,
            "numlock": counters.numlock != 0,
            "waiting": self.shared.waiting(),
            "damage_waiting": counters.damage_waiting,
            "damage_oldest_ms": counters.damage_oldest_ms,
            "pinning": pinning_json(pinning.as_ref()),
        }))
        .unwrap_or_default()
    }

    /// The pinning frame as CSV: one row per vCPU that has a core of its own.
    fn pin_csv(&self) -> Vec<u8> {
        let info = self.shared.pull_pinning();
        let mut out = String::from("cpu,vcpu\n");
        let Some(info) = info else {
            return out.into_bytes();
        };
        for (vcpu, cpu) in info.cpus[..info.cpus_len as usize].iter().enumerate() {
            if (vcpu as u32) < info.vcpus {
                out.push_str(&format!("{cpu},{vcpu}\n"));
            }
        }
        out.into_bytes()
    }

    /// The frame the window is about to draw, as a PNG.
    ///
    /// The **application** copies the pixels out (it owns them); the encoding is the plugin's,
    /// which is why `png` is this crate's dependency and not the application's.
    fn frame_png(&self) -> Option<Vec<u8>> {
        let needed = self
            .shared
            .pull_frame(std::ptr::null_mut(), 0, std::ptr::null_mut());
        if needed == 0 {
            return None;
        }
        let mut buffer = vec![0u8; needed];
        let mut info = dc_plugin::FrameInfo::default();
        let written = self
            .shared
            .pull_frame(buffer.as_mut_ptr(), buffer.len(), &mut info);
        if written == 0 || info.width == 0 || info.height == 0 {
            return None;
        }
        buffer.truncate(written);
        encode_png(&buffer, info)
    }

    /// The WebSocket half: the handshake here, then one thread owning the socket.
    fn websocket(&self, mut stream: TcpStream, request: &Request) -> std::io::Result<()> {
        let Some(key) = request.header("sec-websocket-key") else {
            stream.write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")?;
            return Ok(());
        };
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
            accept_key(&key)
        );
        stream.write_all(response.as_bytes())?;
        stream.flush()?;

        let (tx, rx) = sync_channel::<serde_json::Value>(CLIENT_QUEUE);
        self.shared.add_client(tx);

        let shared = self.shared.clone();
        let stopping = self.stopping.clone();
        std::thread::spawn(move || {
            let _ = serve_client(stream, rx, shared, stopping);
        });
        Ok(())
    }
}

/// One client, from the hello to the close: events out, answers in.
fn serve_client(
    stream: TcpStream,
    rx: std::sync::mpsc::Receiver<serde_json::Value>,
    shared: Arc<Shared>,
    stopping: Arc<std::sync::atomic::AtomicBool>,
) -> std::io::Result<()> {
    let mut socket = WebSocket::from_raw_socket(stream, Role::Server, None);

    loop {
        if stopping.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }
        // Everything the bus has for this client, as fast as it arrives.
        let mut sent_anything = false;
        loop {
            match rx.try_recv() {
                Ok(event) => {
                    let text = event.to_string();
                    if socket.send(Message::Text(text.into())).is_err() {
                        return Ok(());
                    }
                    sent_anything = true;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return Ok(()),
            }
        }
        // Wait for something from the client (an answer, a ping, a close).  `poll` rather than a
        // blocking read, because this thread also has to keep sending.
        let mut pfd = libc::pollfd {
            fd: socket.get_ref().as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ready =
            unsafe { libc::poll(&mut pfd, 1, if sent_anything { 0 } else { IDLE_POLL_MS }) };
        if ready <= 0 {
            continue;
        }
        match socket.read() {
            Ok(Message::Text(text)) => handle_answer(&text, &shared),
            Ok(Message::Close(_)) | Err(_) => break,
            Ok(_) => {}
        }
    }
    let _ = socket.close(None);
    let _ = socket.flush();
    Ok(())
}

/// One answer from a client: `{"answer":{...},"id":"N"}`, or `{"answer":null,"id":"N"}` for
/// "I cannot answer this one".
fn handle_answer(text: &str, shared: &Arc<Shared>) {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return;
    };
    let Some(id) = value
        .get("id")
        .and_then(|i| i.as_str())
        .and_then(|i| i.parse::<u64>().ok())
    else {
        return;
    };
    let answer = match value.get("answer") {
        // `null` is the client saying "no answer": the application falls back to its own dialog,
        // and the user takes as long as they like.
        Some(serde_json::Value::Null) | None => None,
        Some(serde_json::Value::Object(fields)) => {
            if let Some(password) = fields.get("password").and_then(|p| p.as_str()) {
                Some(Answer::Password(zeroize::Zeroizing::new(
                    password.to_string(),
                )))
            } else {
                fields
                    .get("confirm")
                    .and_then(|c| c.as_bool())
                    .map(Answer::Confirm)
            }
        }
        _ => None,
    };
    shared.answer(id, answer);
}

/// `Sec-WebSocket-Accept`: `base64(sha1(key + the protocol's GUID))`.
fn accept_key(key: &str) -> String {
    const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(GUID.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
}

/// Turn a frame in the guest's own layout (BGRA in memory) into an `image/png`.
fn encode_png(bgra: &[u8], info: dc_plugin::FrameInfo) -> Option<Vec<u8>> {
    let (w, h) = (info.width as usize, info.height as usize);
    let stride = if info.stride == 0 {
        w * 4
    } else {
        info.stride as usize
    };
    let mut rgb = Vec::with_capacity(w * h * 3);
    for y in 0..h {
        let start = y * stride;
        let end = (start + w * 4).min(bgra.len());
        if start >= end {
            break;
        }
        for px in bgra[start..end].chunks_exact(4) {
            rgb.extend_from_slice(&[px[2], px[1], px[0]]);
        }
    }
    if rgb.len() < w * h * 3 {
        return None;
    }
    let mut out = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut out, info.width, info.height);
        encoder.set_color(png::ColorType::Rgb);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header().ok()?;
        writer.write_image_data(&rgb).ok()?;
    }
    Some(out)
}

impl Server {
    /// **Run one of the window's own actions** (the plugin's own contract, the `action`
    /// hook): `{"action":"hide-or-show"}`.  The application is asked to run it — the plugin never
    /// acts on the run itself — and its answer says whether it ran.
    fn action(&self, body: &[u8]) -> Option<std::os::raw::c_int> {
        let text = std::str::from_utf8(body).ok()?;
        let value: serde_json::Value = serde_json::from_str(text).ok()?;
        let name = value.get("action")?.as_str()?;
        self.shared.run_action(name)
    }
}

/// The parts of a request head this server needs.
struct Request {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    /// The body, when the request has one (`POST /action`).
    body: Vec<u8>,
}

impl Request {
    fn header(&self, name: &str) -> Option<String> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    }
}

/// Read one request head (the request line and the headers).
fn read_request(reader: &mut BufReader<TcpStream>) -> Option<Request> {
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    let mut headers = Vec::new();
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).ok()? == 0 {
            break;
        }
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
    }
    // A body, when the request says how long it is: `POST /action` carries one, and a body left
    // unread would be read as the next request.
    let mut body = Vec::new();
    let length: usize = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    if length > 0 {
        let mut buffer = vec![0u8; length.min(64 * 1024)];
        let mut read = 0;
        while read < buffer.len() {
            match reader.read(&mut buffer[read..]) {
                Ok(0) | Err(_) => break,
                Ok(n) => read += n,
            }
        }
        body = buffer[..read].to_vec();
    }
    Some(Request {
        method,
        path,
        headers,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The arithmetic every WebSocket implementation checks itself against (RFC 6455 §1.3).
    #[test]
    fn the_accept_key_is_the_protocols_own_arithmetic() {
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    /// The guest's frame reaches a client as an RGB PNG, not as raw bytes and not upside down.
    #[test]
    fn a_frame_in_the_guests_layout_becomes_a_png() {
        // Two pixels of BGRA: opaque red, then opaque green.
        let bgra = [0u8, 0, 255, 255, 0, 255, 0, 255];
        let info = dc_plugin::FrameInfo {
            data: std::ptr::null(),
            width: 2,
            height: 1,
            stride: 8,
        };
        let png = encode_png(&bgra, info).expect("a PNG");
        assert!(png.starts_with(&[0x89, b'P', b'N', b'G']), "a PNG header");
    }
}
