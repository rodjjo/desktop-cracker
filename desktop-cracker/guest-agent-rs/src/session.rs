//! **The guest's own session** (`desk-agent.c`'s `session`), in Rust.
//!
//! Two callers ask for it, and they ask for different halves of the C agent's `session`:
//!
//! * **the initramfs' own init** already has the run's files, the way out and the modules (they are
//!   the shell's own lines in the guest's init, and they stay: that is the guest's init, not this
//!   program).  It calls `session --initramfs`, which brings the **screen, the sound, the shares and
//!   the network** up — the four things only a program can own — and the session's own command;
//! * **the system on the disk** (whose own `desk-agent.service` runs `session`) has none of
//!   that: it calls `session`, which does the whole of the C agent's session — the run's files over
//!   the control channel, the way out before anything that can block, the modules, the screen, the
//!   sound, the shares, the network, the `DESK-READY` line the run waits for — and stays.
//!
//! Nothing here prints anything a person does not need: the same milestone lines the C agent said.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::channel;
use crate::control::{self, Answer};

/// Where the run's files live once they are fetched (the control share's own directory).
pub const CONTROL_DIR: &str = control::CONTROL_DIR;

/// Everything a session needs to know about itself, from its own command line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionPlan {
    /// The file the system watches for a power-off request.
    pub watch: Option<String>,
    /// **The initramfs' own caller**: the run's files and the modules are already done, so this
    /// brings up the screen, the sound, the shares and the network and nothing else.
    pub initramfs: bool,
    /// The network's own devices, when they were named on the command line.
    pub network: Vec<String>,
    /// What to run once the guest is up, if the caller named a command.
    pub command: Vec<String>,
}

impl SessionPlan {
    /// The plan a `session` command line names.
    ///
    /// The C agent took its network from a file (`/run/desktop-cracker/network`); this takes it from
    /// either — the switches here, or that file, which is what the guest's own init writes.
    pub fn parse(args: &[String]) -> SessionPlan {
        let mut plan = SessionPlan::default();
        let mut i = 0;
        while i < args.len() {
            let value = |i: &mut usize| -> Option<String> {
                *i += 1;
                args.get(*i).cloned()
            };
            match args[i].as_str() {
                "--watch" => plan.watch = value(&mut i),
                "--initramfs" => plan.initramfs = true,
                flag @ ("--iface" | "--guest" | "--prefix" | "--gateway" | "--mtu") => {
                    if let Some(value) = value(&mut i) {
                        plan.network.push(flag.to_string());
                        plan.network.push(value);
                    }
                }
                "--" => {
                    plan.command = args[i + 1..].to_vec();
                    break;
                }
                other => {
                    // The first word that is not a switch is the command's own.
                    if !other.starts_with("--") {
                        plan.command = args[i..].to_vec();
                        break;
                    }
                }
            }
            i += 1;
        }
        plan
    }
}

/// **`control <name>…`**: fetch each name and write it where the guest's own tools read it.
///
/// A name the run does not offer is said and skipped: the C agent's own
/// `desk-agent: the host has no <name>`, which is a run without that thing and not a failure.
pub fn do_control(names: &[&str]) -> i32 {
    let _ = std::fs::create_dir_all(CONTROL_DIR);
    let mut code = 0;
    for name in names {
        match control::read(name) {
            Ok(Answer::Data(bytes)) if !bytes.is_empty() => {
                let path = Path::new(CONTROL_DIR).join(name);
                let mode = if control::is_secret(name) { 0o600 } else { 0o644 };
                if let Err(e) = write_private(&path, &bytes, mode) {
                    crate::console::note(&format!("deskd: {name}: {e}"));
                    code = 1;
                }
            }
            Ok(_) => crate::console::say(&format!("deskd: the host has no {name}")),
            Err(e) => {
                crate::console::note(&format!("deskd: {name}: {e}"));
                code = 1;
            }
        }
    }
    code
}

/// **`job`**: the run's secrets over the control channel, and then the guest's own disk tool.
///
/// It is the whole difference between the project's disk job on its own path and this one: there
/// the secrets were a 9P share mounted at `/run/desktop-cracker`, here they are fetched by name from the
/// host and written to that same directory, so `guest-tools diskmgr` finds exactly what it always
/// found.  The names are the job's own, and a name the run did not offer is skipped.
pub fn do_job() -> i32 {
    let _ = std::fs::create_dir_all(CONTROL_DIR);
    let names: Vec<&str> = vec!["disk.secret", "disk.secret.new", "diskplan"];
    let _ = do_control(&names);
    // The guest's own tool does the work, exactly as it does on the project's other path.
    let tool = "/bin/guest-tools";
    match Command::new(tool).arg("diskmgr").status() {
        Ok(status) => status.code().unwrap_or(0),
        Err(e) => {
            crate::console::note(&format!("deskd: cannot run the disk tool: {e}"));
            1
        }
    }
}

/// Write a file with a mode, and nothing else (the passphrase is root's alone).
fn write_private(path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(path)?;
    file.write_all(bytes)
}

/// Start a child of **this** binary in the background (the C agent's `spawn_bg`): the screen, the
/// sound and the shutdown watcher are separate processes of the same program.
///
/// **And it is waited for**, on a thread of its own, so that a service that ends is *said*.  The C
/// agent's `spawn_bg` never waited, which is two problems: a child that exits becomes a zombie for
/// as long as the session lives, and — worse — **a screen whose client has died is a screen nobody
/// hears about** (measured 2026-10-11: the frame stream stopped and the session said nothing at
/// all).  What a person needs from a guest is exactly this line, and it is the same shape as every
/// other milestone here.
pub fn spawn_background(args: &[String]) -> std::io::Result<u32> {
    let self_path = std::env::current_exe()?;
    let mut child = Command::new(self_path)
        .args(args)
        .stdin(Stdio::null())
        .spawn()?;
    let pid = child.id();
    let what = args.first().cloned().unwrap_or_default();
    let rest = args[1..].join(" ");
    std::thread::spawn(move || {
        let status = child.wait();
        let said = match status {
            Ok(status) => match status.code() {
                Some(code) => format!("exit code {code}"),
                None => format!("killed by signal {}", signal_of(&status)),
            },
            Err(e) => format!("{e}"),
        };
        crate::console::say(&format!(
            "DESK-SESSION the {what} service (pid {pid}, {rest}) ended: {said}"
        ));
    });
    Ok(pid)
}

/// The signal a child was killed by, from its own wait status (the low seven bits of a signaled
/// status are the signal's number).
#[cfg(unix)]
fn signal_of(status: &std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status.signal().unwrap_or(0)
}

/// Run a command and answer its trimmed first line (the C agent's `run_line`).
pub fn run_line(command: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(command).args(args).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

/// `modprobe` over the tree the guest's `rootboot` copied into this root.
pub fn modprobe(module: &str, params: Option<&str>) -> bool {
    let mut command = Command::new("modprobe");
    command.arg(module);
    if let Some(params) = params {
        command.arg(params);
    }
    command
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// The kernel's own release (`rootboot` and the modules key on it).
pub fn kernel_release() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// The guest's memory, in kB, as the `DESK-READY` line reports it.
pub fn mem_total_kb() -> u64 {
    let Ok(text) = std::fs::read_to_string("/proc/meminfo") else {
        return 0;
    };
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            if let Some(number) = rest.split_whitespace().next() {
                return number.parse().unwrap_or(0);
            }
        }
    }
    0
}

/// The geometry the run decided, as the control channel published it: `<width> <height>`.
pub fn display_geometry() -> Option<(u32, u32)> {
    let text = std::fs::read_to_string(format!("{CONTROL_DIR}/display-geometry")).ok()?;
    let mut words = text.split_whitespace();
    let width = words.next()?.parse().ok()?;
    let height = words.next()?.parse().ok()?;
    Some((width, height))
}

/// **The screen**: the display client is started beside the module the run loaded, at the geometry
/// the run decided.  Its own process, so a client that ends does not take the session with it.
///
/// Answers the framebuffer's own name (`desk` when this project's module is loaded), which is
/// what tells the run the guest has a screen of its own.
pub fn bring_up_screen() -> Option<String> {
    let (width, height) = display_geometry()?;
    let name = std::fs::read_to_string("/sys/class/graphics/fb0/name")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    if name != "desk" {
        crate::console::say(&format!(
            "DESK-SESSION /dev/fb0 is not this project's own ({}): the guest has no screen",
            if name.is_empty() { "nothing" } else { &name }
        ));
        return None;
    }
    let args = vec!["display".to_string(), width.to_string(), height.to_string()];
    match spawn_background(&args) {
        Ok(pid) => {
            crate::console::say(&format!("DESK-SESSION the screen is the guest's own ({width}x{height}, pid {pid})"))
        }
        Err(e) => println!("DESK-SESSION the screen could not start: {e}"),
    }
    Some(name)
}

/// **The shares**: the run's plan, one line per folder (`tag port where ro|rw`), each served by the
/// FUSE filesystem this project's agent carries.
pub fn bring_up_shares() -> usize {
    let Ok(text) = std::fs::read_to_string(format!("{CONTROL_DIR}/shares")) else {
        return 0;
    };
    let mut started = 0;
    for (tag, port, where_, mode) in share_rows(&text) {
        // The mount point is the guest's own, and the plan says where.
        let _ = std::fs::create_dir_all(&where_);
        let args = vec![
            "share".to_string(),
            tag.to_string(),
            port.to_string(),
            where_.to_string(),
            mode.to_string(),
        ];
        match spawn_background(&args) {
            Ok(_) => {
                crate::console::say(&format!("DESK-SHARE {tag} on {where_} writable={}", mode != "ro"));
                started += 1;
            }
            Err(e) => crate::console::say(&format!("DESK-SHARE {tag}: {e}")),
        }
    }
    started
}

/// The plan's rows: `tag port where ro|rw`, in the order the run wrote them.
///
/// **A comment is not a share.** The plan's own header line (`dc-fc-share::plan`) starts with `#`
/// and names its columns; read as a row it is a share tagged `#` on port 0, which is the
/// `deskd: connect to port 0: Connection reset by peer` and the share service that ended with
/// exit code 1 on a run's console on 2026-10-12.  The C agent skipped such a line; this is the same
/// rule, and a row that does not have the four words is not a row either.
fn share_rows(text: &str) -> Vec<(String, String, String, String)> {
    let mut rows = Vec::new();
    for line in text.lines() {
        if line.trim_start().starts_with('#') {
            continue;
        }
        let mut words = line.split_whitespace();
        let (Some(tag), Some(port), Some(where_), Some(mode)) =
            (words.next(), words.next(), words.next(), words.next())
        else {
            continue;
        };
        rows.push((
            tag.to_string(),
            port.to_string(),
            where_.to_string(),
            mode.to_string(),
        ));
    }
    rows
}

/// **The network**: the guest's own `tun0` over the network channel, in its own process.
///
/// The switches come from the session's own command line or from the run's own file
/// (`/run/desktop-cracker/network`), which is what the C agent read.
pub fn bring_up_network(plan: &SessionPlan) {
    let mut args = vec!["net".to_string()];
    if plan.network.is_empty() {
        if let Ok(text) = std::fs::read_to_string(format!("{CONTROL_DIR}/network")) {
            args.extend(text.split_whitespace().map(|word| word.to_string()));
        }
    } else {
        args.extend(plan.network.iter().cloned());
    }
    if let Err(e) = spawn_background(&args) {
        crate::console::note(&format!("deskd: the network: {e}"));
    }
}

/// The memory's own line, as the readiness channel carries it: `DESK-READY <what> MemTotal=…kB …`.
pub fn ready_line(what: &str, extra: &str) -> String {
    format!("DESK-READY {what} MemTotal={}kB {extra}", mem_total_kb())
}

/// **The session**: everything the guest brings up, in one place.
///
/// It does not return until the session's own command has finished, and it answers that command's
/// own exit code (which is what the initramfs' caller ends the run with).
pub fn run(plan: SessionPlan) -> i32 {
    crate::console::say(&format!("DESK-SESSION the guest's side of the run"));

    // **The initramfs' caller has done the run's files, the way out and the modules already** (they
    // are the shell's own lines in the guest's init): what is left is the four things only a
    // program owns — the screen, the sound, the shares and the network.
    if plan.initramfs {
        let fb = bring_up_screen().unwrap_or_else(|| "none".to_string());
        let _ = spawn_background(&["audio".to_string()]);
        let shares = bring_up_shares();
        if shares == 0 {
            crate::console::say(&format!("DESK-SESSION no shared folder from the run"));
        }
        bring_up_network(&plan);
        crate::console::say(&format!("DESK-SESSION fb={fb} x=display"));
        return if plan.command.is_empty() {
            park()
        } else {
            run_command(&plan.command)
        };
    }

    // **The system on the disk's own session**: the whole of it, in the C agent's order.
    let names: Vec<&str> = control::CONTROL_FILES.to_vec();
    do_control(&names);

    // 2. **The way out, before anything else that can block.**  Firecracker has no ACPI power
    // management: the guest's own reboot pulse on the emulated keyboard is what ends the machine,
    // and the request for it comes over the shutdown channel or this file.
    let watch = plan
        .watch
        .clone()
        .unwrap_or_else(|| format!("{CONTROL_DIR}/poweroff"));
    if let Err(e) = spawn_background(&["shutdown".to_string(), "--watch".to_string(), watch]) {
        crate::console::note(&format!("deskd: the shutdown channel: {e}"));
    }

    // 3. **The modules**, in dependency order: the loopback sound card and this project's own
    // framebuffer (the geometry the run decided arrived with the run's files).
    modprobe("snd-aloop", None);
    match display_geometry() {
        Some((width, height)) => {
            modprobe("desk_fb", Some(&format!("width={width} height={height}")));
        }
        None => {
            modprobe("desk_fb", None);
        }
    }

    // 4. **The screen**, at the geometry the run decided, and the guest's own state beside it.
    let fb = bring_up_screen().unwrap_or_else(|| "none".to_string());
    let _ = std::fs::write(format!("{CONTROL_DIR}/fb"), format!("{fb}\n"));
    let _ = std::fs::write(format!("{CONTROL_DIR}/x"), "display\n");

    // 5. **The sound**, beside the screen.
    let _ = spawn_background(&["audio".to_string()]);

    // 6. **The shares**: the plan's own line per folder.
    let shares = bring_up_shares();
    if shares == 0 {
        crate::console::say(&format!("DESK-SESSION no shared folder from the run"));
    }

    // 7. **The network**: the guest's own tun0, on the channel.
    bring_up_network(&plan);

    // 8. **The guest is up**: the line a person reads on the console, and the same line as one
    // frame on the readiness channel — which is what the run waits for.
    let x = run_line(
        "timeout",
        &["3", "sh", "-c", "ls /tmp/.X11-unix 2>/dev/null | tr '\\n' ' '"],
    )
    .unwrap_or_else(|| "none".to_string());
    crate::console::say(&format!("DESK-SESSION fb={fb} x={x} kernel {}", kernel_release()));
    let ready = channel::ready(&ready_line("system", "agent=session"));
    if ready != 0 {
        return ready;
    }

    if plan.command.is_empty() {
        park()
    } else {
        run_command(&plan.command)
    }
}

/// Run the session's own command and answer its status.
fn run_command(command: &[String]) -> i32 {
    let mut child = Command::new(&command[0]);
    child.args(&command[1..]);
    match child.status() {
        Ok(status) => status.code().unwrap_or(0),
        Err(e) => {
            crate::console::note(&format!("deskd: {}: {e}", command[0]));
            127
        }
    }
}

/// **The session stays while the guest lives**: the screen and the sound it started are the two
/// that must keep running, and this process waits for the guest's own system to end it.
fn park() -> i32 {
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(words: &[&str]) -> Vec<String> {
        words.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_session_command_line_is_read_as_the_agent_reads_it() {
        let plan = SessionPlan::parse(&args(&[
            "--watch",
            "/run/desktop-cracker/poweroff",
            "--iface",
            "tun0",
            "--guest",
            "10.0.177.16/24",
            "--gateway",
            "10.0.177.1",
            "--mtu",
            "1500",
        ]));
        assert_eq!(plan.watch.as_deref(), Some("/run/desktop-cracker/poweroff"));
        assert_eq!(
            plan.network,
            [
                "--iface",
                "tun0",
                "--guest",
                "10.0.177.16/24",
                "--gateway",
                "10.0.177.1",
                "--mtu",
                "1500"
            ]
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>()
        );
        assert!(!plan.initramfs);
        assert!(plan.command.is_empty());
    }

    #[test]
    fn the_initramfs_caller_asks_for_its_own_half() {
        let plan = SessionPlan::parse(&args(&["--initramfs"]));
        assert!(plan.initramfs);
        assert!(plan.network.is_empty());
        assert!(plan.command.is_empty());
    }

    #[test]
    fn the_command_after_the_switches_is_the_sessions_own() {
        let plan = SessionPlan::parse(&args(&["--watch", "/p", "--initramfs", "rootboot"]));
        assert_eq!(plan.watch.as_deref(), Some("/p"));
        assert!(plan.initramfs);
        assert_eq!(plan.command, vec!["rootboot".to_string()]);
        let plan = SessionPlan::parse(&args(&["rootboot", "-x"]));
        assert_eq!(plan.command, vec!["rootboot".to_string(), "-x".to_string()]);
    }

    #[test]
    fn the_readiness_line_is_the_one_the_run_reads() {
        let line = ready_line("system", "agent=session");
        assert!(line.starts_with("DESK-READY system"), "{line}");
        assert!(line.contains("MemTotal="), "{line}");
        assert!(line.ends_with("agent=session"), "{line}");
    }

    /// The plan `dc-fc-share::plan` writes, with its header: the header is not a folder, and a
    /// guest that read it as one dialled port 0.
    #[test]
    fn the_shares_plan_s_header_is_not_a_share() {
        let plan = "# desktop-cracker shares: <tag> <port> <where> <ro|rw>\n\
                    docs 57001 /shared/docs rw\n\
                    # a note the run wrote\n\
                    media 57002 /shared/media ro\n";
        let rows = share_rows(plan);
        assert_eq!(rows.len(), 2, "{rows:?}");
        assert_eq!(rows[0].0, "docs");
        assert_eq!(rows[0].1, "57001");
        assert_eq!(rows[0].2, "/shared/docs");
        assert_eq!(rows[0].3, "rw");
        assert_eq!(rows[1].3, "ro");
        assert!(!rows.iter().any(|row| row.0 == "#" || row.1 == "0"), "{rows:?}");
        // A run with no share has the header and nothing else, which is no shares at all.
        assert!(share_rows("# desktop-cracker shares: <tag> <port> <where> <ro|rw>\n").is_empty());
        // A row missing a word is not a row.
        assert!(share_rows("docs 57001 /shared/docs\n").is_empty());
    }
}
