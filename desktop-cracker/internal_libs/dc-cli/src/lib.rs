//! The command line of desktop-cracker.
//!
//! The design's ordinary use is the whole of it: *how we use desktop-cracker without any
//! parameter, we just execute the application*.  There is **one** run mode — the
//! guest filesystem is read-write, the network is attached — and the management
//! switches below are extras that never change what a bare invocation does.
//!
//! **There is no `--admin` and no `--no-network` any more** (the operator's
//! instruction, 2026-10-08): the read-only mode `--admin` used to switch away
//! from stopped being what the application does, so a switch that says "be the
//! application" says nothing; and the network is always attached, so a switch
//! that removes it only ever made a run the project's rules do not describe.

use std::path::PathBuf;

use dc_settings::ShareMode;

/// Where the guest's audio goes.
///
/// A product choice, not a switch for testing: the guest always has its sound card,
/// and this is what the host does with the samples.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AudioBackend {
    /// the machine's own D-Bus audio, which this process receives and plays (the rule's input).
    #[default]
    Dbus,
    /// Through this process, to the host's own output device (`-audiodev pa`).
    Pulse,
    /// Straight to the host's ALSA device.
    Alsa,
    /// Nowhere: the guest's card works and its samples are dropped.
    None,
}

/// What the user asked for on the command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cli {
    /// `--plugin-path PATH`: load the **plugin** shared library at that path
    ///. The application does not know what a plugin is for: it
    /// loads it and offers it its hooks, and with no path it never looks for one.
    pub plugin_path: Option<PathBuf>,
    /// `--no-display`: boot the guest without the display path at all (headless
    /// runs, and the system tests that only assert the guest came up).
    pub no_display: bool,
    /// `--display`: attach the display path (D-Bus p2p + window) but do not open
    /// a window — the frame path runs, which is what CI and the tests use.
    pub display: bool,
    /// `--show-window`: also open the OpenGL window (needs a display server).
    pub show_window: bool,
    /// `--show-settings`: print the effective settings and exit.
    pub show_settings: bool,
    /// `--set-password`: prompt for a new unlock password, store its hash, exit.
    pub set_password: bool,
    /// `--create-root-disk`: create the guest's root disk in the root-folder and exit.
    pub create_root_disk: bool,
    /// `--disk-size MB`: the size for `--create-root-disk`.
    pub disk_size_mb: Option<u64>,
    /// `--disk-passphrase-stdin`: read the disk's passphrase from stdin instead
    /// of asking on the terminal (automation; the passphrase is still kept only
    /// in memory and is never written anywhere).
    pub disk_passphrase_stdin: bool,
    /// `--config PATH`: use another settings file (tests, several profiles).
    pub config: Option<PathBuf>,
    /// Overrides for a single run; `None` means "whatever the settings say".
    /// `--root-disk PATH`: the guest's root filesystem disk for this run.
    pub root_disk: Option<PathBuf>,
    pub memory_mb: Option<u32>,
    pub vcpus: Option<u32>,
    /// `--share PATH[:ro|rw]`, may be repeated.
    pub shares: Vec<(PathBuf, ShareMode)>,
    /// `--ssh-port PORT`: forward the host's own port `PORT` to the guest's **sshd**, which
    /// listens on port **22 inside the guest** and runs whether this switch is given or not.
    ///
    /// The host side is the host's loopback (`127.0.0.1:PORT`), so a forwarded sshd is reachable
    /// from this machine and from nowhere else.  Without the switch the **settings' own `ssh_port`
    /// decides**, and with neither **nothing is opened**: the
    /// guest's sshd is not exposed, which is what makes the forward optional.  `0` means the same as
    /// the setting being absent — off.
    pub ssh_port: Option<u16>,
    /// `--host-network`: the guest may reach **this computer's own services**. The builtin DNS answers `parenthost` with the guest's gateway, and a
    /// connection to that address is carried to the host's `127.0.0.1`.
    ///
    /// **Off by default** — the rule a run has always had is that the host's own network is not the
    /// guest's to reach.  The settings file carries the same decision as `host_network: true`, and
    /// either one turns it on: this switch is one run's, the file is every run's.
    pub host_network: bool,
    /// `--disk PATH[:ro|rw]`: attach one **additional disk** to this run, as a block device of
    /// its own inside the guest (`/dev/vdb`, `/dev/vdc`, …).  May be repeated.
    ///
    /// Nothing is mounted for the user and no password is asked for it: the disk is attached
    /// and the user mounts it himself inside the guest (`desk-disk-mount`, which opens a
    /// LUKS container with a password typed in the guest, or mounts a plain filesystem
    /// directly).  The name the guest is told is the image's file name, which is what the run
    /// logs it by as well — so a script that attaches a disk knows which is which.
    pub disks: Vec<(PathBuf, ShareMode)>,
    /// `--boot-timeout SECONDS`: how long to wait for the guest's ready marker.
    pub boot_timeout: Option<u64>,
    /// `--run-seconds SECONDS`: exit after this long (automation).
    pub run_seconds: Option<u64>,
    /// `--print-argv`: print the machine's own command line and exit, without running it.
    pub print_argv: bool,
    /// `--kernel PATH`: the guest kernel to boot (hidden default: `download/kernel`).
    pub kernel: Option<PathBuf>,
    /// `--initramfs PATH`: guest initramfs; `-` means "boot the root folder
    /// directly" (no initramfs, the 9P root-folder is the guest's `/`).
    pub initramfs: Option<PathBuf>,
    /// `--append LINE`: extra kernel command line.
    pub append: Option<String>,
    /// `--window-command ITEM`: run one of the **keys** from a terminal (`f9`, `f10`),
    /// for a session with no keyboard to press it on.
    ///
    /// A session with no keyboard to press the chord on (a test, a script) has no other
    /// way in.  This runs the **same** action the key would, so the password flow is
    /// reachable — and testable — anywhere.
    pub window_command: Option<String>,
    /// `--audio BACKEND`: where the guest's sound goes (`dbus` — the default — is the
    /// host's own output through this process; `none` is a guest with a working sound card
    /// and nowhere for the samples to go).
    pub audio: AudioBackend,
    /// `--window-hidden`: start with the display window hidden.
    pub window_hidden: bool,
    /// `--ready-marker TEXT`: the guest line that means "the guest is up".
    pub ready_marker: Option<String>,
    /// `--ready-file PATH`: a file the guest creates when it is up.
    pub ready_file: Option<PathBuf>,
    pub verbose: bool,
    pub help: bool,
    pub version: bool,
}

impl Default for Cli {
    fn default() -> Self {
        Cli {
            plugin_path: None,
            no_display: false,
            display: false,
            show_window: false,
            show_settings: false,
            set_password: false,
            create_root_disk: false,
            disk_size_mb: None,
            disk_passphrase_stdin: false,
            config: None,
            root_disk: None,
            memory_mb: None,
            vcpus: None,
            shares: Vec::new(),
            ssh_port: None,
            host_network: false,
            disks: Vec::new(),
            boot_timeout: None,
            run_seconds: None,
            print_argv: false,
            kernel: None,
            initramfs: None,
            append: None,
            window_command: None,
            audio: AudioBackend::Dbus,
            window_hidden: false,
            ready_marker: None,
            ready_file: None,
            verbose: false,
            help: false,
            version: false,
        }
    }
}

impl Cli {
    /// Does this invocation start a microVM (as opposed to a management switch)?
    pub fn starts_a_vm(&self) -> bool {
        !self.help
            && !self.version
            && !self.show_settings
            && !self.set_password
            && !self.create_root_disk
    }
}

/// A parse failure, with the sentence the user should read.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("{0}")]
pub struct CliError(pub String);

pub const USAGE: &str = "\
desktop-cracker — a sandboxed desktop: a microVM displayed and managed from the host

USAGE:
    desktop-cracker [OPTIONS]

    With no parameter the application runs the microVM: the guest filesystem is
    read-write (applications can be installed and configured) and the network is
    attached.

OPTIONS:
    --plugin-path PATH load the plugin at PATH
    --no-display            no display path at all: run the guest headless
    --display               attach the display (D-Bus p2p) without a window
    --show-window           open the OpenGL window (needs a display server)
    --config PATH           settings file to use (default ~/.desktop-cracker/config.yml)
    --root-disk PATH        override the microvm's root disk for this run
    --memory MB             guest RAM in MiB (default from the settings)
    --vcpus N               number of vCPUs
    --share PATH[:ro|rw]    share a host folder with the guest (repeatable)
    --disk PATH[:ro|rw]     attach a disk to the guest as its own block device (repeatable;
                            the user mounts it inside the guest with desk-disk-mount)
    --ssh-port PORT         forward the host's 127.0.0.1:PORT to the guest's sshd (port 22)
    --host-network          let the guest reach this computer: parenthost resolves to the
                            gateway and a flow to it is carried to the host's 127.0.0.1
    --boot-timeout SEC      how long to wait for the guest to come up
    --run-seconds SEC       exit after this long (automation)
    --kernel PATH           guest kernel to boot (default download/kernel)
    --initramfs PATH        guest initramfs ('-' = boot the root-folder directly)
    --append LINE           extra kernel command line
    --window-command ITEM   run a window key: f9 (hide or show), f10 (hide and settings)
    --audio BACKEND         where the guest's sound goes: dbus (default), pulse, alsa, none
    --window-hidden        start with the display window hidden
    --ready-marker TEXT     the guest serial line that means the guest is up
    --print-argv            print the command line a run would use and exit
    --show-settings         print the effective settings and exit
    --set-password          set (or clear) the unlock password and exit
    --create-root-disk      create the guest root disk in the root-folder and exit
    --disk-size MB          size for --create-root-disk (default 20 GiB)
    --disk-passphrase-stdin read the disk passphrase from stdin (kept in memory only)
    --verbose               more output
    -h, --help              this text
    -V, --version           version
";

/// Parse the real command line.
pub fn parse_env() -> Result<Cli, CliError> {
    parse(std::env::args().skip(1))
}

/// Parse a list of arguments (without the program name) — this is what the
/// tests exercise, so the rules are enforced without spawning anything.
pub fn parse<I, S>(args: I) -> Result<Cli, CliError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let args: Vec<String> = args.into_iter().map(Into::into).collect();
    let mut cli = Cli::default();
    let mut i = 0;

    // A value that follows an option; refuses a missing one with a useful line.
    fn value(args: &[String], i: &mut usize, opt: &str) -> Result<String, CliError> {
        *i += 1;
        match args.get(*i) {
            Some(v) if !v.starts_with("--") || v == "-" => Ok(v.clone()),
            _ => Err(CliError(format!(
                "{opt} needs a value (see --help); got nothing after it"
            ))),
        }
    }

    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "--plugin-path" => {
                cli.plugin_path = Some(PathBuf::from(value(&args, &mut i, "--plugin-path")?))
            }
            "--no-display" | "--headless" => cli.no_display = true,
            "--display" => cli.display = true,
            "--show-window" => cli.show_window = true,
            "--audio" => {
                let which = value(&args, &mut i, "--audio")?;
                cli.audio = match which.as_str() {
                    "dbus" => AudioBackend::Dbus,
                    "pa" | "pulse" => AudioBackend::Pulse,
                    "alsa" => AudioBackend::Alsa,
                    "none" => AudioBackend::None,
                    other => {
                        return Err(CliError(format!(
                            "--audio wants dbus, pulse, alsa or none (not {other:?})"
                        )))
                    }
                };
            }
            "--window-hidden" => cli.window_hidden = true,
            "--show-settings" => cli.show_settings = true,
            "--set-password" => cli.set_password = true,
            "--create-root-disk" => cli.create_root_disk = true,
            "--disk-passphrase-stdin" => cli.disk_passphrase_stdin = true,
            "--disk-size" => {
                let v = value(&args, &mut i, "--disk-size")?;
                cli.disk_size_mb = Some(
                    v.parse()
                        .map_err(|_| CliError(format!("--disk-size needs MiB, got {v:?}")))?,
                );
            }
            "--print-argv" => cli.print_argv = true,
            "--kernel" => cli.kernel = Some(PathBuf::from(value(&args, &mut i, "--kernel")?)),
            "--initramfs" => {
                let v = value(&args, &mut i, "--initramfs")?;
                cli.initramfs = if v == "-" {
                    None
                } else {
                    Some(PathBuf::from(v))
                };
            }
            "--append" => cli.append = Some(value(&args, &mut i, "--append")?),
            "--window-command" => {
                cli.window_command = Some(value(&args, &mut i, "--window-command")?)
            }
            "--ready-marker" => cli.ready_marker = Some(value(&args, &mut i, "--ready-marker")?),
            "--ready-file" => {
                cli.ready_file = Some(PathBuf::from(value(&args, &mut i, "--ready-file")?))
            }
            "--verbose" | "-v" => cli.verbose = true,
            "-h" | "--help" => cli.help = true,
            "-V" | "--version" => cli.version = true,
            "--config" => cli.config = Some(PathBuf::from(value(&args, &mut i, "--config")?)),
            "--root-disk" | "--root" => {
                cli.root_disk = Some(PathBuf::from(value(&args, &mut i, "--root-disk")?))
            }
            "--memory" | "--memory-mb" => {
                let v = value(&args, &mut i, "--memory")?;
                let mb: u32 = v
                    .parse()
                    .map_err(|_| CliError(format!("--memory needs a number of MiB, got {v:?}")))?;
                if mb < 128 {
                    return Err(CliError(format!(
                        "--memory {mb}: the guest kernel does not boot below 128 MiB"
                    )));
                }
                cli.memory_mb = Some(mb);
            }
            "--vcpus" | "--smp" => {
                let v = value(&args, &mut i, "--vcpus")?;
                let n: u32 = v
                    .parse()
                    .map_err(|_| CliError(format!("--vcpus needs a number, got {v:?}")))?;
                if n == 0 || n > 64 {
                    return Err(CliError(format!("--vcpus {n}: must be between 1 and 64")));
                }
                cli.vcpus = Some(n);
            }
            "--boot-timeout" => {
                let v = value(&args, &mut i, "--boot-timeout")?;
                cli.boot_timeout =
                    Some(v.parse().map_err(|_| {
                        CliError(format!("--boot-timeout needs seconds, got {v:?}"))
                    })?);
            }
            "--run-seconds" => {
                let v = value(&args, &mut i, "--run-seconds")?;
                cli.run_seconds =
                    Some(v.parse().map_err(|_| {
                        CliError(format!("--run-seconds needs seconds, got {v:?}"))
                    })?);
            }
            "--share" => {
                let v = value(&args, &mut i, "--share")?;
                let (path, mode) = split_share(&v)?;
                cli.shares.push((path, mode));
            }
            "--host-network" => cli.host_network = true,
            "--ssh-port" => {
                let v = value(&args, &mut i, "--ssh-port")?;
                cli.ssh_port = ssh_port(&v)?;
            }
            "--disk" => {
                let v = value(&args, &mut i, "--disk")?;
                let (path, mode) = split_share(&v)?;
                cli.disks.push((path, mode));
            }
            other if other.starts_with("--share=") => {
                let (path, mode) = split_share(&other["--share=".len()..])?;
                cli.shares.push((path, mode));
            }
            other if other.starts_with("--disk=") => {
                let (path, mode) = split_share(&other["--disk=".len()..])?;
                cli.disks.push((path, mode));
            }
            other if other.starts_with("--plugin-path=") => {
                return Err(CliError(format!("{other}: use --plugin-path PATH")))
            }
            other => {
                return Err(CliError(format!(
                    "unknown parameter {other:?}; run --help for the list"
                )))
            }
        }
        i += 1;
    }

    Ok(cli)
}

/// `--ssh-port PORT` — the host port that is carried to the guest's sshd (port 22 inside).
///
/// A port, and only a port: the guest's side is always 22, so there is no
/// `host:guest` spelling to parse and no address to give.  The host side the forward uses is the
/// host's loopback, which is the rule this project's port mappings follow.
///
/// **`0` is off**, which is what the *settings window* stores for an empty field (The
/// guest's ssh server: `0` and an empty field are the same answer). The switch's own answer for
/// "off" is to be absent — that is what the file has too, where `0` is migrated away — so `0` on the
/// command line says so rather than being an error: a script that passes the setting through
/// (`--ssh-port "$ssh_port"`, empty when off) would otherwise be passing it an invalid value.
fn ssh_port(text: &str) -> Result<Option<u16>, CliError> {
    let text = text.trim();
    if text.is_empty() || text == "0" {
        return Ok(None);
    }
    let port: u16 = text.parse().map_err(|_| {
        CliError(format!(
            "--ssh-port {text:?}: it is a port number, like 2223"
        ))
    })?;
    if !dc_settings::SSH_PORT_RANGE.contains(&port) {
        return Err(CliError(format!(
            "--ssh-port {port}: it is the port on the host that is forwarded, and this application \
             may not bind one below {} (a host usually has its own service there)",
            dc_settings::SSH_PORT_RANGE.start()
        )));
    }
    Ok(Some(port))
}

/// `PATH[:ro|rw]` — the mode defaults to read-write, the useful default for a
/// folder the user chose to share.
fn split_share(text: &str) -> Result<(PathBuf, ShareMode), CliError> {
    let (path, mode) = match text.rsplit_once(':') {
        Some((p, m)) if m == "ro" || m == "rw" => (p, Some(m)),
        _ => (text, None),
    };
    if path.is_empty() {
        return Err(CliError(format!("--share {text:?} has no folder")));
    }
    let mode = match mode {
        Some("ro") => ShareMode::Ro,
        Some("rw") => ShareMode::Rw,
        _ => ShareMode::Rw,
    };
    Ok((PathBuf::from(path), mode))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_parameter_is_the_whole_application() {
        // There is one run mode: a bare invocation starts the microVM, and the switches that
        // used to change the mode (`--admin`, `--no-network`) are gone with it.
        let cli = parse(Vec::<String>::new()).unwrap();
        assert!(cli.starts_a_vm());
        assert!(!cli.help && !cli.version);
    }

    #[test]
    fn the_removed_switches_are_unknown_parameters() {
        // A user carrying one of these in a script gets the sentence, not a silent difference.
        // `--numlock-held` went with the sound rule that needed the key (2026-10-14): the sound
        // follows the window's visibility, so an unattended run has nothing left to pin.
        for gone in ["--admin", "--no-network", "--numlock-held"] {
            let error = parse([gone]).unwrap_err();
            assert!(
                error.to_string().contains("unknown parameter"),
                "{gone}: {error}"
            );
        }
    }

    #[test]
    fn shares_take_an_optional_mode() {
        let cli = parse([
            "--share",
            "/srv/data",
            "--share",
            "/srv/secret:ro",
            "--share=/tmp/x:rw",
        ])
        .unwrap();
        assert_eq!(cli.shares.len(), 3);
        assert_eq!(cli.shares[0], (PathBuf::from("/srv/data"), ShareMode::Rw));
        assert_eq!(cli.shares[1], (PathBuf::from("/srv/secret"), ShareMode::Ro));
        assert_eq!(cli.shares[2], (PathBuf::from("/tmp/x"), ShareMode::Rw));
    }

    #[test]
    fn a_path_with_a_colon_is_not_a_mode() {
        let cli = parse(["--share", "/tmp/a:b"]).unwrap();
        assert_eq!(cli.shares[0], (PathBuf::from("/tmp/a:b"), ShareMode::Rw));
    }

    #[test]
    fn additional_disks_take_the_same_shape_a_share_does() {
        // `--disk PATH[:ro|rw]`, repeated: one disk each, read-write unless it says otherwise.
        let cli = parse(["--disk", "/srv/data.raw", "--disk=/srv/backup.img:ro"]).unwrap();
        assert_eq!(
            cli.disks,
            vec![
                (PathBuf::from("/srv/data.raw"), ShareMode::Rw),
                (PathBuf::from("/srv/backup.img"), ShareMode::Ro),
            ]
        );
        // No switch is no disk: a run that was told about none attaches none.
        assert!(parse(Vec::<String>::new()).unwrap().disks.is_empty());
        assert!(parse(["--disk"]).is_err(), "a --disk needs a path");
    }

    /// `--host-network`: **off is the default**, and the
    /// switch says on for this run.  It takes no value — there is nothing to name.
    #[test]
    fn the_host_network_switch_is_off_until_it_is_given() {
        assert!(
            !parse(Vec::<String>::new()).unwrap().host_network,
            "a run with no switch does not let the guest reach this computer"
        );
        assert!(parse(["--host-network"]).unwrap().host_network);
        // It is a switch, not an option with a value: the next argument is never eaten.
        let both = parse(["--host-network", "--ssh-port", "2223"]).unwrap();
        assert!(both.host_network);
        assert_eq!(both.ssh_port, Some(2223));
    }

    #[test]
    fn the_ssh_port_is_the_hosts_port_and_it_is_optional() {
        // With no switch there is **nothing to forward**: the guest's sshd runs, and no host
        // port carries it.
        assert_eq!(parse(Vec::<String>::new()).unwrap().ssh_port, None);
        assert_eq!(parse(["--ssh-port", "2223"]).unwrap().ssh_port, Some(2223));
        // **`0` and an empty value are off**, the same answer the settings window stores for an
        // empty field — a script passing the setting through is not passing nonsense.
        assert_eq!(parse(["--ssh-port", "0"]).unwrap().ssh_port, None);
        assert_eq!(parse(["--ssh-port", "  "]).unwrap().ssh_port, None);
        // A port, and only a port: the guest's side is 22 by definition, so an address or a
        // `host:guest` pair is not something this switch takes, and neither is one this process
        // may not bind.
        for bad in [
            "abc",
            "22",
            "80",
            "1023",
            "65536",
            "-22",
            "127.0.0.1:2223",
            "2223:22",
        ] {
            assert!(
                parse(["--ssh-port", bad]).is_err(),
                "--ssh-port {bad:?} was accepted"
            );
        }
    }

    #[test]
    fn missing_values_and_bad_numbers_are_refused() {
        assert!(parse(["--memory"]).is_err());
        assert!(parse(["--memory", "64"]).is_err());
        assert!(parse(["--memory", "abc"]).is_err());
        assert!(parse(["--vcpus", "0"]).is_err());
        assert!(parse(["--vcpus", "1000"]).is_err());
        assert!(parse(["--nonsense"]).is_err());
        assert!(parse(["--share", ""]).is_err());
    }

    #[test]
    fn display_switches_are_independent() {
        let cli = parse(["--no-display"]).unwrap();
        assert!(cli.no_display && !cli.display && !cli.show_window);
        let cli = parse(["--display"]).unwrap();
        assert!(cli.display && !cli.no_display && !cli.show_window);
        let cli = parse(["--show-window"]).unwrap();
        assert!(cli.show_window);
        let cli = parse(["--audio", "none"]).unwrap();
        assert_eq!(cli.audio, AudioBackend::None);
        assert!(!parse(["--audio", "nope"]).unwrap_err().0.is_empty());
        assert!(parse(["--window-hidden"]).unwrap().window_hidden);
    }

    #[test]
    fn management_switches_do_not_start_a_vm() {
        assert!(!parse(["--create-root-disk"]).unwrap().starts_a_vm());
        assert!(!parse(["--show-settings"]).unwrap().starts_a_vm());
        assert!(!parse(["--help"]).unwrap().starts_a_vm());
        assert!(!parse(["--set-password"]).unwrap().starts_a_vm());
    }

    #[test]
    fn boot_source_overrides_are_recorded() {
        let cli = parse(["--kernel", "/boot/vmlinuz", "--initramfs", "/tmp/i.gz"]).unwrap();
        assert_eq!(cli.kernel, Some(PathBuf::from("/boot/vmlinuz")));
        assert_eq!(cli.initramfs, Some(PathBuf::from("/tmp/i.gz")));
        // '-' means "no initramfs": boot the 9P root folder directly
        let cli = parse(["--initramfs", "-"]).unwrap();
        assert_eq!(cli.initramfs, None);
    }

    #[test]
    fn run_overrides_are_recorded() {
        let cli = parse([
            "--root-disk",
            "/srv/root",
            "--memory",
            "4096",
            "--vcpus",
            "4",
            "--run-seconds",
            "30",
            "--boot-timeout",
            "60",
        ])
        .unwrap();
        assert_eq!(cli.root_disk, Some(PathBuf::from("/srv/root")));
        assert_eq!(cli.memory_mb, Some(4096));
        assert_eq!(cli.vcpus, Some(4));
        assert_eq!(cli.run_seconds, Some(30));
        assert_eq!(cli.boot_timeout, Some(60));
    }
}
