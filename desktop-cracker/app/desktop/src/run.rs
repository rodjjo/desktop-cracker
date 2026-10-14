//! **One run of desktop-cracker on Firecracker** — the order the project's own run has, with the
//! hypervisor's half replaced.
//!
//! A run is the settings, the question, the window, the rule, the plugin and the shutdown: the
//! machine is a microVM on Firecracker, defined over its API, and every device the guest has is a
//! **channel** this process serves (`fc-run`).
//!
//! The order, and why each step is where it is:
//!
//! 1. **the settings and the plugin** — before anything can ask a question;
//! 2. **the disk's passphrase**, asked on the UI thread with the window already decided, through
//!    the plugin first (a client answers it exactly as a person would);
//! 3. **the run's own files**: the mount plan (the project's `dc-shares`), the disks, the screen's
//!    geometry — all of them travelling to the guest in the control share;
//! 4. **the machine**: `fc_run::start` binds every channel *before* `InstanceStart`, spawns the
//!    child with `PR_SET_PDEATHSIG`, defines and starts the machine and pins the vCPU threads;
//! 5. **the window**: `dc-display`'s own GTK window, fed by `dc-fc-window` (the guest's rectangles
//!    in, the window's keys and pointer out).  It is created after the question, because a GTK
//!    dialog and the window belong to the same thread;
//! 6. **the guest's landmark**: an event on the readiness channel, never a line read off a
//!    console after the fact;
//! 7. **run**: until the window's own exit, `--run-seconds`, or the guest going away;
//! 8. **the clean shutdown**: the guest's own channel (its agent reboots the machine, which is
//!    what ends Firecracker), then the secrets are dropped and the run's own directory removed.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use dc_cli::Cli;
use dc_common::manager::{Manager, Phase};
use dc_common::milestone;
use dc_display::window::{WindowConfig, WindowControl, WindowState};
use dc_display::{Display, InputSink};
use dc_session::ui::UiState;
use fc_run::{RunSpec, Started};

use crate::media;

/// The two states "External state" names, as the numbers the guest's own library
/// reads (`tools/libdesk`).
const DISPLAY_HIDDEN: i32 = -1;
const DISPLAY_VISIBLE: i32 = 1;

/// **A root disk the settings name and that is not there**, and the two questions that answer it:
/// the settings window, where the disk is *selected*, and the passphrase it is
/// then made with — asked **twice**, in a question of its own, because a passphrase is never a
/// setting and never a field in that window.
///
/// It is a value because the two questions belong to the **UI thread** and the run's own thread has
/// to be told the answer: the passphrase is handed on the same way the disk's password for a boot
/// is (`dc_session::ui::DiskAnswer`), and it is the same passphrase — the guest opens the disk the
/// run just made with it.
struct MissingDisk {
    /// **The settings file this run holds**: the window saves through it, so the disk it selects and
    /// the values it writes are in force for this run the moment the window closes.
    file: Arc<Mutex<dc_session::hotkeys::SettingsFile>>,
    /// Where the passphrase goes, once it has been asked for: **the same slot the run's own disk
    /// password uses**, so the run waits for it the one way it waits for a question.
    answer: Arc<dc_session::ui::DiskAnswer>,
    /// The disk the window ended up naming, which is what the run then boots (the window is the
    /// user's to change).
    chosen: Arc<Mutex<Option<std::path::PathBuf>>>,
}

impl MissingDisk {
    /// **Tell the run which disk to boot**, when it is not the one this run read at startup.
    fn chose(&self, path: &std::path::Path) {
        if let Ok(mut slot) = self.chosen.lock() {
            *slot = Some(path.to_path_buf());
        }
    }

    /// **The window where the disk is selected**, on the UI thread.  `Err` is a sentence for the
    /// person.  The settings window is the first thing a first run shows: it is where the disk is
    /// *selected*, and it is the only place a passphrase is not.
    fn select(&self) -> Result<std::path::PathBuf, String> {
        // The window shows what is in force and saves into the same file; what it saved is what this
        // run uses from here on, and it is read back from the file anyway (the window is the user's,
        // and `open_settings` has already adopted it).
        let path = {
            let mut file = match self.file.lock() {
                Ok(file) => file,
                Err(e) => e.into_inner(),
            };
            dc_session::hotkeys::open_settings(&mut file)?;
            file.live.root_disk.clone()
        };
        self.chose(&path);
        Ok(path)
    }

    /// **The question that makes a disk**, on the UI thread: the passphrase, asked **twice** in a
    /// question of its own — a passphrase is never a setting, so the window has no field for it —
    /// and the disk built with it by the project's own disk path (`dc_fc_disk::create_root_disk`, a
    /// microVM of its own: no root, no loop device, no `dm-crypt` on the host).
    ///
    /// The **same passphrase is what the guest opens the new disk with**, and it goes into the run's
    /// answer slot: asked once, used for the disk and for the boot.
    fn make(&self, path: &std::path::Path) -> Result<(), String> {
        let parent = dc_display::display_loop::parent_window();
        let asked = dc_session::diskpass::ask_new_disk_passphrase(path, parent.as_ref())
            .map_err(|e| format!("{e}"))?;
        let text = asked
            .expose()
            .map(|bytes| String::from_utf8_lossy(bytes).to_string())
            .unwrap_or_default();
        dc_fc_disk::create_root_disk(path, dc_common::DEFAULT_ROOT_DISK_MB, &text)
            .map_err(|e| format!("{e}"))?;
        dc_common::milestone!("the root disk {} was made", path.display());
        self.answer.set(asked);
        Ok(())
    }

    /// **The whole first-run step**, on the UI thread: the window that selects the disk, then the
    /// question that makes it when there is none.  `Err` is a sentence for the person, and the run
    /// ends with it rather than starting a machine with no root device.
    fn place(&self) -> Result<(), String> {
        let path = self.select()?;
        // The window may have named a disk that is there — the user's own, selected in it — and that
        // is the whole of this step: the run boots it and asks for its password the way it always
        // has.  A path with nothing behind it is the disk this step **makes**.
        if !path.exists() {
            self.make(&path)?;
        }
        if !path.exists() {
            return Err(said_no_disk(&path));
        }
        Ok(())
    }
}

/// The sentence a run ends with when the disk the window selected is not there: the two things a
/// person can do about it, in the order they are worth trying.
fn said_no_disk(path: &std::path::Path) -> String {
    format!(
        "the root disk {} is not there and was not made, so there is nothing to boot.\n  \
         Make it with the package's own tool, which carries the userland to copy:\n    \
         desk-disk rootdisk --path {} --size {}G",
        path.display(),
        path.display(),
        dc_common::DEFAULT_ROOT_DISK_MB / 1024
    )
}

/// Run until it is over.
pub fn run(cli: Cli) -> Result<()> {
    // ---------------------------------------------------------------- settings
    // **The settings are the package's own** (`dc_settings::config_path`: the folder this
    // application was extracted into — dist: ). `--config` names a file of its own, which
    // is how a development tree and the system tests keep theirs in `temp/`; there is no fallback
    // path, so an installed package never reads another installation's settings.
    let config_path = cli.config.clone().unwrap_or_else(dc_settings::config_path);
    // **The file, and what is in force**: `SettingsFile` owns both, so a save the window makes is a
    // save this run reads — and the unlock hash it asks against is the one it started with, until
    // the window itself replaces it.
    let file = Arc::new(Mutex::new(dc_session::hotkeys::SettingsFile::load(
        config_path.clone(),
        true,
    )?));
    let settings = file
        .lock()
        .map(|file| file.live.clone())
        .unwrap_or_else(|e| e.into_inner().live.clone());
    let mut root_disk = cli
        .root_disk
        .clone()
        .unwrap_or_else(|| settings.root_disk.clone());

    // **The root disk, and the window when there is none.**  The application has no fallback path
    //: the settings are the package's own `config.yml` and the root disk is the one
    // they name.  A path with nothing behind it is a package nobody has used yet — freshly
    // extracted, or installed with `--no-disk` — so the run opens **its window** and says so, which
    // is the order this application has always had: the window first, because it is what a question
    // is asked over (the window "need to appear as soon as we open the VM, even before
    // asking password for the root disk").
    //
    // The disk itself is dealt with **on the UI thread**, further down, where both halves live:
    // 1. **the settings window**, which is where a disk is *selected* — it has no passphrase field,
    //    because a passphrase is a question and not a setting;
    // 2. **the question**, asked **twice** (`dc_session::diskpass::ask_new_disk_passphrase`), whose
    //    answer builds the disk and is dropped with it: it never reaches `config.yml`.
    //
    // A run with **no display server** cannot ask anything, and says so here rather than failing
    // later with the machine's own words about a device that is not there.
    if !root_disk.exists() && cli.no_display {
        anyhow::bail!(
            "the root disk {} is not there, and this run asked for no window to select one in.\n  \
             Make it with the package's own tool, which carries the userland to copy:\n    \
             desk-disk rootdisk --path {} --size {}G",
            root_disk.display(),
            root_disk.display(),
            dc_common::DEFAULT_ROOT_DISK_MB / 1024
        );
    }

    let manager = manager();

    if cli.show_settings {
        print!("{}", serde_yaml::to_string(&settings)?);
        println!("# config file: {}", config_path.display());
        return Ok(());
    }
    if cli.set_password {
        let password = dc_session::prompt::ask_password_twice()?;
        let mut settings_to_write = settings.clone();
        settings_to_write.set_password(password.as_deref())?;
        settings_to_write.save_to(&config_path)?;
        milestone!("unlock password updated in {}", config_path.display());
        return Ok(());
    }
    if cli.create_root_disk {
        anyhow::bail!(
            "a disk is made by `desk-disk` (this tree's own tool, `make disk-tool`): it runs \
             the job in a microVM of its own, and the application never makes a disk of its own"
        );
    }

    // The unlock password this run asks against lives in `file` (`SettingsFile::unlock`): loaded
    // once at startup, and replaced only by a password the settings window
    // itself saves — with a password in force the window asks it **every time**, including the first
    // time, so a person who has not typed it does not get to change it.

    // ---------------------------------------------------------------- the media
    let kernel = media::kernel(&cli);
    let initramfs = media::initramfs(&cli)
        .context("this path always boots the guest's own initramfs: it is what brings the ")?;
    let firecracker = media::firecracker();
    if !kernel.exists() {
        anyhow::bail!(
            "the guest kernel {} does not exist — run `make build` in the project's root first",
            kernel.display()
        );
    }
    if !initramfs.exists() {
        anyhow::bail!(
            "the guest's initramfs {} does not exist — run `make build` in the project's root first",
            initramfs.display()
        );
    }
    if is_a_wrapped_image(&root_disk) {
        anyhow::bail!(
            "the root disk {} is a wrapped image (a `.qcow2` and the like), and Firecracker \
             attaches **raw** images only. Convert it once and point the settings at the result \
             (the copy is the same size as the disk itself, and the original is left alone)",
            root_disk.display(),
        );
    }

    // ---------------------------------------------------------------- the geometry
    //
    // this project's rule, decided **before** the guest boots, because the guest's kernel is loaded
    // with it: the host's own resolution when the guest is full screen, 1280x800 otherwise.  The
    // window is opened at the same size, so the picture is not scaled on this path at all.
    let width = settings.display_width.max(640);
    let height = settings.display_height.max(400);
    let surface = dc_fc_display::Surface {
        width,
        height,
        // The framebuffer publishes `XRGB8888`, which is the guest's own `PIXMAN_x8r8g8b8` — the format
        // `dc-display`'s window already renders, so nothing is converted on either side.
        format: 0x2000_0000,
    };

    // ---------------------------------------------------------------- the UI state
    //
    // The window's control, the state the audio rule reads, and the questions — the project's own
    // types, unchanged.  The UI thread is the display thread (the GTK main loop), which is why the
    // disk's question is asked there and the window is created there too.
    let display_state = Display::new();
    let window_state = WindowState::new();
    window_state.set_size(width, height);
    let window = Arc::new(WindowControl::new());
    // **The window's own first state**: the plugin's rule (Plugins: , and
    // the plugin's own contract) is that a run **with a plugin is hidden by default** — the tests
    // drive it through the plugin, and a window in front of the person at the machine is a test
    // disturbing them — and `--show-window` is what asks for it anyway.
    let plugin_wants_window = cli.plugin_path.is_some() && !cli.show_window;
    let window_visible = cli.display || (!cli.no_display && !plugin_wants_window);
    window.set_visible(window_visible);
    let settings_wanted = Arc::new(AtomicBool::new(false));
    let exit_requested = Arc::new(AtomicBool::new(false));
    let pending: Arc<Mutex<Option<dc_display::xinput::Hotkey>>> = Arc::new(Mutex::new(None));
    // **The disk's question and its answer**, between this thread and the one that owns the
    // window (`dc-session`'s own slot).
    let disk_answer = Arc::new(dc_session::ui::DiskAnswer::default());
    let disk_failed: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let ui = Arc::new(UiState {
        window: window.clone(),
        file: file.clone(),
        settings_wanted: settings_wanted.clone(),
        exit_requested: exit_requested.clone(),
        pending: pending.clone(),
        asking: Arc::new(AtomicBool::new(false)),
        failed: Arc::new(Mutex::new(None)),
        changed: Arc::new((Mutex::new(0u64), Condvar::new())),
    });

    // ---------------------------------------------------------------- the plugin
    let plugin_cells = Arc::new(Mutex::new(PluginCells::default()));
    let pixels: Arc<Mutex<Option<Arc<dc_fc_window::Pixels>>>> = Arc::new(Mutex::new(None));
    let pixels_slot = pixels.clone();
    {
        if let Ok(mut cells) = plugin_cells.lock() {
            cells.display = Some(display_state.clone());
            cells.state = Some(window_state.clone());
            cells.window = Some(window.clone());
            cells.ui = Some(ui.clone());
            cells.pixels = Some(pixels.clone());
        }
    }
    // **Where the vCPUs are pinned**: the run answers it once the machine is made (`fc-run`
    // confines the process and puts each `fc_vcpu N` thread on a core of its own), and the plugin
    // asks for it whenever a client wants to know.  It starts empty, which is the honest answer
    // before there is a machine.
    let pinning = Arc::new(Mutex::new(dc_plugin::PinningInfo::default()));
    let plugin = crate::plugin::load(&cli, plugin_cells.clone(), pinning.clone());

    // ---------------------------------------------------------------- the run's files
    //
    // The mount plan is the project's own (`dc-shares`): the tags, the modes and the mount points
    // the guest's own tools read.  The service this path runs takes its list from it
    // (`fc_run::RunSpec::share_list`), and the control directory — the one writable exception —
    // is offered beside them.
    // **The run's own directory**:
    // `$XDG_RUNTIME_DIR/desktop-cracker/run-<pid>`, or `~/.desktop-cracker/run/…` where the
    // session has no runtime directory.  It is **private** (`0700`) and it is **this run's**: the
    // pid in the name is what keeps a second run — another terminal, another developer, another
    // user — from binding the same names or tripping over a socket this one left.
    //
    // It is a value that removes itself, not a line at the end of this function: a run has more
    // than one way out (the window closed, the disk refused, a signal, an error half-way through
    // the boot), and a cleanup written at the end of one path is a cleanup that only happens on
    // that path.
    let run_dir = dc_common::PrivateDir::create(dc_common::run_directory(
        &dc_common::runtime_dir(),
        std::process::id(),
    ))?;
    let control_dir = run_dir.join("control");
    dc_common::fs::create_dir_all(&control_dir)?;
    // **The host's X socket directory is forwarded, never mounted.**  The guest runs its **own** X
    // server in the system on the disk, whose socket is `/tmp/.X11-unix/X0`, and a read-only share
    // of the host's directory would sit on top of it — this path always has a forwarder (remote
    // X, port 1026, on Firecracker's own unix socket), so the share is never mounted.  Measured
    // 2026-10-10: with the share mounted, the guest's X
    // server could not create its own socket (`X1 X99` were the host's, X0 was not there), LightDM
    // had no display to show and the desktop never came up.
    let x_dir = std::path::PathBuf::from("/tmp/.X11-unix");
    let x_dir = (settings.remote_x && x_dir.is_dir()).then_some(x_dir);
    // **The folder the user's disks live in is made if it is not there**: it is where a disk is
    // put, not a place a run requires the user to have created by hand (the settings
    // name it, and a fresh installation has none).
    let _ = dc_common::fs::create_dir_all(&settings.disk_folder);
    let shares = dc_shares::ShareSet::build(
        None,
        Some(&settings.disk_folder),
        None,
        Some(control_dir.as_path()),
        &settings.shared_folders,
        true,
    )?;
    shares.check_host_paths()?;
    let mut share_list =
        fc_run::RunSpec::share_list(&shares, dc_common::GUEST_SHARE_DIR, &control_dir);

    // `--share` on the command line: the same folders the settings name, added one by one.
    for (path, mode) in &cli.shares {
        let tag = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "share".into());
        share_list.push(dc_fc_share::Share {
            tag: tag.clone(),
            path: path.clone(),
            where_: format!("{}/{}", dc_common::GUEST_SHARE_DIR, tag),
            read_only: mode.is_read_only(),
            writable_exception: false,
        });
    }
    if !shares.shares.is_empty() {
        milestone!("shares: {}", shares.describe());
    }

    // ---------------------------------------------------------------- the passphrase
    //
    // **What is known here is only whether a password is needed** (`--disk-passphrase-stdin`, or a
    // disk that really is a container — read from the image's own header, never from a helper the
    // host may not have).  The question itself is asked further down, **on the thread that owns
    // the window and before the machine is started**: that is where a GTK dialog is safe
    // (`dc-display`'s one-UI-thread rule), and a run
    // that cannot be answered must not have started a guest.  On this path the answer goes into
    // the run's **control share**, and the guest's own initramfs opens the container with it
    // (no host privilege, no helper, no `dm-crypt` on the host).
    let stdin_passphrase: Option<String> = if cli.disk_passphrase_stdin {
        dc_session::diskpass::DiskPassphrase::from_stdin()?
            .expose()
            .map(|bytes| String::from_utf8_lossy(bytes).to_string())
    } else {
        None
    };
    let ask_for_disk = stdin_passphrase.is_none() && disk_is_encrypted(&root_disk);

    // ---------------------------------------------------------------- the machine
    // **The settings as they are *now*** (Settings: the window's save is in force at
    // once).  The first-run window has closed by this point, so a disk it selected and a value it
    // wrote are what this machine is described with — and there is one read, here, rather than one
    // per field, so no two fields can disagree about which settings they came from.
    let settings = file
        .lock()
        .map(|file| file.live.clone())
        .unwrap_or_else(|e| e.into_inner().live.clone());

    let mut spec = RunSpec {
        kernel: dc_fc_vm::Kernel {
            image: kernel.clone(),
            initramfs: Some(initramfs.clone()),
            append: "console=ttyS0 rdinit=/init quiet loglevel=3".into(),
        },
        root: dc_fc_vm::Disk {
            name: "root".into(),
            path: root_disk.clone(),
            read_only: false,
        },
        disks: attached_disks(&settings, &cli),
        // **The run's own overrides win over the settings** (`dc-cli`'s `--vcpus` and `--memory`,
        // as the application applies them): the settings are the file's answer, and a
        // switch on the command line is the person's.
        vcpus: cli.vcpus.unwrap_or(settings.vcpus).max(1),
        memory_mib: cli.memory_mb.unwrap_or(settings.memory_mb).max(256) as u64,
        program: firecracker.clone(),
        run_dir: run_dir.path().to_path_buf(),
        // The guest's own context id: one run, one id (a disk job takes another).
        guest_cid: 3,
        balloon_mib: settings
            .balloon_automatic
            .then_some((settings.memory_mb / 4) as u64),
        display: Some(surface),
        audio: Some(audio_path(&window_state)),
        // **The forward to the guest's sshd**: the switch when it is given, the settings' own
        // `ssh_port` otherwise (The guest's ssh server: — the same rule as `host_network`)
        // — and nothing at all when neither says so.
        ssh_port: cli.ssh_port.or(settings.ssh_port),
        // **`--host-network`, or the settings' `host_network`**: either one turns it on for this run, and neither one turns the other off.
        // With neither, the machine's network keeps the rule it has always had.
        host_network: cli.host_network || settings.host_network,
        shutdown_channel: true,
        x_socket: x_dir.clone(),
        shares: share_list,
        // Filled in below, once the question has been asked: the run is described **without** the
        // secret, and the secret is added to the description on this thread — it is never a
        // command-line argument, a file, or an environment variable.
        root_passphrase: None,
        boot_from_disk: true,
        ..RunSpec::default()
    };
    // **The control share's own files**, in the shape the guest's own tools read, the way its
    // control
    // directory: the mount plan (under the name the guest's own tools read), and the environment
    // remote X's clients need.  A disk the run was given that the passphrase also opens is opened
    // by the **guest**, which is the whole point of this path's shape.
    let mut control = dc_fc_control::Control::new();
    control.put(
        "mounts",
        shares.mount_plan(true, dc_common::GUEST_SHARE_DIR),
    );
    // **The disks plan**: `<device> <name> <ro|rw>`, one line per attached disk — the name the
    // guest's own tool takes (`desk-disk-mount open NAME`) and the device it is.  The plan
    // names the devices the **guest's kernel** gives them, which is what
    // names them, in the order the drives were defined (the root disk is `/dev/vda`, the first
    // additional drive `/dev/vdb`, and so on), which is the same naming and the same file the
    // guest reads (`/run/desktop-cracker/disks`).
    let plan: String =
        std::iter::once("# desktop-cracker disks plan: <device> <name> <ro|rw>\n".to_string())
            .chain(spec.disks.iter().enumerate().map(|(index, disk)| {
                format!(
                    "/dev/vd{} {} {}\n",
                    (b'b' + index as u8) as char,
                    disk.name,
                    if disk.read_only { "ro" } else { "rw" }
                )
            }))
            .collect();
    control.put("disks", plan);
    if let Some(x_dir) = &x_dir {
        if let Ok(host) = dc_xremote::detect(x_dir) {
            let _ = host.extract_authority(&dc_xremote::authority_path(), &control_dir);
            let authority = format!("{}/Xauthority", dc_common::GUEST_CONTROL_DIR);
            control.put(
                "x-display.env",
                host.guest_environment(&authority).as_bytes().to_vec(),
            );
            milestone!(
                "remote X: the guest reaches the host's {} through port 1026",
                host.display
            );
        }
    }
    spec.control = control;

    // ---------------------------------------------------------------- the window
    //
    // **The project's own window comes first**, and it is what asks the disk's question — the
    // order this application has always had, and the reason for it: this project's own words are that the
    // window "need to appear as soon as we open the VM, even before asking password for the root
    // disk", and the question is a **dialog transient for that window**, so it cannot be lost
    // behind the guest's screen.  The window and the question are one thread (GTK's), which is why
    // they are created together.
    let disk_path_for_question = root_disk.clone();
    let disk_answer_for_question = disk_answer.clone();
    let disk_failed_for_question = disk_failed.clone();
    let ask = ask_for_disk;
    // **The disk this run has to make before it can ask anything** (`None` when it is there): the
    // settings window that selects it and the question that asks for its passphrase both belong to
    // the UI thread, which is the thread this closure runs on.  The answer is handed to the run the
    // same way the disk's own password is, and it is the password the guest opens the *new* disk
    // with — one passphrase, asked once and used for the disk and the boot.
    //
    // `Arc`, because the UI thread and the run's own thread both name it: the closure places the
    // disk, and this thread reads what the window ended up choosing.
    let make_disk = (!root_disk.exists()).then(|| {
        Arc::new(MissingDisk {
            file: file.clone(),
            answer: disk_answer.clone(),
            chosen: Arc::new(Mutex::new(None)),
        })
    });
    let make_disk_for_loop = make_disk.clone();
    let input: Arc<Mutex<Option<Arc<dyn InputSink>>>> = Arc::new(Mutex::new(None));
    // **A window is opened whenever there is a display and the caller did not ask for none** —
    // with a plugin it is opened **unmapped** (Plugins: a test's run must not put a
    // window in front of a person), and it still draws: the frame `POST /frame` hands a client is
    // the frame the window is about to draw.
    let display_thread = if !cli.no_display || cli.plugin_path.is_some() {
        let cfg = WindowConfig {
            title: dc_common::APP_NAME.into(),
            width,
            height,
            fullscreen: false,
            run_seconds: cli.run_seconds,
            hidden_initially: !cli.show_window && (plugin_wants_window || !window_visible),
            numlock_held_initially: cli.numlock_held,
            control: Some(window.clone()),
            state: Some(window_state.clone()),
            manager: None,
        };
        let display_for_loop = display_state.clone();
        let input_for_loop = input.clone();
        let ui_for_loop = ui.clone();
        let hotkeys = ui.keys();
        let question_failed = disk_failed_for_question.clone();
        let failed_for_loop = question_failed.clone();
        let question_answered = disk_answer_for_question.clone();
        Some(
            std::thread::Builder::new()
                .name("desktop-cracker-window".into())
                .spawn(move || {
                    let work: dc_display::display_loop::UiWork = {
                        let ui = ui_for_loop.clone();
                        Arc::new(move || ui.work())
                    };
                    // **The run's first work, on this thread and over the window it has just
                    // opened**, in the order this application has always had: the disk, then its
                    // password, then the machine.  A refusal here is a failure with nothing to
                    // start — the machine does not exist yet, so nothing has to be undone.
                    //
                    // * a **disk that is not there** is selected in the settings window and then
                    //   made: its passphrase is asked for **twice**, in a question of its own (it is
                    //   not a setting, so the window has no field for it), and the answer is dropped
                    //   with the disk it built;
                    // * the **disk's password for this run** is the question after that, and the
                    //   run waits for it: the plugin answers first when a client is attached, so a
                    //   test never sees a dialog — `dc-dialog` tries it before any window of its own.
                    let place = move || {
                        // **The disk first, when there is none**: the window that selects it, then
                        // the question that asks for its passphrase (twice), then the disk itself.
                        // The answer lands in the run's own answer slot, which is what the run is
                        // waiting on — one question, one wait, whichever it turns out to be.
                        if let Some(missing) = make_disk_for_loop {
                            missing.place()?;
                            return Ok(());
                        }
                        if !ask {
                            return Ok(());
                        }
                        match dc_session::diskpass::ask_over(
                            &disk_path_for_question,
                            dc_display::display_loop::parent_window().as_ref(),
                        ) {
                            Ok(passphrase) => {
                                question_answered.set(passphrase);
                                Ok(())
                            }
                            Err(e) => {
                                let said = format!("{e}");
                                if let Ok(mut slot) = question_failed.lock() {
                                    *slot = Some(said);
                                }
                                Err("the root disk's password was not given".to_string())
                            }
                        }
                    };
                    if let Err(e) = dc_display::display_loop::run_window(
                        cfg,
                        display_for_loop,
                        input_for_loop,
                        hotkeys,
                        work,
                        place,
                    ) {
                        if let Ok(mut slot) = failed_for_loop.lock() {
                            if slot.is_none() {
                                *slot = Some(e.clone());
                            }
                        }
                        milestone!("the window could not run ({e})");
                    }
                })
                .context("the window's thread")?,
        )
    } else {
        None
    };

    // **The disk's password when there is no window to ask over** — a session with no display
    // server.  It is asked where a question can be asked (`dc-dialog`'s own terminal fallback),
    // on a thread of its own: GTK is never opened on such a run, so there is no GTK thread for it
    // to be wrong on.  The wait below is the same either way.
    if display_thread.is_none() && ask_for_disk {
        manager.set_asking(true, "waiting for the root disk's password");
        let disk = root_disk.clone();
        let answer = disk_answer.clone();
        let failed = disk_failed.clone();
        std::thread::Builder::new()
            .name("desk-disk-question".into())
            .spawn(move || match dc_session::diskpass::ask_about(&disk) {
                Ok(passphrase) => {
                    milestone!(
                        "the disk's password was given ({} byte(s)); the guest opens the disk with it",
                        passphrase.expose().map(|b| b.len()).unwrap_or(0)
                    );
                    answer.set(passphrase);
                }
                Err(e) => {
                    if let Ok(mut slot) = failed.lock() {
                        *slot = Some(format!("{e}"));
                    }
                }
            })
            .context("the disk's question")?;
    }

    // ---------------------------------------------------------------- the machine
    //
    // **Not before the question is answered**: a run that cannot be answered must not have started
    // a guest (and on this path the guest is the only thing that could open the disk).
    // **The disk the window may have named instead of the missing one**: the run boots what the
    // window saved, not what this function read before the window opened.
    if let Some(missing) = &make_disk {
        if let Ok(slot) = missing.chosen.lock() {
            if let Some(chosen) = slot.as_ref() {
                root_disk = chosen.clone();
                spec.root.path = chosen.clone();
            }
        }
    }

    if (ask_for_disk || make_disk.is_some()) && display_thread.is_some() {
        // The window's thread is up: the disk (when there is none) and the question are on their
        // way, and this is the wait.  A person takes as long as they take — there is **no timeout
        // on a question**.
        loop {
            if let Ok(slot) = disk_failed.lock() {
                if let Some(said) = slot.as_ref() {
                    anyhow::bail!("{said}");
                }
            }
            if let Some(passphrase) = disk_answer.take() {
                milestone!(
                    "the disk's password was given ({} byte(s)); the guest opens the disk with it",
                    passphrase.expose().map(|b| b.len()).unwrap_or(0)
                );
                spec.root_passphrase = passphrase
                    .expose()
                    .map(|bytes| String::from_utf8_lossy(bytes).to_string());
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    } else if let Some(passphrase) = stdin_passphrase {
        spec.root_passphrase = Some(passphrase);
    } else if ask_for_disk {
        // The windowless path: the answer (or the failure) arrives on the question's own thread.
        loop {
            if let Ok(slot) = disk_failed.lock() {
                if let Some(said) = slot.as_ref() {
                    anyhow::bail!("{said}");
                }
            }
            if let Some(passphrase) = disk_answer.take() {
                spec.root_passphrase = passphrase
                    .expose()
                    .map(|bytes| String::from_utf8_lossy(bytes).to_string());
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    milestone!(
        "starting: {} vCPU, {} MiB, the system on {} ({})",
        spec.vcpus,
        spec.memory_mib,
        root_disk.display(),
        firecracker.display()
    );
    let mut run = fc_run::start(spec, true)?;

    // The pixels: the guest's rectangles, applied to the window's own picture (`dc-fc-window`).
    let started_pixels = run.display().map(|display| {
        let sink = dc_fc_window::Input::new(display.service());
        if let Ok(mut slot) = input.lock() {
            *slot = Some(sink as Arc<dyn InputSink>);
        }
        let pixels = dc_fc_window::Pixels::start(display_state.clone(), display.service());
        if let Ok(mut slot) = pixels_slot.lock() {
            *slot = Some(pixels.clone());
        }
        pixels
    });

    // ---------------------------------------------------------------- the guest
    let ready = match run.wait_for_guest() {
        Ok(line) => line,
        Err(e) => {
            // **A disk that would not open ends the run here**, with the guest's own words about
            // it rather than a boot time-out: the guest's initramfs is what opens the container,
            // so a wrong passphrase is something only the guest can tell us (its `DESK-ROOT
            // wrong-password` line).  A machine that reports a raw refusal rather than a
            // machine refused the disk while it was being built — and a run that failed for
            // another reason (a missing kernel, a locked image) says that instead.
            let console = run.vm.console().text();
            let _ = run.shutdown();
            if let Some(line) = console.lines().rev().find(|l| {
                l.contains("DESK-ROOT") && (l.contains("password") || l.contains("locked"))
            }) {
                anyhow::bail!("the root disk was not opened: {line}");
            }
            anyhow::bail!("{e}");
        }
    };
    milestone!("the guest said: {ready}");
    // **The project's own milestone for "the guest is up"** (Console: ; a
    // prints the same sentence, and it is what a person — and the plugin's own contract's
    // event stream — watches for).  The guest's meaning is unchanged: it is printed once the
    // guest's own landmark has arrived *and* the disk it was given answered.
    let up = std::time::Instant::now();

    // **The disk's own answer, when there is one to hear.**  When the *machine* opens
    // the container while it is being built, so a wrong passphrase fails before a guest exists; on
    // this path the guest's initramfs is what opens it, and its refusal arrives a moment after its
    // landmark.  Waiting for the guest's own line — inside the same bound the boot had — is what
    // turns a run that would have gone on for minutes into one that ends with the guest's own
    // sentence (`DESK-ROOT wrong-password the password did not open the container`).
    if ask_for_disk {
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        loop {
            let console = run.vm.console().text();
            let refused = console
                .lines()
                .rev()
                .find(|l| {
                    l.contains("DESK-ROOT")
                        && (l.contains("wrong-password")
                            || l.contains("could not be unlocked")
                            || l.contains("container was refused"))
                })
                .map(|l| l.to_string());
            if let Some(line) = refused {
                let _ = run.shutdown();
                anyhow::bail!("{line}");
            }
            // It got past the disk (the guest's own line says so) or it never will: either way
            // this wait is over.
            if console.contains("DESK-ROOT password ok") || std::time::Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    milestone!("guest ready in {:.1}s", up.elapsed().as_secs_f64());
    manager.set_phase(Phase::Running, "the guest is up");
    // **`--ready-file PATH`**: the file a caller watches to know the guest is up.  At
    // path the *guest* writes it (its own tools, into the shared control directory); on this path
    // the guest's files travel the control channel, so the host writes the marker the moment the
    // guest's own landmark arrived — the same fact, and the only place it can be written without
    // asking the guest for a second thing.
    if let Some(path) = &cli.ready_file {
        if let Some(dir) = path.parent() {
            let _ = dc_common::fs::create_dir_all(dir);
        }
        let _ = dc_common::fs::write_atomic(path, format!("{ready}\n").as_bytes());
    }
    if let Ok(mut info) = pinning.lock() {
        *info = crate::plugin::pinning_info(&run);
    }
    let _ = &plugin;
    // **The guest's second landing**, when it has one: a run whose guest is the **system on the
    // disk** reports `DESK-READY system …` once that system has started the guest's own session
    // (`desk-agent.service`: the screen, the sound, the shares and the network).  A run whose
    // guest stayed in its initramfs never reports it — and saying which of the two happened is
    // what a person needs when the window shows a console instead of a desktop.
    match run.wait_for_session(Duration::from_secs(45)) {
        Some(line) => milestone!("the guest's own session said: {line}"),
        None => milestone!(
            "the guest's session did not report: the window will show the guest's console (the \
             system on the disk did not bring its session up)"
        ),
    }

    // The guest's own numbers, and one step of the memory policy (the project's balloon policy,
    // driven by the guest's own statistics — `GET /balloon/statistics` here).
    if let Some(memory) = run.guest_memory() {
        milestone!(
            "memory: the guest has {:.0} MiB, {:.0} MiB free",
            memory.total as f64 / (1024.0 * 1024.0),
            memory.free as f64 / (1024.0 * 1024.0)
        );
    }
    match run.balloon_step() {
        Ok(Some(line)) => milestone!("{line}"),
        Ok(None) => {}
        Err(e) => milestone!("the balloon: {e}"),
    }

    // **The ssh forward**: the host's loopback port becomes a
    // connection to the guest's sshd.  `--ssh-port` or the settings' `ssh_port` — the one rule,
    // decided above — and with neither, no socket is opened at all.
    if let Some(network) = run.network() {
        match run.spec.ssh_port {
            Some(port) => match network.forward_ssh(port) {
                dc_net::ForwardStatus {
                    state: dc_net::ForwardState::Bound,
                    host,
                    guest_port,
                } => milestone!(
                    "ssh: {host} is forwarded to the guest's sshd (the guest's port {guest_port}); \
                     it is on the host's loopback, so only this machine can reach it"
                ),
                dc_net::ForwardStatus {
                    state: dc_net::ForwardState::Failed(reason),
                    ..
                } => milestone!("ssh: not forwarded ({reason})"),
            },
            None => milestone!(
                "ssh: no port (--ssh-port or the settings' ssh_port), so no socket \
 is open on the host"
            ),
        }
    }

    // ---------------------------------------------------------------- run
    //
    // The window's own exit (`Esc` in it, the tray, a plugin's `exit` action), `--run-seconds`, or
    // the guest going away — the three endings a run has.
    let started = std::time::Instant::now();
    let mut published_revision = 0u64;
    // **The guest's console**, echoed the way Console: says: what the guest prints is
    // what a person reads.  It is read from the child's own stream (Firecracker's stdout, which
    // is the guest's serial) and nothing of it is written to disk.
    let console = run.vm.console().clone();
    let mut cursor = 0usize;
    loop {
        if window.exit_requested() || ui.exit_requested.load(Ordering::Relaxed) {
            milestone!("the window asked to finish");
            break;
        }
        if let Some(seconds) = cli.run_seconds {
            if started.elapsed() >= Duration::from_secs(seconds) {
                milestone!("--run-seconds {seconds}: the run is over");
                break;
            }
        }
        if run.vm_exited() {
            milestone!("the guest went away");
            break;
        }
        // **What the guest's own library reads** (`tools/libdesk`): the display's state, in
        // the control share, written when it changes — the file and the fields the guest's own
        // path writes.
        publish_display_state(&run, &window_state, &mut published_revision);
        for line in console
            .since(&mut cursor)
            .lines()
            .filter(|l| !l.trim().is_empty())
        {
            println!("[guest] {line}");
        }
        for report in run.drain_reports() {
            println!("run: the guest reported: {report}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // ---------------------------------------------------------------- shutdown
    manager.set_phase(Phase::Stopping, "shutting the guest down");
    milestone!("shutting the guest down");
    let ended = run.shutdown()?;
    milestone!("{ended}");
    if let Some(display) = run.display() {
        let counters = display.counters();
        milestone!(
            "screen: {} rectangle(s), {} B, largest {} px",
            counters.rectangles,
            counters.bytes,
            counters.largest
        );
    }
    if let Some(pixels) = started_pixels {
        pixels.stop();
    }
    if let Some(audio) = run.audio() {
        let counters = audio.counters();
        milestone!(
            "audio: {} stream(s), {} buffer(s), {} KiB, {} played, {} discarded",
            counters.streams,
            counters.buffers,
            counters.bytes >> 10,
            counters.played,
            counters.discarded
        );
    }
    drop(display_thread);
    dc_plugin::uninstall();
    // **The secrets go with the run** (`AGENTS.md`): the guest had what it needed.  The run's own
    // directory — its sockets and the control directory among them — goes with it here, because
    // `run_dir` is a `PrivateDir`: it is removed when it is dropped, whichever way this function
    // ended (The run's own sockets: a finished run leaves nothing behind).
    Ok(())
}

/// **Is this disk a container?**  Read from the image's own **first 512 bytes**, which is what the
/// LUKS header is and what a `LUKS\xba\xbe` magic means — the same question the disk tool answers
/// on this path (`dc-fc-disk::image::is_luks`).
///
/// It is deliberately **not** `dc_disk::luks_container`: that one asks an external tool, and a
/// host without it is told "no container" — which would mean the run never asks for the passphrase
/// at all, and a guest that needs one would sit in its initramfs saying so (measured 2026-10-10:
/// `DESK-ROOT no password was provided for the root disk; the host asks the user and starts this
/// guest again`, with the question never asked).  The first 512 bytes are the header, and reading
/// them needs nothing at all.
fn disk_is_encrypted(path: &std::path::Path) -> bool {
    dc_fc_disk::image::is_luks(path)
}

/// **Is this a wrapped image?** A raw disk this project makes begins with a partition table or a
/// LUKS header; a `.qcow2` (or anything else another tool wrapped a disk in) begins with its own
/// magic instead, and Firecracker attaches **raw** images and nothing else.  Saying so, before the
/// machine starts, is the difference between a person knowing what to do and a run that fails with
/// a device the guest cannot read.
fn is_a_wrapped_image(path: &std::path::Path) -> bool {
    use std::io::Read;
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic).is_ok() && magic == [b'Q', b'F', b'I', 0xfb]
}

/// The disks the settings and `--disk` name: attached to the guest as devices of their own, and
/// **nothing else happens** — the user mounts them inside the guest (`desk-disk-mount`), and
/// the application never asks for their password.
fn attached_disks(settings: &dc_settings::Settings, cli: &Cli) -> Vec<dc_fc_vm::Disk> {
    let mut disks = Vec::new();
    for (index, disk) in settings.disks_to_attach().enumerate() {
        let name = if disk.tag.is_empty() {
            format!("disk{}", index + 1)
        } else {
            disk.tag.clone()
        };
        announce_disk(&name, &disk.path, disk.mode.is_read_only());
        disks.push(dc_fc_vm::Disk {
            name,
            path: disk.path.clone(),
            read_only: disk.mode.is_read_only(),
        });
    }
    for (path, mode) in &cli.disks {
        let name = path
            .file_stem()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| format!("disk{}", disks.len() + 1));
        announce_disk(&name, path, mode.is_read_only());
        disks.push(dc_fc_vm::Disk {
            name,
            path: path.clone(),
            read_only: mode.is_read_only(),
        });
    }
    disks
}

/// **One line per attached disk**, in the project's own shape (the same
/// sentence): what it is, where it is, whether it is a container, and the one thing the
/// application does with it — attach it.  A disk whose password is the user's is opened **inside**
/// the guest (`desk-disk-mount open NAME`), never here.
fn announce_disk(name: &str, path: &std::path::Path, read_only: bool) {
    if !path.exists() {
        milestone!(
            "disk {name}: {} does not exist; it is not attached",
            path.display()
        );
        return;
    }
    let shape = if dc_fc_disk::image::is_luks(path) {
        "LUKS: opened inside the guest, with the user's password"
    } else {
        "plain"
    };
    milestone!(
        "disk {name}: {} ({shape}, {}) — attached to the guest, which is where the user mounts it",
        path.display(),
        if read_only { "ro" } else { "rw" }
    );
}

/// The sound: **the project's own rule** (`dc-audio::AudioPath`), with the host's own output
/// device when there is one and a counter when there is not.  The guest's card (`snd-aloop`) is
/// what produces the bytes, and this is what decides whether the user hears them.
fn audio_path(window: &Arc<WindowState>) -> Arc<dyn dc_fc_audio::Play> {
    let sink: Arc<dyn dc_audio::Sink> = match dc_audio::PulseSink::open(Default::default()) {
        Some(sink) => Arc::new(sink),
        None => {
            milestone!("audio: no host sound device; the rule still decides what is discarded");
            dc_audio::CountingSink::new()
        }
    };
    Arc::new(dc_audio::AudioPath::new(window.clone(), sink))
}

/// **What the guest's own library reads**: the display's state, in the control share, written only
/// when it changes (a poll of an unchanged pair of values is free for the guest).  What
/// writes the same file with the same fields.
fn publish_display_state(run: &Started, state: &Arc<WindowState>, published: &mut u64) {
    let Some(control) = run.control() else { return };
    let (revision, changed_ms) = state.revision();
    if revision == *published {
        return;
    }
    *published = revision;
    let (width, height) = state.size();
    let status = match state.gate() {
        dc_display::window::Gate::Open | dc_display::window::Gate::NumlockNotHeld => {
            DISPLAY_VISIBLE
        }
        dc_display::window::Gate::WindowHidden => DISPLAY_HIDDEN,
    };
    let text = format!(
        "status={status}\nvisible={}\nnumlock={}\nwidth={width}\nheight={height}\nrevision={revision}\nchanged_ms={changed_ms}\nchanged_unix={}\n",
        state.visible() as u8,
        state.numlock_held() as u8,
        changed_ms / 1000,
    );
    control.publish("display-state", text);
}

/// **The run's own bookkeeping** (`dc-common::manager`): the phase a person reads and the plugin
/// gets as `/status`'s `state` (`booting` → `asking` → `running` → `stopping`), and the events
/// along the way.  It is the project's own manager, so a
/// run on this path reports itself the way the other one does.
pub fn manager() -> &'static Manager {
    static MANAGER: std::sync::OnceLock<Manager> = std::sync::OnceLock::new();
    MANAGER.get_or_init(|| {
        let manager = Manager::new();
        manager.set_phase(Phase::Booting, "the application is starting the microVM");
        manager
    })
}

/// What the plugin's hooks read from the run: the display's surface,
/// the window's own state and actions, and where the vCPUs are pinned.
#[derive(Default)]
pub struct PluginCells {
    pub display: Option<Arc<Display>>,
    /// The pictures this path produced (`dc-fc-window::Pixels`), for `/status`'s frame count.
    pub pixels: Option<Arc<Mutex<Option<Arc<dc_fc_window::Pixels>>>>>,
    pub window: Option<Arc<WindowControl>>,
    pub state: Option<Arc<WindowState>>,
    pub ui: Option<Arc<UiState>>,
}

/// `dc-fc-window`'s own forward declarations for the plugin's frame pull: the picture the window
/// is about to draw, with the guest's pointer already on it.
pub fn composited_frame(display: &Display) -> (Vec<u8>, u32, u32, u32) {
    let cursor = display.cursor.lock().ok().map(|c| c.clone());
    let blit = |frame: &mut Vec<u8>, width: u32, height: u32| {
        if let Some(cursor) = &cursor {
            cursor.draw_onto(frame, width, height, width * 4);
        }
    };
    let blit: &dc_display::Compositor = &blit;
    display.composited_bgra(Some(blit))
}
