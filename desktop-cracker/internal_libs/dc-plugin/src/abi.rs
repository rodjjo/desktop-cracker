//! The **plugin ABI**: the one thing the application and a plugin must agree on.
//!
//! `--plugin-path PATH` makes the application `dlopen` a shared library and hand it a
//! [`HostApi`] (what the plugin may pull from the run); the library hands back a
//! [`HookTable`] (what it takes over).  Nothing here is a cargo dependency edge: the plugin is
//! never linked, and a run without `--plugin-path` never looks at any of it.
//!
//! The whole surface is **C**: `*const c_char` strings, `i32` results, no Rust types with a
//! layout of their own crossing the boundary, and no allocation moving in either direction
//! without a matching free.  That is what makes the file the contract rather than a convention.

use std::os::raw::{c_char, c_int};

/// The ABI the two sides speak.
///
/// **Version 2** added [`PinningInfo`]: the vCPU pins the application applies to the microVM
/// (the frame is the one thing this ABI has that pulls rather than pushes, and a test that
/// measures scheduling needs it).
///
/// A plugin whose table says something else is **refused**: the application says so in one
/// line and runs its normal path.  There is no negotiation and no compatibility range — the
/// plugin is built from this repository.
pub const ABI: u32 = 2;

/// The one symbol a plugin must export.
pub const SYMBOL: &[u8] = b"desk_plugin_init\0";

/// What a pulled frame looks like: the guest's screen, as the window is about to draw it.
///
/// `data` is BGRA in memory (the layout the guest's own scanout has), `stride` bytes per row.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FrameInfo {
    pub data: *const u8,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
}

/// What the application knows about the run, for `/status`.
///
/// What is **not** here is what the plugin knows itself — the events it could not hand to a
/// client, for instance: the application has no way to know that, and asking it would be asking
/// the wrong process.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct RunStatus {
    /// Frames the window has drawn.
    pub frames: u64,
    /// The guest's geometry, 0x0 before its first scanout.
    pub width: u32,
    pub height: u32,
    /// Is the display window on screen?  (`/status` says so; the rule that hides it —
    /// `numlock + F9`, a plugin's own action — is what a test watches.)
    pub visible: u32,
    /// Does the run see numlock held? (The key the two chords are made of, as the window reads
    /// it.  It is not the sound rule: the sound follows `visible` alone.)
    pub numlock: u32,
    /// **How far behind the picture is**: the rectangles waiting to be uploaded.
    ///
    /// A window that has frozen and a window that is merely behind look the same on screen, and
    /// from outside these two numbers are what tells them apart: the queue growing (with the
    /// oldest rectangle getting older) is a window that cannot keep up, while a queue at zero and
    /// a picture that does not change is a guest that has stopped drawing.  A backend that has
    /// nothing to say leaves them at zero.
    pub damage_waiting: u32,
    /// The age of the oldest waiting rectangle, in milliseconds (0 when nothing waits).
    pub damage_oldest_ms: u32,
}

/// **Where the microVM's vCPUs are pinned**, as the application applied it.
///
/// A microVM's vCPUs are pinned to the host's *physical cores* by default (see
/// `dc_common::cpu`); this is the frame a client reads to see the fact rather than the
/// milestone: which CPU each vCPU thread was put on, the host's core count, and how many
/// threads the application has pinned so far (a guest with many vCPUs brings them up over a
/// moment, and the pinning follows).
///
/// Everything here is a small integer: `format` is 0 (nothing to report), 1 (a vCPU list the
/// application read from the kernel's topology) or 2 (the online CPUs — a host whose topology
/// could not be read, which is itself worth seeing).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PinningInfo {
    /// 0 none, 1 from the kernel's topology, 2 the online CPUs.
    pub format: u32,
    /// The CPUs of the microVM's own mask.
    pub cpus: [u32; MAX_PIN_CPUS],
    /// How many of `cpus` are meaningful.
    pub cpus_len: u32,
    /// How many vCPU threads have been pinned to a core of their own.
    pub vcpus_pinned: u32,
    /// How many vCPUs the machine has.
    pub vcpus: u32,
    /// The host's physical core count.
    pub host_cores: u32,
}

impl Default for PinningInfo {
    fn default() -> Self {
        PinningInfo {
            format: 0,
            cpus: [0; MAX_PIN_CPUS],
            cpus_len: 0,
            vcpus_pinned: 0,
            vcpus: 0,
            host_cores: 0,
        }
    }
}

/// How many CPUs one microVM's list may hold (the ABI is a fixed-size frame; this project's
/// machines have at most 64 vCPUs, `dc-settings`' own ceiling).
pub const MAX_PIN_CPUS: usize = 64;

/// What the plugin may **pull** from the application.
///
/// Every entry is optional on the application's side too: a callback the application does not
/// implement is null, and a plugin must cope with that (answering "no answer" is always a legal
/// answer).
#[repr(C)]
pub struct HostApi {
    pub abi: u32,
    /// The application's name and version, for `/status`.
    pub app_name: *const c_char,
    pub app_version: *const c_char,
    /// Copy the frame the window is about to draw into `out` (`cap` bytes), and fill `info`
    /// when it is not null.  Returns the **size it needs** (0 when nothing has been drawn yet),
    /// so a caller asks once with a null buffer and then with enough room.
    ///
    /// # Safety
    ///
    /// Called by the plugin from any thread; the application must be able to answer it without
    /// waiting for anything (it copies what is there, it does not wait for a frame).
    pub frame: Option<extern "C" fn(out: *mut u8, cap: usize, info: *mut FrameInfo) -> usize>,
    /// The run's counters; returns 0 on success.
    pub status: Option<extern "C" fn(out: *mut RunStatus) -> c_int>,
    /// Run one of the **window's own actions** (the same names the keys have): `hide-or-show`,
    /// `hide-and-settings`.  Returns 0 when it ran, 1 when the application does not know that
    /// action, 2 when it ran and failed.
    pub action: Option<extern "C" fn(action: *const c_char) -> c_int>,
    /// **Where the microVM's vCPUs are pinned**; returns 0 on success (and fills nothing but
    /// `format: 0` when there is no pinning to report).
    pub pinning: Option<extern "C" fn(out: *mut PinningInfo) -> c_int>,
}

/// What a plugin answers to a question.
///
/// `kind` says which field means something: 0 is "no answer" (every field ignored), 1 is
/// [`Answer::password`], 2 is [`Answer::confirm`].
#[repr(C)]
pub struct Answer {
    pub kind: u32,
    /// A password, owned by the plugin: the application frees it with [`HookTable::free`].
    pub password: *mut c_char,
    pub confirm: c_int,
}

/// The kind of a question, as the plugin receives it in
/// [`HookTable::ask`].
pub const ASK_NONE: u32 = 0;
pub const ASK_PASSWORD: u32 = 1;
pub const ASK_CONFIRM: u32 = 2;

/// What a plugin takes over.
///
/// A null entry means "the plugin does not provide this hook", and the application then does
/// exactly what it does with no plugin at all.
#[repr(C)]
pub struct HookTable {
    /// [`ABI`].
    pub abi: u32,
    /// The plugin's own name, for the one line the application prints when it loads it.
    pub name: *const c_char,
    /// A milestone line the application has just written: `level` is `info` or `warn`.
    pub log: Option<extern "C" fn(level: *const c_char, message: *const c_char)>,
    /// The run's state changed: `booting`, `asking`, `running`, `stopping`, `exited` (the same
    /// words `/status` answers with).
    pub state: Option<extern "C" fn(state: *const c_char)>,
    /// The application is about to draw a new frame — a `frame` event for the plugin's clients.
    pub frame_ready: Option<extern "C" fn()>,
    /// **Called once, right after the plugin is loaded**: the plugin waits here until its first
    /// client connects.
    ///
    /// It exists so that the *application* never waits on a clock of its own: the question that
    /// follows (the root disk's passphrase) is asked within milliseconds of loading, and a client
    /// needs the port to be listening — so a run started with `--plugin-path` waits here, in the
    /// plugin, until whoever is driving the run connects and answers.  A run without a plugin
    /// never reaches this code at all.
    pub wait_first_client: Option<extern "C" fn()>,
    /// **Answer a question.**  `kind` is a pointer to a NUL-terminated
    /// `disk-password`/`unlock-password`/`confirm`, `prompt` and `detail` are what the dialog
    /// would have shown.  The call **blocks the application**, which is waiting for this answer,
    /// and returns "no answer" when the plugin has no client to ask (or the client says so).
    ///
    /// The application keeps no timeout of its own: a plugin that cannot answer answers at once,
    /// and the human path stays unbounded.
    pub ask: Option<
        extern "C" fn(
            kind: *const c_char,
            prompt: *const c_char,
            detail: *const c_char,
            answer: *mut Answer,
        ),
    >,
    /// Free a password the plugin handed out in an [`Answer`].
    pub free: Option<extern "C" fn(password: *mut c_char)>,
    /// The run is ending: stop serving, close every connection and join the plugin's threads.
    /// Called once, before the library is unloaded.
    pub shutdown: Option<extern "C" fn()>,
}

/// The type of [`SYMBOL`]: the plugin's entry point.
pub type PluginInit = extern "C" fn(host: *const HostApi) -> *const HookTable;

// The tables and the host's API are plain C: function pointers and pointers to strings that the
// other side keeps alive.  They are read from any thread of the application (a hook is called
// where the thing happened), which is exactly what `Sync`/`Send` mean here.
unsafe impl Send for HostApi {}
unsafe impl Sync for HostApi {}
unsafe impl Send for HookTable {}
unsafe impl Sync for HookTable {}
