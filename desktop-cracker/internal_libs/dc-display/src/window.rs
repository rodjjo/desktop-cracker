//! The window: a **GTK3 window** whose content is a `gtk::GLArea`, the guest framebuffer as a
//! texture, and the keyboard/mouse that go back to the guest while the window has focus.
//!
//! Everything the application puts on screen — this window, the disk's password dialog, the
//! settings window, the close question — is a GTK window of **one thread** with **one GTK main
//! loop**.  That is the fix for the dialog that stayed on screen after it had answered: a
//! dialog's `destroy()` has to happen on the thread that runs the loop, and there used to be
//! four threads each starting their own GTK.
//!
//! Two of the project's rules live here:
//!
//! * **the display rule**: the window is the guest's screen at
//! its own size — 1280x800 centered, or FULL_SCREEN_RESOLUTION borderless — whatever
//! the numlock key is doing. The key is still read, globally and every frame, because
//! it is what the two chords are made of (`numlock + F9`, `numlock + F10`) and what the
//! sound rule opens and closes; it is **not** what the window's size or its picture depends
//! on.
//!   This is not the numlock *state*, it is whether the key is pressed at this
//!   moment — so it is a key press/release fact, and the window acts on it at
//!   once;
//! * **input only while focused** (the keyboard and mouse are handled
//!   "when focused"): a window that does not have focus must not steal the
//!   user's typing.
//!
//! The GL calls are the compatibility ones (`glTexSubImage2D` + a textured
//! quad), which is what a straight-through blit of a 32-bit framebuffer needs:
//! the pixels arrive already in the guest's format, so the fastest path is to
//! upload exactly the damaged rows and draw one quad.

use glow::HasContext as _;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::gtk_window::Platform;
use crate::{Display, InputSink, PixelLayout};

/// How often the window is drawn and the numlock key checked, in hertz (the operator asked
/// for 30).
pub const NUMLOCK_HZ: u32 = 30;

/// What the key loop reports: the hotkey chords, on their rising edge.
///
/// It is a trait rather than a channel because the application decides what a chord *means* (a
/// password question, a settings window, a hide) and the loop must never wait for that decision:
/// `fire` returns at once, and the work happens where the loop can carry on.
pub trait HotkeySink: Send + Sync {
    /// A chord was pressed: `numlock + F9` or `numlock + F10`.
    fn fire(&self, hotkey: crate::xinput::Hotkey);
}

/// Why the guest's audio is (or is not) being heard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    /// The window is visible *and* numlock is held: play it.
    Open,
    /// The window is not visible (it is hidden with the keys).
    WindowHidden,
    /// The window is visible but numlock is not held: the key is not there, and the
    /// rule is about the key.
    NumlockNotHeld,
}

impl Gate {
    pub fn is_open(self) -> bool {
        matches!(self, Gate::Open)
    }

    pub fn reason(self) -> &'static str {
        match self {
            Gate::Open => "playing",
            Gate::WindowHidden => "the window is hidden",
            Gate::NumlockNotHeld => "numlock is not held",
        }
    }
}

/// What the window tells the audio path about itself.  `dc-display`'s window
/// owns these two facts, and they are exactly the two the rule needs.
#[derive(Debug, Default)]
pub struct WindowState {
    visible: AtomicBool,
    numlock_held: AtomicBool,
    /// The window's size, which is the guest's screen as the rule has it: the guest's own
    /// size, or FULL_SCREEN_RESOLUTION while the window is full screen. `0x0` is a window
    /// that has not published one yet.
    width: AtomicU64,
    height: AtomicU64,
    /// A counter bumped whenever any of the above changes, and the time it
    /// changed.  A reader **outside** this process — a guest application looking
    /// at the file the host publishes — cannot be called back, so it polls; the
    /// counter is what lets it tell a change from a repeat, and the time is what
    /// tells it the value is fresh.
    revision: AtomicU64,
    changed_ms: AtomicU64,
}

impl WindowState {
    pub fn new() -> Arc<WindowState> {
        Arc::new(WindowState {
            // A window that has not said anything yet is *not* audible: the rule
            // fails closed, which is the only safe direction for "suddenly loud".
            visible: AtomicBool::new(false),
            numlock_held: AtomicBool::new(false),
            width: AtomicU64::new(0),
            height: AtomicU64::new(0),
            revision: AtomicU64::new(1),
            changed_ms: AtomicU64::new(0),
        })
    }

    pub fn set_visible(&self, visible: bool) {
        if self.visible.swap(visible, Ordering::Relaxed) != visible {
            self.bump();
        }
    }

    pub fn set_numlock_held(&self, held: bool) {
        if self.numlock_held.swap(held, Ordering::Relaxed) != held {
            self.bump();
        }
    }

    pub fn set_size(&self, width: u32, height: u32) {
        let (w, h) = (width as u64, height as u64);
        let was_w = self.width.swap(w, Ordering::Relaxed);
        let was_h = self.height.swap(h, Ordering::Relaxed);
        if was_w != w || was_h != h {
            self.bump();
        }
    }

    /// A change happened: the revision moves on and the time is recorded.
    fn bump(&self) {
        self.changed_ms
            .store(dc_common::now_millis(), Ordering::Relaxed);
        self.revision.fetch_add(1, Ordering::Relaxed);
    }

    /// The revision, and when it last changed (milliseconds since the epoch).
    pub fn revision(&self) -> (u64, u64) {
        (
            self.revision.load(Ordering::Relaxed),
            self.changed_ms.load(Ordering::Relaxed),
        )
    }

    pub fn visible(&self) -> bool {
        self.visible.load(Ordering::Relaxed)
    }

    pub fn numlock_held(&self) -> bool {
        self.numlock_held.load(Ordering::Relaxed)
    }

    pub fn size(&self) -> (u32, u32) {
        (
            self.width.load(Ordering::Relaxed) as u32,
            self.height.load(Ordering::Relaxed) as u32,
        )
    }

    /// The rule, in one place.
    pub fn gate(&self) -> Gate {
        if !self.visible() {
            Gate::WindowHidden
        } else if !self.numlock_held() {
            Gate::NumlockNotHeld
        } else {
            Gate::Open
        }
    }
}

/// The two shapes the display rule puts the window in.
///
/// It is the *rule*, in one value, so that every part of the rule can be checked
/// without a screen — and so the window itself only has to ask one question per
/// frame instead of testing focus and the resolution separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// The user's own: the keys' `Hide`, in the request that follows.
    Hidden,
    /// The resolution is FULL_SCREEN_RESOLUTION: "borderless and full screen".
    FullScreen,
    /// Any other resolution: the window at the guest's own size, centered on the
    /// screen (1280x800 by default).
    Normal,
}

impl Shape {
    /// Does entering this shape mean "the numlock key is held"?
    ///
    /// **No shape does.** The key drives the two chords and the sound rule; it never decides
    /// the window's size or its picture, and a shape that claimed it would be a rule that
    /// stopped following the keyboard: measured, the window then stayed small and black while
    /// the key was held (the operator: "pressing numlock the display window does not go normal,
    /// I was not able of using the system").
    pub fn forces_numlock(self) -> bool {
        false
    }
}

/// The rule itself: which shape this window has right now.
///
/// Read it as this project's own list of behaviours, in its order: hidden
/// stays hidden; otherwise the **resolution** decides — the host's own screen (or
/// 1920x1080 when there is none to ask) is borderless full screen, anything else is
/// the guest's window at the guest's own size. The window is never resized down and
/// never painted black: the numlock key is read globally, but it is not what this
/// rule is about.
pub fn shape_for(
    hidden: bool,
    focused: bool,
    numlock_held: bool,
    width: u32,
    height: u32,
) -> Shape {
    let _ = focused;
    let _ = numlock_held;
    if hidden {
        Shape::Hidden
    } else if is_full_screen_resolution(width, height) {
        Shape::FullScreen
    } else {
        Shape::Normal
    }
}

/// The design: "If the display resolution is 1920 x 1080 the display is borderless
/// and full screen".
pub const HD_WIDTH: u32 = 1920;
/// The height of the resolution the full-screen rule is about.
pub const HD_HEIGHT: u32 = 1080;

/// Is this the resolution the full-screen rule names?
pub fn is_hd(width: u32, height: u32) -> bool {
    width == HD_WIDTH && height == HD_HEIGHT
}

/// The **full-screen resolution**: the host's own display, and 1920x1080 when it cannot be read.
///
/// Display: (the operator's words): "a resolution of 1280x800 we have the window
/// centered in the screen, however for bigger resolution, we need to detect the host
/// resolution; if it is widescreen like 2560x1080 we use that as resolution for our display
/// when we are in fullscreen mode, otherwise 1920x1080.  The full screen resolution is the
/// same resolution as the current user's host display resolution, lets call it
/// FULL_SCREEN_RESOLUTION."
///
/// So a full-screen window fills the host's own screen — no mode switch, no letterboxing, and
/// the guest's display is the size the user actually has.
pub fn full_screen_resolution() -> (u32, u32) {
    match crate::xinput::screen_size() {
        Some((w, h)) if w >= HD_WIDTH && h >= 800 => (w, h),
        _ => (HD_WIDTH, HD_HEIGHT),
    }
}

/// Is this the full-screen resolution (the host's own, or the one this project uses)?
pub fn is_full_screen_resolution(width: u32, height: u32) -> bool {
    (width, height) == full_screen_resolution() || is_hd(width, height)
}

/// The shape a window is created in, and the size that means: the window opens at the
/// resolution's shape — full screen when the resolution is FULL_SCREEN_RESOLUTION, the guest's
/// own size otherwise (1280x800 by default) — and hidden when the run asked for that.
pub fn initial_shape(config: &WindowConfig) -> (Shape, u32, u32) {
    let initial = if config.hidden_initially {
        Shape::Hidden
    } else {
        shape_for(
            false,
            true,
            config.numlock_held_initially,
            config.width,
            config.height,
        )
    };
    (initial, config.width, config.height)
}

/// Something else that owns the window: the keys and the application's own loops.
///
/// `hidden` is answered once per frame, and the window **reports back** what it did through
/// `observe`: a show or a hide is carried out by the window (it is what draws, so it is what
/// hides), and the owner is told, so nothing is left asking for a state the window is no longer
/// in.  The window asks it, once per frame, whether it should be hidden, shown, or stop — which
/// keeps the keys' work off the main loop.
pub trait Control: Send + Sync {
    /// Should the window be off the screen?  (`numlock + F9`/`F10` set it, and the window
    /// carries it out — it is what draws, so it is what hides.)
    fn hidden(&self) -> bool;
    /// **Is this request a change?**  Take the answer: `Some(ask)` is a request the window has
    /// not carried out yet, and `None` is one it already has.
    ///
    /// It exists because the window's own state cannot answer "was anything asked?".  The
    /// application only ever *asks* — `WindowControl::set_visible`, which is also the whole truth
    /// for a session with no window (`--window-command`, a test) — and the window both carries
    /// the ask out and **reports what it did** back into the same control
    /// ([`Control::observe`], which the window calls once a frame).  So the flag can already read
    /// "shown" when the ask
    /// arrives, and a window that compared the two found nothing to do and stayed off the screen
    /// — the operator's own report of 2026-10-09: *"numlock + F9 → the password dialog appears →
    /// …and the display window does NOT become visible"*, with the run saying *"the password was
    /// right: the window is shown"*.  An ask is therefore an ask **whether or not the state
    /// already agrees with it**: the count is what makes it one, and the window compares it with
    /// what it is doing (its own lock), not with what the application last believed.
    ///
    /// A [`Control`] that is not a window's own (a run's own stop flag) keeps the default,
    /// which is the plain reading: every answer is taken as a change, so nothing is lost.
    fn take_request(&self) -> Option<bool> {
        Some(self.hidden())
    }
    /// Should the application shut down?
    fn exit_requested(&self) -> bool;
    /// The window reporting what it is doing, once per frame: it hides (the keys, or a
    /// request it has just carried out) and the owner is told, so nothing is left asking for
    /// a state the window is no longer in.  Default: nothing.
    fn observe(&self, _hidden: bool) {}
    /// The user closed the window (its close button or the window manager's close): the
    /// application asks them whether the whole application should close. Default: nothing.
    fn window_closed(&self) {}
    /// The window asks the application to finish — `Esc` inside it, which is how it
    /// gets out of a full-screen guest whose window has no buttons.  Default: nothing.
    fn request_exit(&self) {}
    /// The window's **X id**, once it exists: what a dialog attaches to so that a question
    /// appears over the guest's screen rather than behind it.  Default: none (a session with
    /// no X, or a window that has not been made yet).
    fn set_x11_id(&self, _id: u64) {}
}

/// What the window reports back to whoever owns it (the application): whether it is hidden.
/// The display calls it once per frame, and the owner reads it as a plain value.
pub type WindowObserver = Arc<dyn Fn(bool) + Send + Sync>;

/// What the **application** writes about the window, and what the window's frame loop reads
/// through [`Control`]: the one place "should it be on screen?", "should we quit?" and "did the
/// user close it?" are answered.
///
/// It replaced the system tray's `WindowHandle` when the tray was removed: the same one-value shape, with the hotkeys and the window's own close
/// button as its writers.
#[derive(Default)]
pub struct WindowControl {
    visible: AtomicBool,
    /// **The window's X id**, when the session has one: a dialog attaches itself to it, which
    /// is what makes a question appear over the guest's screen instead of behind it.  In
    /// memory, deliberately — a file that recorded it would outlive the run that wrote it and
    /// mean nothing afterwards.
    x11_id: std::sync::Mutex<Option<String>>,
    exit: AtomicBool,
    /// The window's own report (see `Control::observe`), once a frame.
    observed_hidden: AtomicBool,
    /// **The application's own asks** (`set_visible`), counted, and how many of them the window
    /// has been handed (see [`Control::take_request`]).
    ///
    /// A counter rather than the state alone, because the state cannot say whether anything
    /// happened: the application asks for a window whose flag already reads the way it wants —
    /// set at startup, or by an earlier ask — and the window still has to be told, or it stays
    /// off the screen (measured, and the
    /// operator's own report of 2026-10-09: the run said *"the password was right: the window is
    /// shown"* and the window did not appear).
    requests: std::sync::Mutex<Requests>,
    /// The user asked to **close** the window: the application asks them whether the whole
    /// application should close.
    close_requested: AtomicBool,
}

/// The application's asks about the window's visibility, and what the window has been told.
#[derive(Default)]
struct Requests {
    /// The state the **last** ask wanted (`true` = hidden).
    hidden: bool,
    asks: u64,
    taken: u64,
}

impl Requests {
    /// The application asks for a state.
    fn ask(&mut self, hidden: bool) {
        self.hidden = hidden;
        self.asks += 1;
    }

    /// The request the window has not carried out yet, handed over exactly once.
    fn take(&mut self) -> Option<bool> {
        if self.asks == self.taken {
            return None;
        }
        self.taken = self.asks;
        Some(self.hidden)
    }
}

impl Control for WindowControl {
    fn hidden(&self) -> bool {
        !self.visible()
    }

    fn take_request(&self) -> Option<bool> {
        WindowControl::take_request(self)
    }

    fn exit_requested(&self) -> bool {
        self.exit.load(Ordering::Relaxed)
    }

    fn observe(&self, hidden: bool) {
        self.observed_hidden.store(hidden, Ordering::Relaxed);
    }

    fn window_closed(&self) {
        self.request_close();
    }

    fn request_exit(&self) {
        WindowControl::request_exit(self);
    }
}

impl WindowControl {
    /// Remember the window's X id (the platform tells us once the window exists).
    pub fn set_x11_id(&self, id: u64) {
        if let Ok(mut slot) = self.x11_id.lock() {
            *slot = Some(id.to_string());
        }
    }

    /// The X id a dialog should attach to, when the window has reported one.
    pub fn x11_id(&self) -> Option<String> {
        self.x11_id.lock().ok().and_then(|slot| slot.clone())
    }

    /// A control with the window **not yet shown**: the application's first `set_visible(true)`
    /// is the show.
    pub fn new() -> WindowControl {
        WindowControl {
            visible: AtomicBool::new(false),
            x11_id: std::sync::Mutex::new(None),
            exit: AtomicBool::new(false),
            observed_hidden: AtomicBool::new(true),
            requests: std::sync::Mutex::new(Requests {
                hidden: true,
                asks: 0,
                taken: 0,
            }),
            close_requested: AtomicBool::new(false),
        }
    }

    /// Should the window be on screen?
    pub fn visible(&self) -> bool {
        self.visible.load(Ordering::Relaxed)
    }

    pub fn set_visible(&self, visible: bool) {
        self.visible.store(visible, Ordering::Relaxed);
        self.observed_hidden.store(!visible, Ordering::Relaxed);
        // **A request, not only a value**: the window is what carries it out (it is what draws),
        // and it is told exactly once per ask — even when the state asked for is the one already
        // held, which is the case the keys' own `show()` leaves behind (see
        // [`Control::take_request`]).
        if let Ok(mut requests) = self.requests.lock() {
            requests.ask(!visible);
        }
    }

    /// **The application's request the window has not carried out yet** (see
    /// [`Control::take_request`]): `Some(ask)`, once per `set_visible`, and `None` when there is
    /// nothing new.
    pub fn take_request(&self) -> Option<bool> {
        self.requests
            .lock()
            .ok()
            .and_then(|mut requests| requests.take())
    }

    /// The window's own report, as a plain value.
    pub fn is_hidden(&self) -> bool {
        self.observed_hidden.load(Ordering::Relaxed)
    }

    /// The user asked to close the window (its close button).
    pub fn request_close(&self) {
        self.close_requested.store(true, Ordering::Relaxed);
    }

    pub fn close_requested(&self) -> bool {
        self.close_requested.load(Ordering::Relaxed)
    }

    pub fn clear_close_request(&self) {
        self.close_requested.store(false, Ordering::Relaxed);
    }

    /// Ask the application to shut down (the key watcher's `exit`).
    pub fn request_exit(&self) {
        self.exit.store(true, Ordering::Relaxed);
    }

    pub fn exit_requested(&self) -> bool {
        self.exit.load(Ordering::Relaxed)
    }

    /// A closure the display can call with what the window is doing (see `Control::observe`).
    pub fn observer(self: &Arc<Self>) -> WindowObserver {
        let me = Arc::clone(self);
        Arc::new(move |hidden| me.observe(hidden))
    }
}

/// What the window needs to know to run.
#[derive(Clone)]
pub struct WindowConfig {
    /// The window title.
    pub title: String,
    /// The size to open at (the guest's geometry may differ; the picture is
    /// scaled to the window).
    pub width: u32,
    pub height: u32,
    /// Start in fullscreen.
    pub fullscreen: bool,
    /// Stop after this long (tests, benchmarks); `None` runs until closed.
    pub run_seconds: Option<u64>,
    /// Start with the window hidden (the keys' `Hide`, and what an unattended run uses to test
    /// that state).
    pub hidden_initially: bool,
    /// Start with numlock treated as held.  On a desktop the physical key
    /// decides (a press or release event overrides this at once); for an
    /// unattended run — a test, a benchmark, a machine with no keyboard — this
    /// is how the "numlock is held" state is produced.
    pub numlock_held_initially: bool,
    /// The application's window control, when there is one: the window polls it (see `Control`).
    pub control: Option<Arc<dyn Control>>,
    /// The state the audio rule reads: the window publishes its visibility and
    /// the numlock key here, and `dc-audio` decides from it.  Sharing the same
    /// value is what keeps the two in step — there is one answer to "is the window visible?",
    /// not two that could disagree.
    pub state: Option<Arc<WindowState>>,
    /// The application's controller, when there is one: the window reads the **guest's**
    /// phase and its last console line from it (so its status line says what the guest is
    /// doing without ever waiting for the guest), and reports its own visibility back
    /// through the same handle.
    pub manager: Option<dc_common::manager::Manager>,
}

impl Default for WindowConfig {
    fn default() -> Self {
        WindowConfig {
            title: "desktop-cracker".into(),
            width: 1280,
            height: 800,
            fullscreen: false,
            run_seconds: None,
            control: None,
            hidden_initially: false,
            numlock_held_initially: false,
            state: None,
            manager: None,
        }
    }
}

/// Why the window could not run.
#[derive(Debug, thiserror::Error)]
pub enum WindowError {
    #[error("the window: {0}")]
    Window(String),
    #[error("OpenGL: {0}")]
    Gl(String),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, WindowError>;

/// The window's **button numbers**: left 0, middle 1, right 2.  They are the numbers this project's
/// pointer path names a button by; the *mask* that travels with every pointer event is a different
/// thing (bit 0 left, bit 1 middle, bit 2 right — the guest's `uinput` device's own packing).
///
/// The wheel is not here, because the wheel is not a button: it is a step on a relative axis
/// (`REL_WHEEL` on the guest's pointer device).  Sending it as a button is how the wheel used to
/// travel, and the guest's device — which offers no such button — threw it away.
pub const BUTTON_LEFT: u32 = 0;
pub const BUTTON_MIDDLE: u32 = 1;
pub const BUTTON_RIGHT: u32 = 2;

/// The GL enums the pixel-layout mapping needs, as numbers (the renderer takes them
/// directly, so the names would only be a second spelling of the same constants).
const GL_RGBA: u32 = 0x1908;
const GL_BGRA_EXT: u32 = 0x80E1;
const GL_UNSIGNED_BYTE: u32 = 0x1401;
const GL_UNSIGNED_INT_8_8_8_8_REV: u32 = 0x8367;

pub struct Window {
    /// The GTK window and its GLArea (raw OpenGL through `glow`).
    platform: Option<Platform>,
    /// The renderer: one program, one streaming texture, one quad.  Built at the first frame,
    /// because that is when GTK has realized the GLArea's context.
    renderer: Option<crate::gl::Renderer>,
    /// The texture's size, as the frame path last saw it (the geometry).
    tex_size: (u32, u32),
    /// The guest's pointer texture's size, for the status line.
    cursor_tex_size: (i32, i32),
    /// Whether there is a real window and GL context.  A headless window runs the same
    /// state machine and the same frame path, without them.
    windowed: bool,
    /// What the application last asked for, so a request is acted on when it *changes*
    /// rather than on every frame (the window may start hidden by configuration,
    /// and the application's steady state must not undo that).
    control_hidden: Option<bool>,
    config: WindowConfig,
    /// The real (guest-sized) dimensions, restored when the window leaves full screen.
    real_size: (i32, i32),
    focused: bool,
    /// The shape the window is in **because of the screen** (it may have been asked
    /// for a shape of its own, by the keys' `Show`): the rule's answer, kept so that
    /// a frame does not have to re-derive it to know whether anything changed.
    shape: Shape,
    /// The keys' `Hide`: the window is not on screen at all (the guest keeps
    /// running; only the window is gone).
    hidden: bool,
    /// The state of the numlock key *right now*, which is what the rule is about.
    numlock_held: bool,
    /// Keys currently down, so a release is always sent for a press.
    keys_down: Vec<i32>,
    /// **The pointer's buttons the guest is currently holding** (bit 0 left, 1 middle, 2 right).
    ///
    /// It is the window's own state, and it is what every pointer event carries to the guest: a
    /// move during a drag, a release beside another held button, a wheel during a drag.  Without
    /// it the guest's pointer is a device that forgets what it was holding (see
    /// [`Window::mouse_button`]).
    buttons_down: u32,
    /// Where the guest's pointer was last put, in the **guest's** pixels: a button event carries
    /// the position with it, because the guest's pointer device takes the two together.
    pointer_guest: (i32, i32),
    quit: bool,
    start: Instant,
    frames: u64,
    /// Whether the shape the window was **created** in has been announced (once).
    shape_announced: bool,
    /// Is the window full screen (the 1920x1080-with-the-key rule)?
    fullscreen: bool,
    /// The user asked to **close** the window (its close button): the application asks them
    /// whether the whole application should close, and does it.  Reported through
    /// `Control::window_closed`.
    close_requested: bool,
}

impl Window {
    /// Apply what the **application** asked for, if anything (see `Control`): the hotkeys and
    /// the close question write it, and the window is what carries it out — it is what draws, so
    /// it is what hides.
    ///
    /// Called once a frame, which is often enough for a key press and cheap enough to be free.
    fn follow_control(&mut self) {
        let Some(control) = self.config.control.clone() else {
            return;
        };
        if control.exit_requested() {
            self.quit = true;
            return;
        }
        control.observe(self.hidden);
        // **Every ask is a request**, whether or not the state it wants is the one the application
        // already believes: the window reports back what it does once a frame, so the flag can
        // already read "shown" when the ask arrives, and the window is still the thing that has to
        // be on the screen (see `Control::take_request`).  What the request is compared with is
        // the window's **own** state, below.
        let Some(asked) = control.take_request() else {
            return;
        };
        // The **first** answer only records where the application stands: a window configured to
        // start hidden stays hidden, and one it has already been told about is left alone.
        let first = self.control_hidden.is_none();
        self.control_hidden = Some(asked);
        if first {
            return;
        }
        // The window's own lock is the one that answers "already like that?": the ask is the
        // application's, and the screen is the window's.
        if asked == self.hidden {
            return;
        }
        if asked {
            self.hide();
        } else {
            self.show();
        }
    }

    pub fn focused(&self) -> bool {
        self.focused
    }

    pub fn numlock_held(&self) -> bool {
        self.numlock_held
    }

    /// Is there a real window behind this?  (A headless one has no keyboard to ask, so
    /// the numlock watcher is only started when there is.)
    pub fn has_window(&self) -> bool {
        self.windowed
    }

    /// The size the window last drew the frame at (what the texture holds).
    pub fn drawn_size(&self) -> (u32, u32) {
        self.tex_size
    }
    pub fn frames(&self) -> u64 {
        self.frames
    }

    /// A window with no platform at all: only the frame path runs (the protocol, the
    /// damage queue, the latency numbers, the snapshot).  This is how the
    /// system tests and a headless benchmark use the *real* display code
    /// without needing a display server.
    pub fn headless(config: WindowConfig) -> Result<Window> {
        let hidden = config.hidden_initially;
        let window = Window {
            windowed: false,
            platform: None,
            renderer: None,
            tex_size: (0, 0),
            cursor_tex_size: (0, 0),
            fullscreen: false,
            numlock_held: config.numlock_held_initially,
            config,
            real_size: (0, 0),
            // There is no window manager here and no other window: "the window is
            // not focused" is a window-manager fact, and this one has none to lose
            // focus to.  (A windowed run starts unfocused and gains it when the
            // window manager maps the window.)
            focused: true,
            shape: Shape::Hidden,
            hidden,
            control_hidden: None,
            keys_down: Vec::new(),
            buttons_down: 0,
            pointer_guest: (0, 0),
            quit: false,
            frames: 0,
            shape_announced: false,
            start: Instant::now(),
            close_requested: false,
        };
        Ok(window)
    }

    /// Take the pending damage, as the uploading path does, and record the
    /// latency — everything `upload` does except the GL calls.
    fn consume(&mut self, display: Arc<Display>) {
        // The frame path's own bookkeeping: the resize flag, the frame the window would draw,
        // and the batch of damage it is about to account for.
        let _ = display.frames.take_resized();
        let Some(frame) = display.frames.take_frame() else {
            return;
        };
        if frame.is_empty() {
            return;
        }
        drop(frame);
        let batch = display.frames.take_damage();
        let now = display.now_us();
        for d in &batch {
            display.stats.add_latency(now - d.ts_us);
        }
        if !batch.is_empty() || self.tex_size.0 == 0 {
            let g = display.geometry();
            if self.tex_size != (g.width, g.height) {
                self.tex_size = (g.width, g.height);
            }
        }
        self.frames += 1;
        display.stats.frames.fetch_add(1, Ordering::Relaxed);
    }

    /// Open the window: the GTK window and its GLArea.
    ///
    /// It is created on the thread that runs the GTK main loop (see
    /// `crate::display_loop::run_window`), which is the same thread every dialog is asked on:
    /// a dialog needs a main loop to be destroyed in, and one loop for everything is what makes
    /// that true.
    pub fn create(config: WindowConfig) -> Result<Window> {
        let (initial, open_w, open_h) = initial_shape(&config);
        let fullscreen = config.fullscreen || initial == Shape::FullScreen;
        let mut platform = Platform::open(&config.title, open_w, open_h, !config.hidden_initially)
            .map_err(WindowError::Other)?;
        // The dialogs the application puts up belong to **this window**: a question appears
        // over the guest's screen because the dialog is transient for it.  It is handed to the
        // control the application holds (in memory — a file would outlive the run that wrote it
        // and mean nothing afterwards).
        platform.refresh_x11_id();
        if let (Some(id), Some(control)) = (platform.x11_id(), config.control.as_ref()) {
            control.set_x11_id(id);
        }
        let mut window = Window {
            platform: Some(platform),
            renderer: None,
            tex_size: (0, 0),
            cursor_tex_size: (0, 0),
            real_size: (config.width as i32, config.height as i32),
            // Just created, and therefore focused (see `is_focused`): the events that follow are
            // what take it away.
            focused: true,
            shape: initial,
            shape_announced: false,
            hidden: config.hidden_initially,
            control_hidden: None,
            numlock_held: config.numlock_held_initially,
            keys_down: Vec::new(),
            buttons_down: 0,
            pointer_guest: (0, 0),
            quit: false,
            frames: 0,
            start: Instant::now(),
            fullscreen,
            close_requested: false,
            config,
            windowed: true,
        };
        // The shape the window opens in: the rule's, applied once before the first frame —
        // the guest's window (or full screen at FULL_SCREEN_RESOLUTION), and hidden when the
        // run asked for that.
        window.apply_shape(initial, true);
        Ok(window)
    }

    /// The shape the window is created in, and the size that means.
    pub fn shape_name(&self) -> Shape {
        self.shape
    }

    /// The user asked to close the window, or the run's own clock ran out.
    pub fn finished(&self) -> bool {
        self.quit
    }

    /// The run's own clock ran out (`--run-seconds`): the window is finished, whether or not
    /// anything was drawn this tick.
    pub fn request_stop(&mut self) {
        self.quit = true;
    }

    /// The GTK window, when there is one: what the display loop connects its signals to.
    pub fn platform(&self) -> Option<&Platform> {
        self.platform.as_ref()
    }

    /// The platform, to be connected: signals are `connect_*` calls on GTK widgets, and the
    /// closures need the window itself (see `crate::display_loop`).
    pub fn platform_mut(&mut self) -> Option<&mut Platform> {
        self.platform.as_mut()
    }

    /// The GTK window's X id, when the session has one.
    pub fn x11_id(&self) -> Option<u64> {
        self.platform.as_ref().and_then(|p| p.x11_id())
    }

    /// **Where the pointer is inside the window right now**, in window pixels.
    ///
    /// `None` for a headless window (there is no window to be over), when the pointer is over
    /// another window, and when it is on this window's **own chrome** (its title bar or border): the
    /// display area is the only place the guest's pointer lives.  The display loop asks this on its
    /// 30 Hz tick, which is what keeps the guest's pointer where the user's is even though the
    /// pointer's *events* go to the toplevel (see `crate::gtk_window::Platform::pointer_state`).
    pub fn pointer_position(&self) -> Option<(f64, f64)> {
        self.platform.as_ref()?.pointer_position()
    }

    /// **Is the pointer on this window's own chrome** (its title bar or border)?
    ///
    /// project's rules ("Display — The pointer is the guest's, except on the window's own chrome"): the
    /// title bar is the window manager's, and the operator has to be able to drag it (2026-10-12:
    /// "I need to be able of draging the display window's tittle bar because the mouse region is not
    /// in the display area where we see the vm display").  A press there is the window's, so it is
    /// not sent to the guest and the keyboard grab is let go for as long as the pointer is there —
    /// a title-bar drag is the window manager's own grab op, and it is refused while our keyboard
    /// grab is held.
    pub fn pointer_over_chrome(&self) -> bool {
        self.pointer_state().over_our_chrome
    }

    /// **Where the pointer is**, in one reading (see `crate::gtk_window::PointerState`).
    ///
    /// The display loop asks this once per tick and uses both halves of it: the position for the
    /// guest's pointer, and the chrome answer for the keyboard grab.
    pub fn pointer_state(&self) -> crate::gtk_window::PointerState {
        self.platform
            .as_ref()
            .map(|platform| platform.pointer_state())
            .unwrap_or_default()
    }

    // ------------------------------------------------------------------ input
    //
    // The GTK signals arrive here as plain values: the window decides what they mean (the
    // rule, the guest's input), and the display loop is what connects GTK's own signals to
    // these calls.  **Nothing here waits.**  Every call that goes to the guest's own input is
    // the *fire-and-forget* form (`InputSink::send_*`): the answer is not waited for, because
    // the connection it travels on is the one the frames and the events arrive on, and a frame
    // that waits for a round trip is a window that stops — measured, the first frame was held
    // for twenty-five seconds by one mouse move.

    /// A key from the window, as its **hardware key code**.
    ///
    /// The window does not decide what a key means.  X's keycode is the number the kernel's input
    /// codes use, and it is the number the guest's `uinput` keyboard takes, so the key goes in
    /// unchanged: `Alt+F4` is Alt and F4 **in the guest**, `Super` is the guest's Super,
    /// `Ctrl+Escape` is the guest's.  The window's own three keys — numlock, `numlock + F9`,
    /// `numlock + F10` — are read from the host's keyboard by the display loop (`crate::xinput`)
    /// and never from here, so nothing is taken away from the guest and no table of key names sits
    /// between the two.
    ///
    /// `repeat` is GTK's own auto-repeat: the guest's keyboard is a real keyboard and repeats by
    /// itself, so a repeated press from the host would be a key pressed twice as fast as the user
    /// is holding it.
    pub fn key(&mut self, keycode: i32, pressed: bool, repeat: bool, input: &dyn InputSink) {
        if keycode <= 0 {
            return; // no key code, no key
        }
        if repeat && pressed {
            return;
        }
        if !self.accepts_input() {
            return;
        }
        if pressed {
            input.send_key_press(keycode);
            if !self.keys_down.contains(&keycode) {
                self.keys_down.push(keycode);
            }
        } else {
            input.send_key_release(keycode);
            self.keys_down.retain(|c| *c != keycode);
        }
    }

    /// The pointer moved inside the window: the guest is told where, in the guest's own
    /// coordinates (the picture is scaled to fit the window), **with the buttons it is holding**.
    ///
    /// The mask is what makes a drag a drag: a move that said "no buttons" is a button that let go
    /// on the way, and the guest drops what is being dragged at the first pixel of the drag.
    pub fn pointer_moved(&mut self, x: f64, y: f64, display: &Display, input: &dyn InputSink) {
        if !self.accepts_input() {
            return;
        }
        let (gx, gy) = self.to_guest(x as i32, y as i32, display);
        self.pointer_guest = (gx, gy);
        let buttons = self.buttons_down;
        input.send_mouse_move(gx, gy, buttons);
    }

    /// A mouse button, in GDK's own numbering (1 = left, 2 = middle, 3 = right).
    ///
    /// The mask the guest is told is the mask **after** this event — the state the guest's pointer
    /// device is being asked to match.  Press left, move, release left is a click; press left,
    /// press right, release left is a left button still down under a right button.
    pub fn mouse_button(&mut self, gdk_button: u32, pressed: bool, input: &dyn InputSink) {
        if !self.accepts_input() {
            return;
        }
        // This project's numbering **is** the machine's (left 0, middle 1, right 2): sending another
        // library's numbers is a click that never lands.
        let (button, bit) = match gdk_button {
            1 => (BUTTON_LEFT, 1),
            2 => (BUTTON_MIDDLE, 2),
            3 => (BUTTON_RIGHT, 4),
            _ => return,
        };
        if pressed {
            self.buttons_down |= bit;
        } else {
            self.buttons_down &= !bit;
        }
        input.send_mouse_button(button, pressed, self.buttons_down);
    }

    /// The wheel, as a **step**: `steps` vertical (up is positive), `hsteps` horizontal (right is
    /// positive).
    ///
    /// The wheel is not a button.  It reaches the guest as a relative axis on its pointer device
    /// (`REL_WHEEL`), which is what the kernel calls a wheel and what the guest's X server turns
    /// into a scroll (see `guest-agent-rs`'s `uinput`).  The buttons held while the wheel turns go
    /// with it, so a wheel during a drag is still a drag.
    pub fn mouse_wheel(&self, steps: i32, hsteps: i32, input: &dyn InputSink) {
        if !self.accepts_input() {
            return;
        }
        if steps == 0 && hsteps == 0 {
            return;
        }
        input.send_mouse_wheel(steps, hsteps, self.buttons_down);
    }

    /// **Let go of everything the guest is holding**: the pointer's buttons and the keys.
    ///
    /// It is called when the window loses the keyboard — the focus went elsewhere, the window was
    /// hidden, the run is ending.  A guest left with a button down is a guest that keeps dragging
    /// after the user's finger left the mouse; a guest left with Ctrl down is a guest whose next
    /// plain click is a Ctrl-click.  This is the half that knows what it sent, so it is the half
    /// that takes it back.
    pub fn release_input(&mut self, input: &dyn InputSink) {
        if self.buttons_down != 0 {
            for (button, bit) in [(BUTTON_LEFT, 1), (BUTTON_MIDDLE, 2), (BUTTON_RIGHT, 4)] {
                if self.buttons_down & bit != 0 {
                    input.send_mouse_button(button, false, 0);
                }
            }
            self.buttons_down = 0;
        }
        for code in std::mem::take(&mut self.keys_down) {
            input.send_key_release(code);
        }
    }

    /// The window has (or lost) the window manager's focus.
    ///
    /// Losing it is not a detail: the keys the guest was holding, and the buttons, belong to a
    /// keyboard that is no longer ours.  Whatever is down is released before the focus goes, so the
    /// guest does not go on dragging a window the user stopped dragging two windows ago.
    pub fn focus_changed(&mut self, focused: bool, input: &dyn InputSink) {
        if !focused && (self.focused || self.accepts_input()) {
            self.release_input(input);
        }
        self.focused = focused;
        self.publish_state();
    }

    /// The window was resized (by the window manager, or by the rule).
    pub fn resized(&mut self, width: u32, height: u32) {
        if let Some(platform) = &mut self.platform {
            platform.report_size(width, height);
        }
    }

    /// The user closed the window (its close button, or the window manager's close).
    pub fn close_asked(&mut self) {
        self.close_requested = true;
        // The application is what asks the user and decides;
        // all the window does is report that it was asked.
        if let Some(control) = &self.config.control {
            control.window_closed();
        }
    }

    /// One frame of the display: what the rule says, the damage, the picture, the report.
    ///
    /// The GL work happens in [`Window::render`], inside GTK's `render` signal — that is where
    /// the GLArea's context is current.  This half is the bookkeeping, and it runs on the
    /// loop's own timer.
    pub fn frame(&mut self, display: Arc<Display>, input: &dyn InputSink) {
        self.follow_control();
        if self.quit {
            return;
        }
        self.publish_state();
        if self.frames == 0 && !self.shape_announced {
            self.shape_announced = true;
        }
        let _ = input;
        if self
            .config
            .run_seconds
            .is_some_and(|secs| self.start.elapsed().as_secs() >= secs)
        {
            self.quit = true;
        }
        if self.platform.is_none() {
            // Headless: the frame path's bookkeeping is all there is to do (the damage queue,
            // the latency numbers), which is what the system tests measure.
            self.consume(display);
            return;
        }
        self.follow_shape();
    }

    /// Draw one frame **inside GTK's `render` signal**: the uploads and the GL pass, with the
    /// GLArea's context current.
    ///
    /// Returns `true` when a frame was drawn (the plugin's frame hook and the frame counter are
    /// driven from here).
    pub fn render(&mut self, display: Arc<Display>) -> bool {
        if self.platform.is_none() {
            return false;
        }
        // The renderer is built at the first frame: GTK has realized the area by then, so the
        // context exists and the shaders can be compiled into it.
        if self.renderer.is_none() {
            let built = {
                let Some(platform) = &mut self.platform else {
                    return false;
                };
                let area = platform.area().clone();
                match platform.gl(&area) {
                    Ok(gl) => match crate::gl::Renderer::new(gl) {
                        Ok(built) => {
                            // SAFETY: this runs with the GLArea's context current, which is
                            // the only place a GL string may be asked for.
                            let (version, renderer) = unsafe {
                                (
                                    gl.get_parameter_string(glow::VERSION),
                                    gl.get_parameter_string(glow::RENDERER),
                                )
                            };
                            dc_common::milestone!("OpenGL {version} on {renderer}");
                            Some(built)
                        }
                        Err(e) => {
                            dc_common::milestone!("the renderer could not be built: {e}");
                            None
                        }
                    },
                    Err(e) => {
                        dc_common::milestone!("the display has no OpenGL: {e}");
                        None
                    }
                }
            };
            let Some(renderer) = built else {
                return false;
            };
            self.renderer = Some(renderer);
        }
        let viewport = match &self.platform {
            Some(platform) => platform.pinned_size(),
            None => return false,
        };
        let geometry = {
            let g = display.geometry();
            if g.width == 0 || g.height == 0 {
                None
            } else {
                Some((g.width, g.height))
            }
        };
        // The screen is drawn whatever the numlock key is doing: the key is not what the
        // picture depends on. A **disabled** display is the one case with nothing to draw
        // (the run has no display path at all).
        let drawn = if display.disabled.load(Ordering::Relaxed) {
            None
        } else {
            geometry
        };
        self.upload(display.clone());
        // The pointer's **shape** first (the guest redefines it rarely and this only uploads
        // when it changed), then the position the renderer will draw it at.
        self.upload_cursor(&display);
        let cursor = if drawn.is_some() {
            self.cursor_draw(&display)
        } else {
            None
        };
        // **The borrows are taken last**, and only for the call: everything above reads
        // `self` (the cursor, the rule's answer), which a borrowed renderer would forbid.
        let (Some(platform), Some(renderer)) = (self.platform.as_mut(), self.renderer.as_ref())
        else {
            return false;
        };
        let area = platform.area().clone();
        let Ok(gl) = platform.gl(&area) else {
            return false;
        };
        renderer.draw(gl, viewport, drawn, cursor);
        self.frames += 1;
        display.stats.frames.fetch_add(1, Ordering::Relaxed);
        if cursor.is_some() {
            display.cursor_drawn.fetch_add(1, Ordering::Relaxed);
        }
        true
    }

    /// Run the frame path with **no window**: the damage in, the latency measured, one frame
    /// after another until the run's clock runs out (a test, a benchmark, a session with no
    /// display server).
    pub fn run_headless(&mut self, display: Arc<Display>, input: &dyn InputSink) -> Result<()> {
        while !self.quit {
            self.frame(display.clone(), input);
            std::thread::sleep(Duration::from_millis(2));
        }
        self.finish(display, input);
        Ok(())
    }

    /// The run is over: release the keys the guest is still holding.
    pub fn finish(&mut self, display: Arc<Display>, input: &dyn InputSink) {
        let _ = display;
        // Release the keys we are holding: a guest with a stuck Ctrl is a confusing guest.
        for code in std::mem::take(&mut self.keys_down) {
            input.send_key_release(code);
        }
    }

    /// Input is forwarded only while the window has focus (keyboard
    /// and mouse are handled "when focused").
    fn accepts_input(&self) -> bool {
        self.is_focused()
    }

    /// Apply the display rule to the window, once a frame.
    ///
    /// The rule is [`shape_for`], and this is where it is carried out: the window is
    /// resized to the shape it asks for, and the shape it *was* is what the frame
    /// compares against, so a shape that has not changed costs nothing (resizing the window
    /// every frame would fight the window manager and make the picture flicker).
    fn follow_shape(&mut self) {
        if self.platform.is_none() {
            // Headless: the rule is still applied to the state the audio rule and
            // the display state read, which is what a test can assert.
            self.apply_shape(self.shape_for_now(), false);
            return;
        }
        let want = self.shape_for_now();
        if want == self.shape {
            return;
        }
        // The real size is remembered when the window leaves it, so a full-screen round trip
        // returns to the same place.
        //
        // **Only when the window was really that size.**  While the user is dragging the
        // window by its title bar (or the window manager is moving it), the events stop for
        // the length of the drag, and what the window reports then is whatever the drag has
        // left — measured: the size read back during a drag became the window's "real" size,
        // so coming back from full screen brought back a small window instead of the one the
        // user had.
        let leaves_the_real_shape = self.shape == Shape::FullScreen || self.shape == Shape::Normal;
        if leaves_the_real_shape {
            let (w, h) = self.current_window_size();
            if w > 0 && h > 0 {
                self.real_size = (w, h);
            }
        }
        self.apply_shape(want, true);
    }

    /// Which shape the rule gives this window **now**.
    fn shape_for_now(&self) -> Shape {
        if self.hidden {
            return Shape::Hidden;
        }
        // A hidden window is the keys' business; what is left is the screen's.
        shape_for(
            false,
            self.is_focused(),
            self.numlock_held,
            self.config.width,
            self.config.height,
        )
    }

    /// Does the window have focus?
    ///
    /// A window that was **just created** is focused: it is the newest window on the session,
    /// its window manager gives it the keyboard, and "when the window is not
    /// focused" is about *losing* it. Starting at "not focused" instead makes the reverse
    /// mistake: a session with no window manager at all — a bare X server, a test — never
    /// delivers a focus event (measured).
    ///
    /// From then on the platform's own events are the truth: `focused` is set by them.
    ///
    /// It is `pub(crate)` because the **keyboard grab** is decided by it (`dc_ui::KeyboardRule`,
    /// applied in `crate::display_loop`): a grab this client holds does **not** expire when the
    /// window manager moves the focus elsewhere, so a window that is not focused must not hold one.
    pub(crate) fn is_focused(&self) -> bool {
        self.focused
    }

    /// Carry out a shape: the size (and full screen) it means.
    fn apply_shape(&mut self, shape: Shape, _real: bool) {
        let was = self.shape;
        self.shape = shape;
        if let Some(platform) = &mut self.platform {
            match shape {
                Shape::Hidden => {}
                Shape::Normal => {
                    platform.set_fullscreen(false);
                    self.fullscreen = false;
                    let (w, h) = self.real_size;
                    platform.set_size(w.max(1) as u32, h.max(1) as u32);
                }
                Shape::FullScreen => {
                    platform.set_fullscreen(true);
                    self.fullscreen = true;
                }
            }
        }
        self.publish_state();
        let _ = was;
    }

    /// The numlock key changed: record it and let the rule decide the shape.
    ///
    /// The key is what the two chords (`numlock + F9`, `numlock + F10`) and the sound rule are
    /// about.  The shape is decided in [`shape_for`] from the resolution — the key is not what
    /// resizes the window or paints it black — and it is re-derived here so a run that changes
    /// resolution mid-flight lands in the right shape.
    pub fn set_numlock_held(&mut self, held: bool) {
        if self.numlock_held == held {
            return;
        }
        self.numlock_held = held;
        self.follow_shape();
        self.publish_state();
    }

    /// **The key, as the loop just read it.**  Called on every tick, not only when the answer
    /// changed, because `numlock + F9` is the way a hidden window comes back and the key the
    /// chord was pressed with is still held when the window is shown.
    pub fn numlock_key_seen(&mut self, held: bool) {
        self.set_numlock_held(held);
    }

    /// Tell the audio rule what this window is doing.
    ///
    /// Two independent facts, and the project's rules need both: is the window on
    /// screen at all (the keys' Show/Hide), and is the numlock key held?
    fn publish_state(&self) {
        let Some(state) = &self.config.state else {
            return;
        };
        state.set_visible(!self.hidden);
        state.set_numlock_held(self.numlock_held);
        if self.windowed {
            // The **rule's** answer, not the window manager's opinion of it.  A reader of this
            // file is an application inside the guest asking "what is the display doing?", and
            // the honest answer is what the rule decided — the window manager honours a resize
            // a frame or two later, and measured: the file said one size while the window was
            // still another, which is exactly the window's own state being read as the rule's.
            let (w, h) = match self.shape {
                Shape::Hidden => (0, 0),
                Shape::Normal | Shape::FullScreen => {
                    // The screen's own size: full screen is the display's resolution, and the
                    // normal shape is the guest's.
                    let (ww, wh) = self.current_window_size();
                    if self.fullscreen && ww > 0 && wh > 0 {
                        (ww, wh)
                    } else {
                        self.real_size
                    }
                }
            };
            state.set_size(w.max(0) as u32, h.max(0) as u32);
        } else if self.hidden {
            state.set_size(0, 0);
        } else {
            let (w, h) = self.real_size;
            state.set_size(w.max(0) as u32, h.max(0) as u32);
        }
    }

    /// Hide the window (the `numlock + F9` key, or `numlock + F10`).
    ///
    /// Display: the window is hidden with the **keys**, and a hidden window comes
    /// back only through them (with the unlock password).  The guest keeps running, the window
    /// goes away, and the audio rule closes.
    pub fn hide(&mut self) {
        self.hidden = true;
        self.shape = Shape::Hidden;
        if let Some(platform) = &self.platform {
            platform.set_visible(false);
        }
        self.publish_state();
    }

    /// **Plain "put the widget away"**, for the close request: no rule, no bookkeeping — the
    /// window goes off the screen and that is all.  [`Window::hide`] is the *keys'* hide (it
    /// publishes the state, so the audio rule closes); the close request's own hide happens a
    /// moment before the question that decides whether the run ends or the window comes back.
    pub fn go_away(&mut self) {
        self.hidden = true;
        self.shape = Shape::Hidden;
        if let Some(platform) = &self.platform {
            platform.set_visible(false);
        }
        self.publish_state();
    }

    /// Show it again (the unlock key, once the password is accepted).
    ///
    /// The shape is the **rule's**, from the key the key watcher last read: showing the window
    /// does not claim the key is held (see [`Shape::forces_numlock`]) — a claim like that stops
    /// the rule following the keyboard, which is exactly what "pressing numlock the window does
    /// not go normal" was.
    pub fn show(&mut self) {
        self.hidden = false;
        if let Some(platform) = &mut self.platform {
            platform.refresh_x11_id();
            if let (Some(id), Some(control)) = (platform.x11_id(), self.config.control.as_ref()) {
                control.set_x11_id(id);
            }
            platform.set_visible(true);
            // The session's own pointer is taken away over the window: the picture inside it
            // carries the **guest's** pointer, and two arrows on one screen is one too many
            // (Display: — the guest's pointer is part of the picture).
            platform.hide_host_cursor();
            // Focus follows the Show: a window that reappears behind another one is a window
            // the user cannot use.
            platform.focus();
        }
        self.follow_shape();
    }

    pub fn hidden(&self) -> bool {
        self.hidden
    }

    /// Did the user ask to close the window?  (Answered by the application: it asks them to
    /// confirm, and closing is the application's end, not the window's.)
    pub fn close_requested(&self) -> bool {
        self.close_requested
    }

    /// The close was answered: the window keeps running (or the caller is ending the run).
    /// The owner's flag is cleared by whoever answered.
    pub fn clear_close_request(&mut self) {
        self.close_requested = false;
    }

    fn current_window_size(&self) -> (i32, i32) {
        match &self.platform {
            Some(platform) => {
                let (w, h) = platform.size();
                (w as i32, h as i32)
            }
            None => (0, 0),
        }
    }

    /// Window coordinates -> guest coordinates (the picture is scaled to fit).
    fn to_guest(&self, x: i32, y: i32, display: &Display) -> (i32, i32) {
        let g = display.geometry();
        let (ww, wh) = self.current_window_size();
        let (ww, wh) = (ww.max(1), wh.max(1));
        let cw = if g.width > 0 { g.width as i32 } else { ww };
        let ch = if g.height > 0 { g.height as i32 } else { wh };
        let gx = (x as i64 * cw as i64 / ww.max(1) as i64) as i32;
        let gy = (y as i64 * ch as i64 / wh.max(1) as i64) as i32;
        (gx.clamp(0, cw - 1), gy.clamp(0, ch - 1))
    }

    /// Upload the damaged rectangles into the frame texture.
    ///
    /// The surface is an `Arc` clone held for the whole upload: the protocol thread **never
    /// blocks here**, and a new scanout arriving mid-upload cannot unmap the memory being
    /// read (it is unmapped when the last reference goes).
    fn upload(&mut self, display: Arc<Display>) {
        if self.platform.is_none() || self.renderer.is_none() {
            return; // headless: `consume` already counted the damage
        }
        let g = display.geometry();
        let resized = display.frames.take_resized();
        // **The frame this upload draws**: the oldest whole frame the window has not drawn, or
        // the newest picture when nothing is waiting (see `crate::frames`).  The `Arc` is held
        // for the whole upload, which is what keeps the mapping alive under the GL call.
        let Some(surface) = display.frames.take_frame() else {
            return;
        };
        if surface.is_empty() {
            return;
        }
        let mut batch = display.frames.take_damage();
        let (Some(platform), Some(renderer)) = (&mut self.platform, &mut self.renderer) else {
            return;
        };
        let area = platform.area().clone();
        let Ok(gl) = platform.gl(&area) else {
            return;
        };

        if resized || self.tex_size != (g.width, g.height) {
            renderer.ensure_texture(gl, g.width, g.height);
            self.tex_size = (g.width, g.height);
            batch.clear();
            batch.push(crate::Damage {
                x: 0,
                y: 0,
                w: g.width as i32,
                h: g.height as i32,
                ts_us: display.now_us(),
                generation: 0,
            });
        }

        if batch.is_empty() {
            return;
        }
        let (format, type_) = gl_format(g.layout());
        let base = surface.as_ptr();
        if base.is_null() {
            return;
        }
        let now = display.now_us();
        for d in &batch {
            let offset = (d.y as usize) * (g.stride as usize) + (d.x as usize) * (g.bpp() as usize);
            // SAFETY: `surface` (an `Arc` clone) is alive until this function returns, so the
            // mapped memory `base` points into cannot be unmapped under the call.
            unsafe {
                renderer.upload_rect(
                    gl,
                    base,
                    offset,
                    g.stride,
                    d.x,
                    d.y,
                    d.w,
                    d.h,
                    g.bpp(),
                    format,
                    type_,
                )
            };
            display.stats.add_latency(now - d.ts_us);
        }
    }

    /// Upload the guest's pointer shape, if it changed.
    ///
    /// `CursorDefine` is rare (the guest redefines its pointer only when the shape changes),
    /// while `MouseSet` arrives constantly, so the shape is a texture of its own and its
    /// position is just a quad drawn where the guest says.
    fn upload_cursor(&mut self, display: &Arc<Display>) {
        if self.platform.is_none() || self.renderer.is_none() {
            return;
        }
        let changed = display.cursor_shape.swap(false, Ordering::Relaxed);
        let (w, h, data) = {
            let Ok(cursor) = display.cursor.lock() else {
                return;
            };
            (cursor.width, cursor.height, cursor.data.clone())
        };
        if w <= 0 || h <= 0 || data.is_empty() {
            return;
        }
        let (Some(platform), Some(renderer)) = (&mut self.platform, &mut self.renderer) else {
            return;
        };
        if !changed && renderer.cursor_size() == (w, h) {
            return;
        }
        let area = platform.area().clone();
        let Ok(gl) = platform.gl(&area) else {
            return;
        };
        renderer.upload_cursor(gl, w, h, &data);
        self.cursor_tex_size = (w, h);
    }

    /// What the pointer should look like this frame (the renderer draws it).
    fn cursor_draw(&self, display: &Arc<Display>) -> Option<crate::gl::CursorDraw> {
        if self.cursor_tex_size.0 <= 0 {
            return None;
        }
        let cursor = display.cursor.lock().ok()?;
        Some(crate::gl::CursorDraw {
            x: cursor.x,
            y: cursor.y,
            hot_x: cursor.hot_x,
            hot_y: cursor.hot_y,
            visible: cursor.visible,
        })
    }
}

impl Drop for Window {
    fn drop(&mut self) {
        // The platform owns the GTK window and its GLArea, and GDK owns the GL context:
        // dropping them in this order releases the renderer's objects first.
        self.renderer = None;
        self.platform = None;
    }
}

/// The GL (format, type) pair for a pixel layout.
fn gl_format(layout: PixelLayout) -> (u32, u32) {
    match layout {
        PixelLayout::Bgra => (GL_BGRA_EXT, GL_UNSIGNED_BYTE),
        PixelLayout::Rgba => (GL_RGBA, GL_UNSIGNED_BYTE),
        PixelLayout::BgraWordRev => (GL_BGRA_EXT, GL_UNSIGNED_INT_8_8_8_8_REV),
        PixelLayout::RgbaWordRev => (GL_RGBA, GL_UNSIGNED_INT_8_8_8_8_REV),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The guest's input, for the frame-path tests: every call is accepted and dropped (these
    /// tests are about the window's own state, and there is no guest here to send anything to).
    struct Silent;

    impl InputSink for Silent {
        fn key_press(&self, _code: i32) -> crate::Result<()> {
            Ok(())
        }
        fn key_release(&self, _code: i32) -> crate::Result<()> {
            Ok(())
        }
        fn mouse_move(&self, _x: i32, _y: i32, _buttons: u32) -> crate::Result<()> {
            Ok(())
        }
        fn mouse_button(&self, _button: u32, _pressed: bool, _buttons: u32) -> crate::Result<()> {
            Ok(())
        }
        fn mouse_wheel(&self, _steps: i32, _hsteps: i32, _buttons: u32) -> crate::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn gl_formats_follow_the_pixel_layout() {
        assert_eq!(
            gl_format(PixelLayout::Bgra),
            (GL_BGRA_EXT, GL_UNSIGNED_BYTE)
        );
        assert_eq!(gl_format(PixelLayout::Rgba), (GL_RGBA, GL_UNSIGNED_BYTE));
        assert_eq!(
            gl_format(PixelLayout::BgraWordRev),
            (GL_BGRA_EXT, GL_UNSIGNED_INT_8_8_8_8_REV)
        );
        assert_eq!(
            gl_format(PixelLayout::RgbaWordRev),
            (GL_RGBA, GL_UNSIGNED_INT_8_8_8_8_REV)
        );
    }

    /// The whole of Display: 's rule, as a table: which shape a window
    /// has. It is this project's own list of behaviours, in its own order.
    #[test]
    fn the_shape_rule_is_the_projects_own_list() {
        // Hidden: "the window is not visible" — nothing else changes that.
        for held in [false, true] {
            assert_eq!(
                shape_for(true, false, held, 1280, 800),
                Shape::Hidden,
                "a hidden window stays hidden"
            );
            assert_eq!(shape_for(true, true, held, 1920, 1080), Shape::Hidden);
        }
        // **The resolution decides, and the numlock key does not touch it**: a window
        // whose key is held and one whose key is not are the same window — the key is
        // what the two chords and the sound rule are about, never what resizes the
        // window or paints it black.
        for focused in [false, true] {
            for held in [false, true] {
                assert_eq!(
                    shape_for(false, focused, held, 1280, 800),
                    Shape::Normal,
                    "the guest's own resolution: the window at the guest's size"
                );
                assert_eq!(
                    shape_for(false, focused, held, 1920, 1080),
                    Shape::FullScreen,
                    "FULL_SCREEN_RESOLUTION: borderless full screen"
                );
            }
        }
        assert!(is_hd(1920, 1080));
        assert!(
            !is_hd(1920, 1200),
            "only that exact resolution is the full-screen one"
        );
        assert!(!is_hd(1280, 800));
    }

    /// A `Show` is a show: it does **not** decide what the numlock key says (see
    /// `Shape::forces_numlock`).
    #[test]
    fn no_shape_claims_the_numlock_key() {
        // **No shape claims the key.**  A `Show` that pinned the key as held stopped the rule
        // following the keyboard, which is the bug the operator reported.
        for shape in [Shape::Hidden, Shape::Normal, Shape::FullScreen] {
            assert!(!shape.forces_numlock(), "{shape:?} must not claim the key");
        }
    }

    /// The display rule, at the level it can be tested without a screen: the window is
    /// the guest's size whatever the numlock key is doing, and the key only decides the
    /// chords and the sound rule.
    #[test]
    fn the_window_keeps_its_size_whatever_the_numlock_key_does() {
        // A machine whose key is not held opens the guest's window, at the guest's size:
        // there is no shape left that the key alone can put the window in.
        let mut w = Window::headless(WindowConfig {
            numlock_held_initially: false,
            ..WindowConfig::default()
        })
        .unwrap();
        w.set_numlock_held(true);
        assert_eq!(
            w.shape_for_now(),
            Shape::Normal,
            "the key does not resize it"
        );
        w.set_numlock_held(false);
        assert_eq!(
            w.shape_for_now(),
            Shape::Normal,
            "and releasing it does not either"
        );
        // The key is still recorded — it is what the sound rule and the chords read.
        assert!(!w.numlock_held());
        w.set_numlock_held(true);
        assert!(w.numlock_held());
    }

    /// **A window hidden with the keys, shown through the application's own control**, must be on
    /// the screen after the frame that carries the show out.
    ///
    /// This is `follow_control`'s work — the frame is what turns the flag into a `show()`, and the
    /// answer the application asked for is compared with the window's **own** state, not with the
    /// flag it reports back.
    #[test]
    fn a_window_the_application_shows_is_on_the_screen_after_the_frame_that_shows_it() {
        let control = Arc::new(WindowControl::new());
        let mut w = Window::headless(WindowConfig {
            numlock_held_initially: false,
            control: Some(control.clone()),
            ..WindowConfig::default()
        })
        .unwrap();
        let display = Display::new();
        let input = Silent;

        // The run's own startup: the control is asked for the window **before it exists**, and
        // that first ask only records where the application stands (the window opens
        // unless the run asked for it hidden).
        control.set_visible(true);
        w.frame(Arc::clone(&display), &input);
        assert!(
            !w.hidden(),
            "the application asked for the window, and it is there"
        );

        // `numlock + F9` hides it: the guest keeps running and only the window is gone.
        w.hide();
        w.frame(Arc::clone(&display), &input);
        assert!(w.hidden(), "the keys hid the window");

        // `numlock + F9` with the right password: the application shows the window through its
        // own control (the last step of `WindowKeys::ask_for_password`).
        control.set_visible(true);
        w.frame(Arc::clone(&display), &input);
        assert!(
            !w.hidden(),
            "the window must be on the screen after the frame that carries the show out"
        );

        // And it stays there: the next frame finds nothing new to do.
        w.frame(Arc::clone(&display), &input);
        assert!(!w.hidden(), "an answered request is not carried out again");
    }

    #[test]
    fn closing_the_window_asks_to_close_the_application() {
        // Closing the window: "closing the window, it just ask permission to close
        // the application then it close".  The window itself does not decide: it reports, and
        // the application asks the user.
        let mut w = Window::headless(WindowConfig::default()).unwrap();
        assert!(!w.close_requested());
        w.close_requested = true;
        assert!(w.close_requested(), "the window reports the close");
        assert!(!w.quit, "and it is the application that decides");
        w.clear_close_request();
        assert!(
            !w.close_requested(),
            "an answered question is not asked again"
        );
    }

    #[test]
    fn hiding_and_showing_is_the_key_s_business() {
        // A hidden window is not gone: the guest keeps running, and it comes back through the
        // unlock key (see `dc-display`'s hotkeys).
        let mut w = Window::headless(WindowConfig::default()).unwrap();
        assert!(!w.hidden());
        w.hide();
        assert!(w.hidden(), "hidden, not gone");
        assert!(!w.quit, "and the application keeps running");
        w.show();
        assert!(!w.hidden());
    }
}

#[cfg(test)]
mod full_screen_tests {
    use super::*;

    #[test]
    fn the_full_screen_resolution_falls_back_to_the_specified_one() {
        // On a host with no display to ask (a headless machine, a test) the answer is what
        // this project uses: 1920x1080. On a host that has one, it is the host's own screen —
        // the operator's "if it is widescreen like 2560x1080 we use that".
        let (w, h) = full_screen_resolution();
        assert!(w >= HD_WIDTH && h >= 800, "{w}x{h} is not a screen");
        if crate::xinput::screen_size().is_none() {
            assert_eq!((w, h), (HD_WIDTH, HD_HEIGHT));
        }
    }

    #[test]
    fn the_specified_resolution_always_counts_as_full_screen() {
        // The rule must hold whatever the host's screen is: 1920x1080
        // with the key held is borderless full screen.
        assert!(is_full_screen_resolution(HD_WIDTH, HD_HEIGHT));
        assert!(!is_full_screen_resolution(1280, 800));
        assert!(!is_full_screen_resolution(120, 128));
    }
}
