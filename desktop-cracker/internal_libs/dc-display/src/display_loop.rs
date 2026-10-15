//! The window's own loop: the **GTK main loop**, and everything the display does happens
//! inside it.
//!
//! This is the shape the whole application has now.  There is **one GTK thread** in the
//! process, and it is this one: the display window (a `gtk::Window` with a `gtk::GLArea`) is
//! created here and every dialog is asked here.  That is the fix for the password dialog that
//! stayed on screen after it had answered: a GTK dialog has to be created, run and destroyed on
//! the thread whose main loop is running, and there used to be four threads each starting their
//! own GTK — one of them with a main loop, the others with none.
//!
//! The 30 Hz the operator asked for is the **loop's own cadence** here
//! (`glib::timeout_add_local`), not a second thread: that is the place where a `QueryKeymap`
//! costs nothing, because the connection to the X server is already open on this thread. Every GTK signal (a key, the pointer, a resize, the close
//! button) is connected to the window directly, so there is no queue and nothing to poll.
//!
//! What deliberately is *not* here: any wait for the guest.  A frame reads the damage queue,
//! draws and returns; a guest that is booting is a guest whose frames have not arrived yet, not
//! a loop that is blocked.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use gtk::prelude::*;

use crate::window::{HotkeySink, Window, WindowConfig, NUMLOCK_HZ};
use crate::xinput::{KeyReader, Keys};
use crate::{Display, DisplayError, InputSink};
/// The result an `InputSink`'s calls return (the display's own error type).
type SinkResult<T> = std::result::Result<T, DisplayError>;

/// How often the keyboard is asked what it says: the operator's own number (30 times a second).
pub const KEY_INTERVAL: Duration = Duration::from_millis(1000 / NUMLOCK_HZ as u64);

/// Everything the loop's callbacks share: the window, the display it draws and the input sink
/// it forwards to.
///
/// `Rc<RefCell<..>>` rather than `Arc<Mutex<..>>`: every one of these callbacks runs on the
/// thread running the GTK main loop — GTK callbacks are not `Send` and are never called from
/// another thread — so there is no sharing to guard against, and a lock here would only make the
/// borrow rules harder to see.
pub struct UiLoop {
    pub window: Window,
    pub display: Arc<Display>,
    /// **The guest's input, once the run has it.**  Every signal below forwards to it; the slot is
    /// empty while the run is still coming up — the disk's question is asked before the machine exists,
    /// and the display client is connected after that — and a window whose sink has not arrived
    /// simply has nothing to send yet.  It is filled in by the run, which is the thread that
    /// connects the display client.
    pub input: Arc<std::sync::Mutex<Option<Arc<dyn InputSink>>>>,
    /// **The application's own work**, carried out on this thread once per tick (see [`UiWork`]).
    pub work: UiWork,
    /// The host keyboard, read on this thread (see [`KEY_INTERVAL`]).
    pub reader: Option<KeyReader>,
    /// **X's keycode → the kernel's key code**, from the same server the reader was opened on:
    /// every key the window forwards is forwarded as a kernel code, which is what the guest's
    /// `uinput` keyboard takes (`crate::keymap`).
    pub keycodes: Option<crate::keymap::KeyCodes>,
    /// What the keyboard said last time, so that a change is a change and a rising edge is one.
    pub last_keys: Option<Keys>,
    /// **The keyboard grab** this window holds for the guest (see `dc_ui::grab`): the keyboard is
    /// the guest's while the window is on screen, so `Alt+F4`, `Super` and `Ctrl+Escape` reach the
    /// microVM instead of the window manager.  It is applied on this loop's own tick.
    pub grab: dc_ui::KeyboardGrab,
    /// **What the wheel has been told so far** (see `crate::wheel`): the host reports one notch as
    /// two scroll events, and the notch is forwarded once.
    pub wheel: crate::wheel::Wheel,
    /// The loop is ending: the callbacks stop drawing.
    pub stopping: bool,
}

/// The shared handle the GTK callbacks are given.
pub type Shared = Rc<RefCell<UiLoop>>;

impl UiLoop {
    /// What the **keyboard** says: the numlock key and the two hotkey chords.
    ///
    /// It is asked here, on the loop's own thread and at the loop's own cadence, because the
    /// question is about the *physical* keyboard and the answer must not depend on our window
    /// being focused, mapped or fast.  `QueryKeymap` is that question.
    ///
    /// The hotkey sink's `fire` only *records* what a chord means: the application puts the
    /// question up through the very loop this runs in (`crate::window::HotkeySink`), so a chord
    /// can never stop the loop that draws.
    pub fn read_keys(&mut self, hotkeys: &Arc<dyn HotkeySink>) {
        let Some(reader) = &self.reader else {
            return;
        };
        let Some(keys) = reader.keys() else {
            return;
        };
        // The key as the keyboard says it, with nothing pinned: the numlock key is the chord's
        // half and a fact the guest's own library reads, never a rule the run can hold open.
        let numlock = keys.numlock;
        let previous = self.last_keys.replace(keys);
        // **The key, every tick, not only when the answer changed.**  A window that has just come
        // back from `numlock + F9` did not see the presses that happened while it was hidden (a
        // hidden window has no keyboard of its own, and the reader only *notices* a change), so
        // telling it every tick is what keeps its own state in step with the keyboard.
        self.window.numlock_key_seen(numlock);
        // The **rising edge** of a chord: one press, one action.
        let before = previous.and_then(|p| p.hotkey());
        let now = keys.hotkey();
        if now != before {
            if let Some(hotkey) = now {
                hotkeys.fire(hotkey);
            }
        }
    }

    /// One turn of the display loop: the keyboard, the application's own requests, and the
    /// frame the GLArea draws.
    pub fn tick(&mut self, hotkeys: &Arc<dyn HotkeySink>) {
        if self.stopping {
            return;
        }
        // **The keyboard, first**: whether the guest has it decides everything the rest of this
        // tick does with the pointer and the frame.  The rule is `dc_ui::KeyboardRule`, and a
        // question that runs a GTK loop of its own (`gtk::Dialog::run`) reaches this tick too, which
        // is why `question_is_up` is asked here rather than remembered from the caller.
        //
        // **The focus is read from the server, not from the window's own flag.**  An active grab is
        // this client holding the keyboard, and it does not expire when the window manager moves the
        // focus away; measured on this host (`Xephyr` + mutter 42.9, a scratch probe that went with the fix),
        // while our window holds `gdk_seat_grab(KEYBOARD)` a click in another window's client area
        // moves `XGetInputFocus` to it — and GTK is told **nothing**: no `focus-out`, no
        // `is-active` notify, `gtk_window_is_active()` stays `true`.  A grab held there is the worst
        // of both: the host's application cannot type and the guest receives nothing.  The operator's
        // report of 2026-10-12: "when I minimize it and go using other application of the system, I'm
        // not able of using keyboard at the host anymore."
        let pointer = self.window.pointer_state();
        let focused = match (&self.reader, self.window.x11_id()) {
            (Some(reader), Some(id)) => reader
                .focus_is(u32::try_from(id).unwrap_or(0))
                .unwrap_or_else(|| self.window.is_focused()),
            // No display to ask (a headless run, a test): the window's own flag is the best answer.
            _ => self.window.is_focused(),
        };
        // Published for the code that has to decide the same thing **without** a server in reach: a
        // dialog that ends asks `dc_ui` whether the keyboard goes back to the guest's window.
        dc_ui::publish_session_focus(Some(focused));
        self.grab.apply(
            dc_ui::KeyboardRule {
                window_visible: !self.window.hidden(),
                window_focused: focused,
                asking: dc_ui::question_is_up(),
                // **The window's own chrome is the window manager's moment**: a title-bar drag is the
                // manager's grab op, and it is refused while our keyboard grab is held (measured: the
                // bar moves the window 120 px with no grab of ours, and nothing while it is held).
                dragging_our_chrome: pointer.over_our_chrome,
            },
            self.window.platform().map(|platform| platform.window()),
        );
        self.read_keys(hotkeys);
        // **The pointer's own position**, once a tick: the guest must have the pointer where the
        // user's is, and the position cannot be read off the motion signal (a windowless `GLArea`
        // never gets one).  A run with no window, a pointer over another window, and a pointer on the
        // window's own title bar all answer `None` and send nothing.
        if let Some((x, y)) = pointer.client {
            let display = Arc::clone(&self.display);
            let input = self.sink();
            self.window.pointer_moved(x, y, &display, input.as_ref());
        }
        // The frame bookkeeping (the shape's rule and the run's clock), then the drawing:
        // the GL pass happens inside GTK's `render` signal, which is where the GLArea's context
        // is current, and this is what asks GTK for it.
        let input = self.sink();
        let display = Arc::clone(&self.display);
        self.window.frame(display, input.as_ref());
        if let Some(platform) = self.window.platform() {
            platform.queue_render();
        }
    }

    /// **Where the guest's input goes right now.**  The window's signals are connected when it is
    /// created and the machine is started afterwards (the disk's question is asked first), so for
    /// a moment there is a window with nothing to forward to; those events are dropped, because
    /// there is no guest that could receive them.
    pub fn sink(&self) -> Arc<dyn InputSink> {
        sink_in(&self.input)
    }
}

/// The sink the slot holds, or the silent one while the run has not filled it in yet.
///
/// It is a free function so the rule is testable on its own: the slot is empty for the whole time
/// between the window being created and the display client being connected, and what the window's
/// own signals must get in that window of time is a sink that **does nothing** — not a panic and
/// not a stall.
fn sink_in(slot: &std::sync::Mutex<Option<Arc<dyn InputSink>>>) -> Arc<dyn InputSink> {
    match slot.lock().ok().and_then(|held| held.clone()) {
        Some(input) => input,
        None => Arc::new(NoInput),
    }
}

/// The sink a window uses **before the guest exists**: every call is dropped.
///
/// The window's own signals are connected when it is created, and the run's machine is started
/// afterwards (the disk's question is asked first), so there is a window with nothing to forward
/// to for a moment.  A silent sink is the honest shape for that: the events are the user's, and
/// nobody is there to take them yet.
struct NoInput;

impl InputSink for NoInput {
    fn key_press(&self, _code: i32) -> SinkResult<()> {
        Ok(())
    }
    fn key_release(&self, _code: i32) -> SinkResult<()> {
        Ok(())
    }
    fn mouse_move(&self, _x: i32, _y: i32, _buttons: u32) -> SinkResult<()> {
        Ok(())
    }
    fn mouse_button(&self, _button: u32, _pressed: bool, _buttons: u32) -> SinkResult<()> {
        Ok(())
    }
    fn mouse_wheel(&self, _steps: i32, _hsteps: i32, _buttons: u32) -> SinkResult<()> {
        Ok(())
    }
}

/// **A scroll event as the guest's wheel steps** lives in [`crate::wheel`]: the host reports one
/// notch as two events, so it needs a little state and is tested there on its own.
///
/// Work the application wants done **on the UI thread** — the thread running the GTK main loop.
///
/// The keys' own actions belong here: `numlock + F9` on a hidden window asks the unlock password,
/// `numlock + F10` opens the settings window, and closing the window asks whether the application
/// should end.  All three are GTK questions, so all three must be asked where the loop is, and
/// [`parent_window`] is what makes the question belong to the display window.
///
/// It is called once per loop tick, on the UI thread, and **certainly not** from a key handler:
/// a dialog asked from inside a GTK signal handler is a dialog inside a callback, and the frame
/// that was being drawn waits for it.
pub type UiWork = std::sync::Arc<dyn Fn() + Send + Sync>;

/// The display window, when this thread has one: what a dialog is transient for, so a question
/// lands over the guest's screen instead of behind it.  `None` on any other thread (and before the
/// window exists).
///
/// It, and the placement rule every window here is centered by, live in **`dc-ui`** — the crate
/// whose whole subject is "what a window belongs to, and where it goes" — and are re-exported
/// because this is the thread that owns them.
pub use dc_ui::{center, parent_window, screen_size};

/// **Hand the UI thread a piece of work, from any thread, without touching GTK here.**
///
/// `glib::idle_add_local_once` looks safe from anywhere and is not: it panics when the calling
/// thread is not the one a main loop is running on ("default main context already acquired by
/// another thread", measured — the run's own loop calling it for a message about the unlock
/// password).  So a caller that is not the UI thread sends its closure over a **channel** and the
/// thread that runs `gtk::main` runs it on its next tick; the caller never blocks, because the
/// work it is asking for is a dialog and the loop is what puts it up.
///
/// `None` when no UI thread is running (a headless run, `--no-display`), which the caller reads as
/// "nobody to show this to".
pub fn schedule_once(work: impl FnOnce() + Send + 'static) -> bool {
    let sender = SCHEDULER.with(|slot| slot.borrow().clone());
    match sender {
        Some(sender) => sender.send(Box::new(work)).is_ok(),
        None => false,
    }
}

/// The channel the UI thread's own tick drains (see [`schedule_once`]).
type Scheduled = Box<dyn FnOnce() + Send>;

thread_local! {
    static SCHEDULER: std::cell::RefCell<Option<std::sync::mpsc::Sender<Scheduled>>> =
        const { std::cell::RefCell::new(None) };
}

/// Ask the loop to end, **from wherever the request arrives**.
///
/// `gtk::main_quit` quits the *innermost* loop `gtk::main` is running, and it is a **panic**
/// ("Attempted to quit a GTK main loop when none is running") when there is none — which is the
/// case while the application's first question is up, because the dialog runs a loop of its own
/// ([`gtk::Dialog::run`]) from inside `place`.  So a caller that is itself a loop callback quits
/// the loop it is in (`gtk::main_quit`); a caller that is not (the run, waiting for the answer)
/// only records the request, and the loop's own timer carries it out (see the 30 Hz tick).
///
/// Returns `true` when the loop was quit here, which is what a callback turns into
/// `ControlFlow::Break`.
pub fn leave_loop() -> bool {
    if gtk::main_level() > 0 {
        gtk::main_quit();
        true
    } else {
        false
    }
}

/// `gtk::init()` on this thread, once per process.
///
/// The caller that needs it before the display window exists is the disk's password question
/// (The disk's password is asked by the application: , and the operator's own order:
/// the question is asked, and the window follows on the same thread).
pub fn init() -> Result<(), String> {
    if gtk::is_initialized() {
        return Ok(());
    }
    gtk::init().map_err(|e| format!("no display server for the window: {e}"))
}

/// Run the window until it is closed, **inside the GTK main loop**.
///
/// The numlock key is what this reads, from the physical keyboard and nothing else: the key is
/// the half of the two chords, and the sound rule is the window's visibility on its own.
///
/// It takes over the calling thread (the GTK main loop does), so the application runs it on a
/// thread of its own (see `desktop-cracker`'s display thread): the microVM, the console and the
/// guest keep going while this thread draws.  **Everything GTK, though, happens here**: the
/// window and every dialog and the settings window are this thread's.
///
/// `place` is called **after** the display window is on screen and **before** the loop starts its
/// own work: it is where the application puts the questions that must be asked first — the root
/// disk's password is the one.  The window is created and shown before it is called, so the
/// question is a dialog **over the window**, which is the operator's own rule ("The window need to
/// appears as soon as we open the VM, even before asking password for the root disk"); the
/// question's own `gtk::Dialog::run()` uses this same thread's main loop, so the window behind it
/// is mapped and drawn while the user types.
pub fn run_window<P>(
    config: WindowConfig,
    display: Arc<Display>,
    input: Arc<std::sync::Mutex<Option<Arc<dyn InputSink>>>>,
    hotkeys: Arc<dyn HotkeySink>,
    work: UiWork,
    place: P,
) -> Result<(), String>
where
    P: FnOnce() -> Result<(), String>,
{
    init()?;

    let run_seconds = config.run_seconds;
    // A run that asked for a hidden window (`--window-hidden`) keeps it unmapped: the question the
    // window was shown for is then asked over nothing, which is what that switch means.
    let start_hidden = config.hidden_initially;
    let window = Window::create(config).map_err(|e| e.to_string())?;
    let platform = window
        .platform()
        .expect("a windowed run always has a platform");
    let gtk_window = platform.window().clone();
    let area = platform.area().clone();
    // The window a dialog belongs to (`dc_ui::parent_window`): it is published here, on the
    // thread that made the window, and stays until the loop is gone.
    dc_ui::set_parent_window(gtk_window.clone());

    let reader = KeyReader::connect();
    // The keycode map comes from the same connection the keyboard reader was opened on: one
    // server, one mapping, and the window's own three keys and every other key read out of it.
    let keycodes = reader.as_ref().map(|reader| reader.key_codes().clone());
    let grab = dc_ui::KeyboardGrab::default();
    // Published for the code that has to let go of the keyboard — every dialog and the settings
    // window (`dc_ui::hold_keyboard_for_guest`).
    dc_ui::publish_keyboard_grab(grab.clone());

    let shared: Shared = Rc::new(RefCell::new(UiLoop {
        window,
        display,
        input,
        work,
        reader,
        keycodes,
        last_keys: None,
        grab,
        wheel: crate::wheel::Wheel::default(),
        stopping: false,
    }));

    // ---------------------------------------------------------------- the signals
    //
    // **Which widget each signal is connected to is not a style choice**: a `GLArea` is a
    // *windowless* widget (`gtk_widget_get_has_window` is false and its GdkWindow is the
    // toplevel's — measured), so GTK delivers the pointer's events to the toplevel's own window
    // and never to the area's.  The pointer signals therefore go on the `gtk::Window`; the key
    // ones stay on the area, which is the widget that holds the focus (`set_can_focus`).
    //
    // Every one of them is applied **at once**: this is the thread that owns the window, so
    // there is nothing to queue.
    {
        let shared = shared.clone();
        area.connect_render(move |_area, _ctx| {
            let mut state = shared.borrow_mut();
            if state.stopping {
                return gtk::glib::Propagation::Proceed;
            }
            let display = state.display.clone();
            state.window.render(display);
            gtk::glib::Propagation::Proceed
        });
    }
    {
        let shared = shared.clone();
        gtk_window.connect_configure_event(move |_w, event| {
            let (width, height) = event.size();
            shared.borrow_mut().window.resized(width, height);
            false
        });
    }
    {
        let shared = shared.clone();
        area.connect_key_press_event(move |_a, event| {
            // **The hardware keycode**, not the keyval: the keyval depends on the shift state and
            // the layout, so `Shift+2` and `2` are two keyvals and the guest would be told a
            // different key had been pressed.  The keycode is the key's physical position, and the
            // map read from this server turns it into the kernel code the guest's keyboard takes
            // (`crate::keymap`).  A key the map cannot name is forwarded as its own keycode, which
            // is what the kernel's numbering says it is.
            let keycode = i32::from(event.hardware_keycode());
            let mut state = shared.borrow_mut();
            let code = state
                .keycodes
                .as_ref()
                .and_then(|map| map.code(u16::try_from(keycode).unwrap_or(0)))
                .map(i32::from)
                .unwrap_or(keycode);
            let input = state.sink();
            state.window.key(code, true, false, input.as_ref());
            gtk::glib::Propagation::Proceed
        });
    }
    {
        let shared = shared.clone();
        area.connect_key_release_event(move |_a, event| {
            let keycode = i32::from(event.hardware_keycode());
            let mut state = shared.borrow_mut();
            let code = state
                .keycodes
                .as_ref()
                .and_then(|map| map.code(u16::try_from(keycode).unwrap_or(0)))
                .map(i32::from)
                .unwrap_or(keycode);
            let input = state.sink();
            state.window.key(code, false, false, input.as_ref());
            gtk::glib::Propagation::Proceed
        });
    }
    {
        let shared = shared.clone();
        gtk_window.connect_motion_notify_event(move |_w, event| {
            // **GDK is asked where the pointer is**, not the signal: the pointer's events are
            // delivered to the window that owns the surface, and the x/y a signal carries are
            // measured from *that* window's origin.  Asking GDK is right for every event and for
            // every window shape (a `GLArea` is windowless, and its events are the toplevel's —
            // measured: the area's own `motion_notify_event` never fires at all).
            let _ = event;
            let mut state = shared.borrow_mut();
            let Some((x, y)) = state.window.pointer_position() else {
                return gtk::glib::Propagation::Proceed; // the pointer is over another window
            };
            let display = state.display.clone();
            let input = state.sink();
            state.window.pointer_moved(x, y, &display, input.as_ref());
            gtk::glib::Propagation::Proceed
        });
    }
    {
        let shared = shared.clone();
        gtk_window.connect_button_press_event(move |_w, event| {
            let button = event.button();
            let mut state = shared.borrow_mut();
            let input = state.sink();
            state.window.mouse_button(button, true, input.as_ref());
            gtk::glib::Propagation::Proceed
        });
    }
    {
        let shared = shared.clone();
        gtk_window.connect_button_release_event(move |_w, event| {
            let button = event.button();
            let mut state = shared.borrow_mut();
            let input = state.sink();
            state.window.mouse_button(button, false, input.as_ref());
            gtk::glib::Propagation::Proceed
        });
    }
    {
        let shared = shared.clone();
        gtk_window.connect_scroll_event(move |_w, event| {
            // **One notch, once.**  The host reports a wheel notch as two scroll events — a `Smooth`
            // one with a delta and a discrete one — both with the same server timestamp, and the
            // smooth half's vertical sign is the content's, not the wheel's.  Answering each event on
            // its own is what made one notch arrive in the guest as `+1` and `-1` (the operator,
            // 2026-10-12: "sometimes it add 1 and remove 1 right after, so it cancel the scroll
            // movement").  See `crate::wheel`.
            let (steps, hsteps) = {
                let mut state = shared.borrow_mut();
                crate::wheel::steps(
                    &mut state.wheel,
                    event.direction(),
                    event.delta(),
                    event.time(),
                )
            };
            if steps != 0 || hsteps != 0 {
                let state = shared.borrow();
                let input = state.sink();
                state.window.mouse_wheel(steps, hsteps, input.as_ref());
            }
            gtk::glib::Propagation::Proceed
        });
    }
    {
        let shared = shared.clone();
        gtk_window.connect_focus_in_event(move |_w, _e| {
            let mut state = shared.borrow_mut();
            let input = state.sink();
            state.window.focus_changed(true, input.as_ref());
            gtk::glib::Propagation::Proceed
        });
    }
    {
        let shared = shared.clone();
        gtk_window.connect_focus_out_event(move |_w, _e| {
            // **The keys and buttons the guest is holding are released here**: the keyboard is no
            // longer ours, and a guest left with Ctrl down or a button down is a guest that keeps
            // doing what the user stopped doing.  The wheel's unfinished notch goes with them: a
            // half-notch carried into a focus the window no longer has is a notch the user will
            // never finish.
            let mut state = shared.borrow_mut();
            state.wheel.forget();
            let input = state.sink();
            state.window.focus_changed(false, input.as_ref());
            gtk::glib::Propagation::Proceed
        });
    }
    {
        // The window's own close button: the application asks the user, so this only **reports** it — and it **stops there**.
        //
        // `Propagation::Stop` is what keeps the question askable: `Proceed` lets GTK destroy the
        // window, and the application's question is then a question about a window that is
        // already gone — the window was unusable whatever the user answered ("if I choose keep
        // open on the second question the window became unusable", the operator's own report).
        // The application is the one that closes: it destroys the window when the answer is
        // *Close*, and the run ends there.
        let shared = shared.clone();
        gtk_window.connect_delete_event(move |_w, _e| {
            // **The window goes first, and the question waits for the loop's own turn.**  The click
            // is answered by hiding the window **here and now** — one call, on the thread that owns
            // it, so it is off the screen before anything else can happen — and the ask is *queued*
            // (`close_asked`): the application asks what closing means on its next tick
            // (`dc_session::ui`'s `Tick::Close`), so **nothing on this path blocks, waits or shows a
            // dialog** (the operator, 2026-10-13: "make it async and non blocking: schedule a
            // callback before you set the window hidden").  A dialog put up from here would be a
            // dialog inside the callback that asked for it, with the window the user just dismissed
            // still on the screen behind it.
            {
                let mut state = shared.borrow_mut();
                // `go_away` also publishes the state the *rules* read (the audio rule): the frame
                // the window would otherwise wait for is a frame of sound the user has already asked
                // to be gone.
                state.window.go_away();
                state.window.close_asked();
            }
            gtk::glib::Propagation::Stop
        });
    }

    // ---------------------------------------------------------------- the 30 Hz timer
    {
        let shared = shared.clone();
        let hotkeys = hotkeys.clone();
        gtk::glib::timeout_add_local(KEY_INTERVAL, move || {
            // The run is over (a timer below says so): the loop is left **here**, inside
            // `gtk::main`'s own loop, because that is the only loop `gtk::main_quit` may quit
            // (see `leave_loop`).
            if shared.borrow().stopping && leave_loop() {
                return gtk::glib::ControlFlow::Break;
            }
            // **The application's own work first** (a chord's meaning, the settings window, the
            // close question — see `UiLoop::work`), then the keyboard and the frame.
            let work = shared.borrow().work.clone();
            work();
            let mut state = shared.borrow_mut();
            state.tick(&hotkeys);
            gtk::glib::ControlFlow::Continue
        });
    }
    // The run's own clock, when a caller asked for one (`--run-seconds`): the same window clock
    // the frame path reads, checked here so the loop leaves even while nothing is drawn.
    if let Some(seconds) = run_seconds {
        let shared = shared.clone();
        let started = Instant::now();
        gtk::glib::timeout_add_local(Duration::from_millis(200), move || {
            if started.elapsed().as_secs() >= seconds {
                let mut state = shared.borrow_mut();
                state.stopping = true;
                state.window.request_stop();
                return match leave_loop() {
                    true => gtk::glib::ControlFlow::Break,
                    false => gtk::glib::ControlFlow::Continue,
                };
            }
            gtk::glib::ControlFlow::Continue
        });
    }
    // **The application's own requests, carried out on this thread**: the window's frame path
    // reports what it did, and the loop leaves when the window says it is finished (the `Esc`
    // exit, the close the user confirmed, `--run-seconds`).
    {
        let shared = shared.clone();
        gtk::glib::timeout_add_local(Duration::from_millis(100), move || {
            if shared.borrow().window.finished() {
                shared.borrow_mut().stopping = true;
                return match leave_loop() {
                    true => gtk::glib::ControlFlow::Break,
                    false => gtk::glib::ControlFlow::Continue,
                };
            }
            gtk::glib::ControlFlow::Continue
        });
    }

    // **The window is on screen before the application's first question is asked** (the operator:
    // "The window need to appears as soon as we open the VM, even before asking password for the
    // root disk").  `show_all` queues the mapping, so GTK is given the loop for the work it has
    // queued — mapping and drawing the window — before `place` puts its question up as a dialog
    // transient for it.  A run that asked for a hidden window (`--window-hidden`) keeps it
    // unmapped, and the question is then asked over nothing, which is what that switch means.
    // **The UI thread's work channel** (see `schedule_once`): it is published here, on the thread
    // that owns GTK, and drained on this loop's own timer.  A caller on another thread (the run's
    // own loop, a thread of the application) sends a closure; nothing but this thread ever asks
    // glib for anything.
    let (scheduled_tx, scheduled_rx) = std::sync::mpsc::channel::<Scheduled>();
    SCHEDULER.with(|slot| *slot.borrow_mut() = Some(scheduled_tx));
    {
        let shared = shared.clone();
        gtk::glib::timeout_add_local(Duration::from_millis(20), move || {
            while let Ok(work) = scheduled_rx.try_recv() {
                // The closure is the application's own: it may put a dialog up, which is exactly
                // what this thread is for.
                work();
            }
            if shared.borrow().stopping {
                return gtk::glib::ControlFlow::Break;
            }
            gtk::glib::ControlFlow::Continue
        });
    }

    if !start_hidden {
        gtk_window.show_all();
        while gtk::events_pending() {
            gtk::main_iteration_do(false);
        }
    }
    if let Err(e) = place() {
        // The application refused the answer (a cancelled dialog, a disk nobody can open): there
        // is nothing to show, so the window goes with it rather than staying on screen.
        // SAFETY: this runs on the thread that created the window, inside its own GTK session,
        // and nothing else holds a reference to it (the `Window` and its `Platform` are dropped
        // as this returns).
        unsafe { gtk_window.destroy() };
        return Err(e);
    }
    // The window is redrawn at once, so the guest's own screen replaces whatever the session
    // showed while the question was up — the dialog was transient for this window, and what is
    // behind it is the frame the loop is about to draw.
    gtk_window.queue_draw();
    gtk::main();

    // The run is over: the keys the guest is still holding are released.
    {
        let mut state = shared.borrow_mut();
        state.stopping = true;
        let display = state.display.clone();
        let input = state.sink();
        state.window.finish(display, input.as_ref());
    }
    // **The window goes last.**  The GL objects and the textures are released by `Window`'s own
    // `Drop` (`Self::renderer = None` before `Self::platform = None`, which is the order the
    // driver wants), so the loop has to leave the state — and the window inside it — out of
    // scope while the GL context still exists.  Dropping the window after `gtk::main()` keeps
    // that order; leaving it to the process's exit does not (the context is gone by then, and
    // measured, a run that ended that way *crashed* in a GL destructor).
    drop(shared);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **A window whose guest does not exist yet forwards to nothing.**  The window is created
    /// before the display client is connected (the disk's question is asked first), so for that
    /// moment every signal the user produces has nowhere to go; what it must be is *silent*, not
    /// a panic and not something that waits.
    #[test]
    fn a_window_before_its_guest_forwards_to_a_silent_sink() {
        let slot: std::sync::Mutex<Option<Arc<dyn InputSink>>> = std::sync::Mutex::new(None);
        let silent = sink_in(&slot);
        // Every call is accepted and dropped: the events are the user's, and nobody is there
        // to take them yet.
        assert!(silent.key_press(1).is_ok());
        assert!(silent.key_release(1).is_ok());
        assert!(silent.mouse_move(10, 10, 1).is_ok());
        assert!(silent.mouse_button(0, true, 1).is_ok());
        assert!(silent.mouse_button(0, false, 0).is_ok());
        assert!(silent.mouse_wheel(-3, 0, 1).is_ok());
        // The asynchronous forms are the ones the window actually uses, and they must not wait.
        silent.send_key_press(1);
        silent.send_mouse_move(10, 10, 0);
        silent.send_mouse_button(0, true, 1);
        silent.send_mouse_wheel(1, 0, 0);
    }

    /// **The slot is what the window reads once the run has filled it in**: the same call answers
    /// with the guest's own sink as soon as the display client exists.
    #[test]
    fn the_run_filling_the_slot_is_what_the_window_forwards_to() {
        struct Counting(std::sync::atomic::AtomicUsize);
        impl InputSink for Counting {
            fn key_press(&self, _code: i32) -> SinkResult<()> {
                self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(())
            }
            fn key_release(&self, _code: i32) -> SinkResult<()> {
                Ok(())
            }
            fn mouse_move(&self, _x: i32, _y: i32, _buttons: u32) -> SinkResult<()> {
                Ok(())
            }
            fn mouse_button(&self, _button: u32, _pressed: bool, _buttons: u32) -> SinkResult<()> {
                Ok(())
            }
            fn mouse_wheel(&self, _steps: i32, _hsteps: i32, _buttons: u32) -> SinkResult<()> {
                Ok(())
            }
        }

        let slot: std::sync::Mutex<Option<Arc<dyn InputSink>>> = std::sync::Mutex::new(None);
        assert!(sink_in(&slot).key_press(1).is_ok());
        let guest = Arc::new(Counting(std::sync::atomic::AtomicUsize::new(0)));
        *slot.lock().unwrap() = Some(guest.clone() as Arc<dyn InputSink>);
        sink_in(&slot).key_press(28).unwrap();
        assert_eq!(
            guest.0.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "the press must have reached the guest's own sink"
        );
    }
}
