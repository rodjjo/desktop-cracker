//! # The desktop-cracker plugin
//!
//! A shared library the application `dlopen`s when it is started with `--plugin-path PATH`
//!. It is the outside of a running application: the milestones it
//! writes, its state, the frame it is about to draw, the questions it would put to a person, and
//! the window's own actions.  A run without `--plugin-path` never loads it, never looks at it,
//! and behaves exactly as the rule.
//!
//! Three rules shape the whole crate:
//!
//! * **it writes nothing** — no log file, no frame on disk, no passphrase.  Its state is memory
//!   and its socket, and a password lives only for the question that produced it;
//! * **it never slows the application down** — every hook copies, publishes or answers and
//!   returns; the only waiting is the waiting the application is already doing for an answer;
//! * **it prints nothing** — the application's console carries the guest's own output.

use std::os::raw::c_char;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use dc_plugin::abi::{
    Answer, FrameInfo, HookTable, HostApi, RunStatus, ABI, ASK_CONFIRM, ASK_NONE, ASK_PASSWORD,
};

pub mod http;
pub mod state;

pub const APP_NAME: &str = "desktop-cracker";
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The one environment variable in this project: **the plugin's port**.
///
/// It is read here, by the plugin, and never by the application (`AGENTS.md`).  It carries a
/// port, never a credential.  Without it the plugin still loads — it simply has no client to
/// serve, and answers "no answer" for every question.
pub const PORT_VAR: &str = "DESK_PLUGIN_PORT";

/// Everything the plugin holds while it is loaded.
///
/// The server is kept only to keep it alive: it owns the accepting thread and the clients, and
/// dropping it is what gives the port back.  The host table is kept for the same reason in the
/// other direction — the callbacks in it point into the application, and they are called until
/// `shutdown` says the run is over.
struct Loaded {
    shared: Arc<state::Shared>,
    #[allow(dead_code)]
    server: Option<Arc<http::Server>>,
    stopping: Arc<AtomicBool>,
    #[allow(dead_code)]
    host: *const HostApi,
}

// The `HostApi` is read-only for the plugin, and every callback in it is `extern "C"`.
unsafe impl Send for Loaded {}
unsafe impl Sync for Loaded {}

static LOADED: OnceLock<Mutex<Option<Loaded>>> = OnceLock::new();

fn loaded() -> &'static Mutex<Option<Loaded>> {
    LOADED.get_or_init(|| Mutex::new(None))
}

/// **The one symbol a plugin must export.**
///
/// Called once, when the application loads the library, with the host table it keeps alive for as
/// long as the library is loaded.  It returns the hooks the application should call; the table is
/// `static`, so it lives as long as the library does.
///
/// # Safety
///
/// `host` must be null or the table the dynamic loader passes (its callbacks and the strings
/// they point at outlive the library), which is the contract `dc_plugin::Plugin::load` keeps.
#[no_mangle]
pub unsafe extern "C" fn desk_plugin_init(host: *const HostApi) -> *const HookTable {
    let shared = state::Shared::default();
    let stopping = Arc::new(AtomicBool::new(false));

    // What the application offers to be read: how long a question may wait for its first client,
    // the counters, the screen, and the window's own actions.
    if !host.is_null() {
        let host_ref = &*host;
        shared.offer(host_ref.status, host_ref.frame, host_ref.action);
        shared.offer_pinning(host_ref.pinning);
    }
    let shared = Arc::new(shared);

    let server = std::env::var(PORT_VAR)
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .and_then(|port| http::Server::start(shared.clone(), port, stopping.clone()).ok());

    {
        let mut slot = loaded().lock().unwrap_or_else(|e| e.into_inner());
        *slot = Some(Loaded {
            shared,
            server,
            stopping,
            host,
        });
    }

    &TABLE
}

/// The plugin's own name, as the application prints it in the one line that says one was loaded.
static NAME: &str = "desk-plugin\0";

/// The hooks.  `name` is a byte string with its NUL, which is what the header wants.
static TABLE: HookTable = HookTable {
    abi: ABI,
    name: NAME.as_ptr() as *const c_char,
    log: Some(hook_log),
    state: Some(hook_state),
    frame_ready: Some(hook_frame_ready),
    wait_first_client: Some(hook_wait_first_client),
    ask: Some(hook_ask),
    free: Some(hook_free),
    shutdown: Some(hook_shutdown),
};

/// A milestone line the application wrote.
extern "C" fn hook_log(level: *const c_char, message: *const c_char) {
    let (level, message) = unsafe { (cstr(level, "info"), cstr(message, "")) };
    with(|loaded| {
        loaded.shared.log(level, message);
    });
}

/// The run's state changed.
extern "C" fn hook_state(state: *const c_char) {
    let text = unsafe { cstr(state, "running") };
    with(|loaded| {
        let state = state::State::parse(text).unwrap_or_default();
        loaded.shared.set_state(state);
    });
}

/// **Called once, right after the plugin is loaded**: wait here for the first client.
///
/// This is where the "the application is already asking its first question and nobody is
/// connected yet" race is settled — in the plugin, on the plugin's own thread of execution, with
/// the application waiting on a call it asked for.  The application has no sleep and no timeout of
/// its own anywhere.
extern "C" fn hook_wait_first_client() {
    with(|loaded| {
        loaded.shared.wait_for_first_client();
    });
}

/// The window is about to draw a frame.
extern "C" fn hook_frame_ready() {
    with(|loaded| {
        loaded.shared.frame_ready();
    });
}

/// **Answer a question.**  The application is waiting here, and it keeps no timeout of its own:
/// a plugin with nobody to ask answers "no answer" at once, and the application falls back to
/// its own dialog, where a person may take as long as they like.
extern "C" fn hook_ask(
    kind: *const c_char,
    prompt: *const c_char,
    detail: *const c_char,
    answer: *mut Answer,
) {
    let (kind, prompt, detail) = unsafe { (cstr(kind, ""), cstr(prompt, ""), cstr(detail, "")) };
    if answer.is_null() {
        return;
    }
    let answered = with_answer(|loaded| loaded.shared.ask(kind, prompt, detail));
    unsafe {
        match answered.flatten() {
            Some(state::Answer::Password(password)) => {
                (*answer).kind = ASK_PASSWORD;
                (*answer).password = c_password(&password);
            }
            Some(state::Answer::Confirm(yes)) => {
                (*answer).kind = ASK_CONFIRM;
                (*answer).confirm = if yes { 1 } else { 0 };
            }
            None => (*answer).kind = ASK_NONE,
        }
    }
}

/// Give a password back: the application is done with it, and the buffer is wiped.
extern "C" fn hook_free(password: *mut c_char) {
    if password.is_null() {
        return;
    }
    unsafe {
        let text = std::ffi::CStr::from_ptr(password);
        let len = text.to_bytes().len();
        // The NUL is included: everything the password occupied is overwritten, and only then is
        // the allocation handed back.
        for i in 0..=len {
            (password as *mut u8).add(i).write_volatile(0);
        }
        drop(std::ffi::CString::from_raw(password));
    }
}

/// The run is ending: stop serving, let every waiter go, and give the port back.
extern "C" fn hook_shutdown() {
    let taken = {
        let mut slot = loaded().lock().unwrap_or_else(|e| e.into_inner());
        slot.take()
    };
    if let Some(loaded) = taken {
        loaded.stopping.store(true, Ordering::Relaxed);
        loaded.shared.stop();
        // A moment for the connection threads to notice, so nothing is still writing into the
        // library as it goes away.
        std::thread::sleep(std::time::Duration::from_millis(80));
        drop(loaded);
    }
}

/// Read a C string, with a fallback for a null or non-UTF-8 one.
///
/// # Safety
///
/// `p` must be null or a valid NUL-terminated string that outlives the call.
unsafe fn cstr(p: *const c_char, fallback: &str) -> &str {
    if p.is_null() {
        return fallback;
    }
    std::ffi::CStr::from_ptr(p).to_str().unwrap_or(fallback)
}

/// Run `f` with the loaded state, if there is one.
fn with(f: impl FnOnce(&Loaded)) {
    let slot = loaded().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(loaded) = slot.as_ref() {
        f(loaded);
    }
}

/// The same, for the one hook that produces a value while the application waits.
fn with_answer<T>(f: impl FnOnce(&Loaded) -> T) -> Option<T> {
    let slot = loaded().lock().unwrap_or_else(|e| e.into_inner());
    slot.as_ref().map(f)
}

/// A NUL-terminated copy of a password, for the application to read and hand straight back.
fn c_password(password: &str) -> *mut c_char {
    match std::ffi::CString::new(password) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// The application's counters, straight from its own hand — used by the tests below.
#[allow(dead_code)]
fn host_status() -> Option<RunStatus> {
    let pull = {
        let slot = loaded().lock().unwrap_or_else(|e| e.into_inner());
        slot.as_ref().and_then(|l| l.shared.status_pull())
    }?;
    let mut status = RunStatus::default();
    (pull(&mut status) == 0).then_some(status)
}

/// The frame hook, for the tests below: it is `None` with no application behind it.
#[allow(dead_code)]
fn frame_hook() -> Option<extern "C" fn(*mut u8, usize, *mut FrameInfo) -> usize> {
    let slot = loaded().lock().unwrap_or_else(|e| e.into_inner());
    slot.as_ref().and_then(|l| l.shared.frame_hook())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every hook the application may call must be present, and the ABI must be the one the
    /// application speaks: a plugin that answers a different number is refused at load time, so
    /// the table the two sides agree on is worth asserting.
    #[test]
    fn the_hook_table_speaks_the_abi_the_application_does() {
        assert_eq!(TABLE.abi, ABI);
        assert!(TABLE.log.is_some());
        assert!(TABLE.state.is_some());
        assert!(TABLE.frame_ready.is_some());
        assert!(TABLE.ask.is_some());
        assert!(TABLE.free.is_some());
        assert!(TABLE.shutdown.is_some());
    }

    #[test]
    fn the_plugin_has_a_name() {
        let name = unsafe { std::ffi::CStr::from_ptr(TABLE.name) };
        assert_eq!(name.to_str().unwrap(), "desk-plugin");
    }

    /// With no application behind it, the plugin has nothing to pull: `/status` reports zeros
    /// and `/frame` has nothing to encode.  That is the state a plugin in a unit test is in.
    #[test]
    fn with_no_application_there_is_nothing_to_pull() {
        assert!(host_status().is_none());
        assert!(frame_hook().is_none());
    }
}
