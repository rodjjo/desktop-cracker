//! **Loading a plugin**: `dlopen`, the entry point, and the ABI check.
//!
//! The application **never links** a plugin.  This module is the only place that knows how one
//! is loaded, and every failure it can meet — no file, a bad build, no symbol, a different ABI —
//! is one line on the console and then the run continues without it.  A plugin is an observer
//! that may answer questions, never a thing the run depends on.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::path::Path;
use std::sync::OnceLock;

use crate::abi::{Answer, FrameInfo, HookTable, HostApi, PluginInit, RunStatus, ABI, SYMBOL};

/// A loaded plugin.
///
/// Held for the life of a run: dropping it calls the plugin's `shutdown` (so its threads stop and
/// its socket closes) and then `dlclose`s the library.
pub struct Plugin {
    handle: *mut c_void,
    hooks: *const HookTable,
    name: String,
    /// The host half the plugin was handed.  It must outlive the library, and the strings it
    /// points at must outlive it in turn — so they are kept here, in that order.
    _host: Box<HostApi>,
    _strings: Vec<CString>,
}

// The plugin's own functions are `extern "C"` and reach no Rust state of ours; a plugin that is
// not thread-safe broke its contract, which is not something this side can serialise away.
unsafe impl Send for Plugin {}
unsafe impl Sync for Plugin {}

impl Plugin {
    /// Load `path`.  `host` is what the plugin may pull from the application.
    ///
    /// Every failure is an `Err(sentence)` — the caller prints it and carries on without a
    /// plugin.
    pub fn load(
        path: &Path,
        app_name: &str,
        app_version: &str,
        host: Host,
    ) -> Result<Plugin, String> {
        let text = path
            .to_str()
            .ok_or_else(|| format!("{}: not a valid path", path.display()))?;
        let file = CString::new(text).map_err(|_| format!("{text}: not a valid path"))?;

        // The plugin's own symbol resolution happens at load time (`RTLD_NOW`): a build with a
        // missing symbol is refused here rather than in the middle of a run.
        let handle = unsafe { libc::dlopen(file.as_ptr(), libc::RTLD_NOW) };
        if handle.is_null() {
            return Err(format!("{}: {}", path.display(), dl_error()));
        }

        let entry: PluginInit = unsafe {
            let symbol = libc::dlsym(handle, SYMBOL.as_ptr() as *const c_char);
            if symbol.is_null() {
                let why = dl_error();
                libc::dlclose(handle);
                return Err(format!("{}: {why}", path.display()));
            }
            std::mem::transmute::<*mut c_void, PluginInit>(symbol)
        };

        // The strings the `HostApi` points at, kept alive for as long as the plugin holds them.
        let strings = vec![
            CString::new(app_name).unwrap_or_default(),
            CString::new(app_version).unwrap_or_default(),
        ];
        // Installed once: a second plugin in one process is not a thing this project has,
        // and the trampolines above are one per process by construction.
        let _ = HOST.set(HostImpl {
            frame: host.frame,
            status: host.status,
            action: host.action,
            pinning: host.pinning,
        });
        let host_api = Box::new(HostApi {
            abi: ABI,
            app_name: strings[0].as_ptr(),
            app_version: strings[1].as_ptr(),
            frame: HOST
                .get()
                .and_then(|h| h.frame.as_ref())
                .map(|_| host_frame as _),
            status: HOST
                .get()
                .and_then(|h| h.status.as_ref())
                .map(|_| host_status as _),
            action: HOST
                .get()
                .and_then(|h| h.action.as_ref())
                .map(|_| host_action as _),
            pinning: HOST
                .get()
                .and_then(|h| h.pinning.as_ref())
                .map(|_| host_pinning as _),
        });

        let hooks = entry(&*host_api as *const HostApi);
        if hooks.is_null() {
            unsafe { libc::dlclose(handle) };
            return Err(format!("{}: it returned no hook table", path.display()));
        }
        let abi = unsafe { (*hooks).abi };
        if abi != ABI {
            unsafe { libc::dlclose(handle) };
            return Err(format!(
                "{}: it speaks ABI {abi}, this application speaks {ABI}",
                path.display()
            ));
        }
        let name = unsafe {
            let p = (*hooks).name;
            if p.is_null() {
                String::new()
            } else {
                CStr::from_ptr(p).to_string_lossy().into_owned()
            }
        };

        Ok(Plugin {
            handle,
            hooks,
            name,
            _host: host_api,
            _strings: strings,
        })
    }

    /// The name the plugin gives itself (for the one line the application prints).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Tell it about a milestone line.
    pub fn log(&self, level: &str, message: &str) {
        let Some(f) = self.hook(|h| h.log) else {
            return;
        };
        let (Ok(level), Ok(message)) = (CString::new(level), CString::new(message)) else {
            return;
        };
        f(level.as_ptr(), message.as_ptr());
    }

    /// Tell it the run's state changed.
    pub fn state(&self, state: &str) {
        let Some(f) = self.hook(|h| h.state) else {
            return;
        };
        let Ok(state) = CString::new(state) else {
            return;
        };
        f(state.as_ptr());
    }

    /// **Wait for the plugin's first client** (called once, right after loading).
    ///
    /// The waiting is the plugin's, not the application's: this is a hook the application calls,
    /// exactly like `log` or `ask`, and what it does with the call is its own business.
    pub fn wait_first_client(&self) {
        if let Some(f) = self.hook(|h| h.wait_first_client) {
            f();
        }
    }

    /// Tell it the window is about to draw a frame.
    pub fn frame_ready(&self) {
        if let Some(f) = self.hook(|h| h.frame_ready) {
            f();
        }
    }

    /// **Ask it a question.**  `kind` is `disk-password`, `unlock-password` or `confirm`;
    /// `None` means the plugin has no answer (no client, or the client said so).
    pub fn ask(&self, kind: &str, prompt: &str, detail: &str) -> Option<Answered> {
        let f = self.hook(|h| h.ask)?;
        let (Ok(kind), Ok(prompt), Ok(detail)) = (
            CString::new(kind),
            CString::new(prompt),
            CString::new(detail),
        ) else {
            return None;
        };
        let mut answer = Answer {
            kind: crate::abi::ASK_NONE,
            password: std::ptr::null_mut(),
            confirm: 0,
        };
        f(kind.as_ptr(), prompt.as_ptr(), detail.as_ptr(), &mut answer);
        match answer.kind {
            crate::abi::ASK_PASSWORD => {
                // The password is the plugin's allocation: it is read here and handed straight
                // back to it to free, so no copy of ours outlives the call.
                let text = if answer.password.is_null() {
                    String::new()
                } else {
                    unsafe { CStr::from_ptr(answer.password) }
                        .to_string_lossy()
                        .into_owned()
                };
                if let Some(free) = self.hook(|h| h.free) {
                    free(answer.password);
                }
                Some(Answered::Password(text))
            }
            crate::abi::ASK_CONFIRM => Some(Answered::Confirm(answer.confirm != 0)),
            _ => None,
        }
    }

    fn hook<T>(&self, pick: impl Fn(&HookTable) -> Option<T>) -> Option<T> {
        if self.hooks.is_null() {
            return None;
        }
        pick(unsafe { &*self.hooks })
    }
}

impl Drop for Plugin {
    fn drop(&mut self) {
        // The plugin's own threads and socket go first, then the library, and only then the
        // strings it was pointing at.
        if let Some(shutdown) = self.hook(|h| h.shutdown) {
            shutdown();
        }
        if !self.handle.is_null() {
            unsafe { libc::dlclose(self.handle) };
            self.handle = std::ptr::null_mut();
        }
    }
}

/// What a plugin answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answered {
    /// A password (empty when the plugin could not produce one, which the caller reads as
    /// "no answer").
    Password(String),
    /// A yes/no answer.
    Confirm(bool),
}

/// Copy the frame the window is about to draw into a caller's buffer, and answer how many bytes
/// it needs (0 when there is nothing to read yet).
pub type FramePull = Box<dyn Fn(*mut u8, usize, *mut FrameInfo) -> usize + Send + Sync>;

/// The run's counters.
pub type StatusPull = Box<dyn Fn() -> RunStatus + Send + Sync>;

/// Run one of the window's **own** actions by name: 0 ran, 1 unknown, 2 failed.
pub type ActionRun = Box<dyn Fn(&str) -> c_int + Send + Sync>;

/// What the application answers about the microVM's pinning.
pub type PinningPull = Box<dyn Fn() -> crate::abi::PinningInfo + Send + Sync>;

/// The application half of the ABI: what a plugin may **pull** from the run.
///
/// It is written as ordinary Rust closures, and the loader hands the plugin plain C function
/// pointers that call them: the trampolines are the only `extern "C"` things in this file, and
/// they look the host up in a slot that exists once per process (a plugin is a singleton, so
/// there is exactly one host to find).
#[derive(Default)]
pub struct Host {
    /// Copy the frame the window is about to draw into `out` (`cap` bytes), and say how many
    /// bytes it needs.  Called from the plugin's threads, and it must not wait for anything.
    pub frame: Option<FramePull>,
    /// The run's counters.
    pub status: Option<StatusPull>,
    /// Run one of the window's **own** actions, answering 0 (ran), 1 (unknown), 2 (failed).
    pub action: Option<ActionRun>,
    /// Where the microVM's vCPUs are pinned.
    pub pinning: Option<PinningPull>,
}

/// The host the plugin's trampolines call into.
static HOST: OnceLock<HostImpl> = OnceLock::new();

struct HostImpl {
    frame: Option<FramePull>,
    status: Option<StatusPull>,
    action: Option<ActionRun>,
    pinning: Option<PinningPull>,
}

/// The three trampolines the plugin receives, and the only `extern "C"` entry points into the
/// application.
extern "C" fn host_frame(out: *mut u8, cap: usize, info: *mut FrameInfo) -> usize {
    match HOST.get().and_then(|h| h.frame.as_ref()) {
        Some(f) => f(out, cap, info),
        None => 0,
    }
}

extern "C" fn host_status(out: *mut RunStatus) -> c_int {
    let Some(f) = HOST.get().and_then(|h| h.status.as_ref()) else {
        return 1;
    };
    if out.is_null() {
        return 1;
    }
    unsafe { *out = f() };
    0
}

extern "C" fn host_pinning(out: *mut crate::abi::PinningInfo) -> c_int {
    let Some(f) = HOST.get().and_then(|h| h.pinning.as_ref()) else {
        return 1;
    };
    if out.is_null() {
        return 1;
    }
    unsafe { *out = f() };
    0
}

extern "C" fn host_action(action: *const c_char) -> c_int {
    let Some(f) = HOST.get().and_then(|h| h.action.as_ref()) else {
        return 1;
    };
    if action.is_null() {
        return 1;
    }
    let name = unsafe { CStr::from_ptr(action) }
        .to_string_lossy()
        .into_owned();
    f(&name)
}

/// What `dlopen`/`dlsym` last said.
fn dl_error() -> String {
    unsafe {
        let err = libc::dlerror();
        if err.is_null() {
            return "the dynamic loader gave no reason".into();
        }
        CStr::from_ptr(err).to_string_lossy().into_owned()
    }
}
