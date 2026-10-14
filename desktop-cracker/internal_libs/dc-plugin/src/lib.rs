//! # `dc-plugin` — the host side of the plugin seam
//!
//! The application has exactly one switch for testing it from the outside
//! (`--plugin-path PATH`), and this crate is the other side of
//! it: loading a shared library, the ABI, and the small set of things a loaded plugin may do to
//! the run.
//!
//! Nothing here is linked by the application as a *plugin*: the library is `dlopen`ed at run
//! time and unloaded with the run.  What the application links is this crate — the loader and
//! the five one-line calls (`log`, `state`, `frame_ready`, `ask`, `action`) that its own code
//! already had as no-ops.
//!
//! With no plugin loaded, every one of those calls is a no-op and a run is exactly what
//! The design describes.

pub mod abi;
pub mod loader;

pub use abi::{FrameInfo, PinningInfo, RunStatus, MAX_PIN_CPUS};
pub use loader::{Answered, Host, Plugin};

use std::sync::{Arc, Mutex, OnceLock};

/// The plugin this process loaded, if any.
///
/// One per process: the loader installs it at the start of a run
/// and it is dropped — `shutdown`, then `dlclose` — when the run ends.
static PLUGIN: OnceLock<Mutex<Option<Arc<Plugin>>>> = OnceLock::new();

fn slot() -> &'static Mutex<Option<Arc<Plugin>>> {
    PLUGIN.get_or_init(|| Mutex::new(None))
}

/// Install the plugin for this process.  Returns the previous one (there is none, in practice).
pub fn install(plugin: Plugin) -> Option<Arc<Plugin>> {
    let mut slot = slot().lock().unwrap_or_else(|e| e.into_inner());
    slot.replace(Arc::new(plugin))
}

/// Take the plugin out again (the run is ending), so it can be dropped in a known place.
pub fn uninstall() -> Option<Arc<Plugin>> {
    let mut slot = slot().lock().unwrap_or_else(|e| e.into_inner());
    slot.take()
}

/// The loaded plugin, if there is one.
pub fn current() -> Option<Arc<Plugin>> {
    slot().lock().ok().and_then(|slot| slot.clone())
}

/// Is a plugin loaded?  (What every caller below asks first.)
pub fn is_loaded() -> bool {
    current().is_some()
}

/// A milestone line, as an event.  No-op with no plugin.
pub fn log(level: &str, message: &str) {
    if let Some(plugin) = current() {
        plugin.log(level, message);
    }
}

/// The run's state changed (`booting`, `asking`, `running`, `stopping`, `exited`).  No-op with
/// no plugin.
pub fn state(state: &str) {
    if let Some(plugin) = current() {
        plugin.state(state);
    }
}

/// **Wait for the plugin's first client** (called once, right after it is loaded).  No-op with no
/// plugin, and bounded by the plugin's own patience.
pub fn wait_first_client() {
    if let Some(plugin) = current() {
        plugin.wait_first_client();
    }
}

/// The window is about to draw a frame.  No-op with no plugin.
pub fn frame_ready() {
    if let Some(plugin) = current() {
        plugin.frame_ready();
    }
}

/// Ask the plugin a question.  `None` means it has no answer, and the caller does what it always
/// does: the dialog, and the user's own time to type.
pub fn ask(kind: &str, prompt: &str, detail: &str) -> Option<Answered> {
    current()?.ask(kind, prompt, detail)
}

/// Run one of the window's **own** actions through the plugin, when it provides that hook.
///
/// Returns `None` when there is no plugin (or no such hook), which is the caller's cue to do the
/// action itself.
pub fn asks_for_action() -> bool {
    current().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property everything else rests on: with nothing loaded, the seam is silent.
    #[test]
    fn with_no_plugin_every_hook_is_a_no_op() {
        assert!(!is_loaded());
        assert!(current().is_none());
        // Not one of these may panic, print or block without a plugin.
        log("info", "a milestone");
        state("running");
        frame_ready();
        assert_eq!(ask("disk-password", "Root disk password:", ""), None);
        assert!(uninstall().is_none());
    }
}
