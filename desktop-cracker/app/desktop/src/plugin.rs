//! **The plugin, on this path.**
//!
//! the plugin's own contract's contract is the application's, not the hypervisor's: a plugin is
//! loaded beside the binary, it may pull the frame the window is about to draw, ask the run's
//! status, run one of the window's own actions, and read where the vCPUs are pinned.  Every one of
//! those answers is the same value the machine this project started with hands over — the frame comes from the same
//! `dc-display` surface, the actions are the same chords the same UI thread carries out, and the
//! pinning is this path's own (`fc_vcpu N` threads on the host's cores).
//!
//! The one difference is where the **pinning report** comes from: before this machine the application
//! reads the threads' affinity itself; here `fc_run` pinned them and its own summary is the truth,
//! so the report is filled in from what the run did.

use std::sync::{Arc, Mutex};

use dc_cli::Cli;
use dc_common::milestone;

use fc_run::Started;

use crate::run::{composited_frame, PluginCells};

/// Load the plugin the user named, if any: every failure is one line and the run carries on (a
/// plugin is an observer, and nothing about the run depends on it).
///
/// `started` is the machine, when it has been started: the plugin is loaded **after** it (the
/// application's own order — the plugin is loaded before the disk's question, and the machine is
/// made once the answer is in), and the pinning report comes from it.
pub fn load(
    cli: &Cli,
    cells: Arc<Mutex<PluginCells>>,
    pinning: Arc<Mutex<dc_plugin::PinningInfo>>,
) -> Option<Arc<dc_plugin::Plugin>> {
    let path = cli.plugin_path.as_ref()?;

    let frame_cells = cells.clone();
    let status_cells = cells.clone();
    let action_cells = cells.clone();
    // **Where the vCPUs are pinned**, from the run's own answer (`fc-run` confined the machine's
    // process and put each `fc_vcpu N` thread on a core of its own).  The machine this project started with reads the same
    // fact from the threads it pinned itself; here the run did it, and its summary is the truth.
    let pinning_cells = pinning.clone();

    let host = dc_plugin::Host {
        frame: Some(Box::new(
            move |out: *mut u8, cap: usize, info: *mut dc_plugin::FrameInfo| {
                copy_frame(&frame_cells, out, cap, info)
            },
        )),
        status: Some(Box::new(move || status_of(&status_cells))),
        action: Some(Box::new(move |name: &str| run_action(&action_cells, name))),
        pinning: Some(Box::new(move || {
            pinning_cells.lock().map(|p| *p).unwrap_or_default()
        })),
    };

    match dc_plugin::Plugin::load(path, dc_common::APP_NAME, env!("CARGO_PKG_VERSION"), host) {
        Ok(plugin) => {
            milestone!("plugin loaded: {} ({})", plugin.name(), path.display());
            dc_plugin::install(plugin);
            // The plugin waits for its own first client: the waiting is the plugin's, so the
            // application itself never sleeps and has no timeout of any kind.
            dc_plugin::wait_first_client();
            dc_plugin::current()
        }
        Err(why) => {
            milestone!("plugin not loaded: {why}");
            None
        }
    }
}

/// The machine's own vCPUs, as the plugin's `pinning` frame wants them: one row per pinned vCPU
/// (`cpu,vcpu`), the list a person reads, and the counts.  It is filled from `fc-run`'s answer to
/// "where did the threads go?", which is `/proc`'s answer, not a guess.
pub fn pinning_info(run: &Started) -> dc_plugin::PinningInfo {
    let Some(cpus) = run.cpus.as_ref().filter(|_| run.vcpus_pinned > 0) else {
        return dc_plugin::PinningInfo::default();
    };
    let mut info = dc_plugin::PinningInfo {
        format: 2,
        vcpus: run.spec.vcpus,
        vcpus_pinned: run.vcpus_pinned as u32,
        host_cores: cpus.len() as u32,
        cpus_len: cpus.len().min(dc_plugin::MAX_PIN_CPUS) as u32,
        ..Default::default()
    };
    for (vcpu, cpu) in cpus.iter().take(dc_plugin::MAX_PIN_CPUS).enumerate() {
        info.cpus[vcpu] = *cpu as u32;
    }
    info
}

/// The frame the window is about to draw (`dc-display`'s own compositing, pointer included).
fn copy_frame(
    cells: &Arc<Mutex<PluginCells>>,
    out: *mut u8,
    cap: usize,
    info: *mut dc_plugin::FrameInfo,
) -> usize {
    let (frame, width, height, stride) = {
        let Ok(cells) = cells.lock() else { return 0 };
        let Some(display) = &cells.display else {
            return 0;
        };
        composited_frame(display)
    };
    let need = frame.len();
    if need == 0 || width == 0 || height == 0 {
        return 0;
    }
    if !info.is_null() {
        unsafe {
            *info = dc_plugin::FrameInfo {
                data: std::ptr::null(),
                width,
                height,
                stride,
            };
        }
    }
    if out.is_null() || cap < need {
        return need;
    }
    unsafe { std::ptr::copy_nonoverlapping(frame.as_ptr(), out, need) };
    need
}

/// The run's counters and the window's own state — the same values the machine this project started with reports.
fn status_of(cells: &Arc<Mutex<PluginCells>>) -> dc_plugin::RunStatus {
    let Ok(cells) = cells.lock() else {
        return dc_plugin::RunStatus::default();
    };
    // **What the run produced**: the pictures this path spliced out of the guest's rectangles
    // (`dc-fc-window::Pixels`), not the window's draw count — a run whose window is unmapped (the
    // plugin's own default) draws nothing while its pictures are there, and a test that asked for
    // a frame has to see that it got one.
    let produced = cells
        .pixels
        .as_ref()
        .and_then(|slot| {
            slot.lock()
                .ok()
                .and_then(|p| p.as_ref().map(|p| p.frames()))
        })
        .unwrap_or(0);
    let mut status = match &cells.display {
        Some(display) => {
            let geometry = display.geometry();
            dc_plugin::RunStatus {
                frames: produced,
                width: geometry.width,
                height: geometry.height,
                visible: 0,
                numlock: 0,
                damage_waiting: 0,
                damage_oldest_ms: 0,
            }
        }
        None => dc_plugin::RunStatus::default(),
    };
    // **The window's own state**, which is the same value the audio rule and the guest's own
    // library read: it is written by the window (its size follows numlock, and its own close
    // hides it), so it is the honest answer to "is the window on screen?".
    if let Some(state) = &cells.state {
        status.visible = state.visible() as u32;
        status.numlock = state.numlock_held() as u32;
    }
    // **How far behind the picture is**: the rectangles waiting to be uploaded and the age of the
    // oldest one.  A frozen window and a window that is merely behind look the same on screen, and
    // these two numbers are what tells them apart from outside (`/status`).
    if let Some(display) = &cells.display {
        let behind = display.frames.damage_waiting();
        status.damage_waiting = behind.min(u32::MAX as u64) as u32;
        let oldest = display.frames.damage_oldest_us();
        if oldest > 0 {
            let now = display.now_us();
            if now > oldest {
                status.damage_oldest_ms = ((now - oldest) / 1000).min(u32::MAX as i64) as u32;
            }
        }
    }
    status
}

/// One of the window's own actions, by name: `exit` ends the run, `f9`/`f10` are the **keys'**
/// actions and are carried out by the UI thread on its next tick (a GTK dialog belongs there).
fn run_action(cells: &Arc<Mutex<PluginCells>>, name: &str) -> std::os::raw::c_int {
    if name == "exit" {
        let control = cells.lock().ok().and_then(|c| c.window.clone());
        let Some(control) = control else { return 2 };
        control.request_exit();
        milestone!("window: exit asked for");
        return 0;
    }
    let hotkey = match name {
        "hide-or-show" | "f9" => dc_display::xinput::Hotkey::HideOrShow,
        "hide-and-settings" | "f10" => dc_display::xinput::Hotkey::HideAndOpenSettings,
        _ => return 1,
    };
    let ui = cells.lock().ok().and_then(|c| c.ui.clone());
    let Some(ui) = ui else { return 2 };
    if let Ok(mut pending) = ui.pending.lock() {
        *pending = Some(hotkey);
    }
    ui.notify();
    milestone!("window: {name} asked for (the UI thread carries it out)");
    0
}
