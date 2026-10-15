//! **The Firecracker display, as the window's own `Display`**.
//!
//! The window half of the application — `dc-display`'s GTK window, its GL renderer, its audio
//! gate, its keys, its shapes and its dialogs — is **the project's own code and does not change**.
//! What it reads is a `Display`: a geometry, a `FramePath` (the picture plus the damage the
//! renderer drains) and the guest's pointer.  Before this machine the D-Bus listener fills that
//! struct; here it is filled from the display channel (`dc-fc-display`, port 53000).
//!
//! * **pixels in**: [`Pixels`] takes rectangles from the channel and applies them the way the machine's
//!   own `update` does — splice the rectangle into the published **copy** (never write into the
//!   picture the renderer may be reading), announce the geometry once, and `publish_damage` the
//!   rectangle so the window's GL pass uploads only what moved.  A run on this path therefore
//!   looks like a run on the other one: one whole screen, then rectangles;
//! * **input out**: [`Input`] is the window's [`InputSink`].  The codes are **already the
//!   guest's**: the window forwards the kernel key code its `keymap` read off the X server that
//!   reported the key (`dc_display::keymap`), and the agent writes that number straight into its
//!   `uinput` keyboard — the *same* numbering on both paths (`30` is `a`, `103` is `Up`).  The
//!   pointer is in the guest's own pixels, with the buttons the window is holding, and the wheel is
//!   a step on the guest's relative axes.
//!
//! What this crate does **not** do is the window's own rules — visibility, the audio gate, the
//! shapes, the keys.  They live in `dc-display` and are shared by both backends.
//!
//! Everything here is generic over [`Channel`], which is the display service and nothing else:
//! the trait is the seam a test stands in for (the same shape `dc-display`'s own tests use for
//! the channel), and it is why this file has no socket in it.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use dc_display::{Display, Geometry, InputSink, Surface};

/// **The display channel**, as this crate needs it: what the guest drew, and the way back to its
/// keyboard and pointer.  `dc-fc-display::DisplayService` implements it; a test stands in for it.
pub trait Channel: Send + Sync {
    /// What the guest says its screen is, once it has said it.
    fn surface(&self) -> Option<dc_fc_display::Surface>;
    /// The rectangles the guest drew since this was last called.
    fn take_damage(&self) -> Vec<dc_fc_display::Damage>;
    /// A key, in the guest's own code.
    fn key(&self, code: u32, down: bool);
    /// The pointer, in the guest's own pixels, and the buttons held (the **state**, not one event).
    fn mouse(&self, x: u32, y: u32, buttons: u32);
    /// The wheel: a step on a relative axis (up and right are positive), with the buttons held.
    fn wheel(&self, steps: i32, hsteps: i32, buttons: u32);
    /// The pointer's shape.
    fn cursor(&self, x: u32, y: u32, visible: bool);
}

impl Channel for dc_fc_display::DisplayService {
    fn surface(&self) -> Option<dc_fc_display::Surface> {
        dc_fc_display::DisplayService::surface(self)
    }
    fn take_damage(&self) -> Vec<dc_fc_display::Damage> {
        dc_fc_display::DisplayService::take_damage(self)
    }
    fn key(&self, code: u32, down: bool) {
        dc_fc_display::DisplayService::key(self, code, down);
    }
    fn mouse(&self, x: u32, y: u32, buttons: u32) {
        dc_fc_display::DisplayService::mouse(self, x, y, buttons);
    }
    fn wheel(&self, steps: i32, hsteps: i32, buttons: u32) {
        dc_fc_display::DisplayService::wheel(self, steps, hsteps, buttons);
    }
    fn cursor(&self, x: u32, y: u32, visible: bool) {
        dc_fc_display::DisplayService::cursor(self, x, y, visible);
    }
}

/// The pixels the guest drew, on their way into `dc-display`'s own frame path.
pub struct Pixels {
    display: Arc<Display>,
    channel: Arc<dyn Channel>,
    stop: Arc<AtomicBool>,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
    surface: Mutex<Option<dc_fc_display::Surface>>,
    /// **The pictures this path produced.**  A frame is *ready* the moment the guest's rectangles
    /// have been spliced into the published surface — that is what `POST /frame` hands a client and
    /// what the window draws when it is on screen.  The window's own counter (`dc_display`'s
    /// `stats.frames`) counts **draws**, and a run whose window is unmapped (the plugin's default:
    /// Plugins: ) draws none — while the pictures are still there, one per
    /// `frame_ready`.  So the two are counted separately and neither is invented.
    frames: AtomicU64,
}

use std::sync::atomic::AtomicU64;

impl Pixels {
    /// Start applying the guest's rectangles to `display`.
    ///
    /// The channel is already bound by then (`fc-run` binds every channel before the machine
    /// starts), so this is only the thread and the splice.
    pub fn start(display: Arc<Display>, channel: Arc<dyn Channel>) -> Arc<Pixels> {
        let pixels = Arc::new(Pixels {
            display,
            channel,
            stop: Arc::new(AtomicBool::new(false)),
            thread: Mutex::new(None),
            surface: Mutex::new(None),
            frames: AtomicU64::new(0),
        });
        let worker = pixels.clone();
        let handle = std::thread::Builder::new()
            .name("fc-pixels".into())
            .spawn(move || worker.run())
            .expect("the pixel thread");
        *pixels.thread.lock().expect("the pixel thread") = Some(handle);
        pixels
    }

    /// What the guest said its screen is, once it has said it.
    pub fn surface(&self) -> Option<dc_fc_display::Surface> {
        *self.surface.lock().ok()?
    }

    /// The number of pictures this path has produced: what a client's `POST /frame` answers, and
    /// what `/status` reports as the run's frames (see the field's own note).
    pub fn frames(&self) -> u64 {
        self.frames.load(Ordering::Relaxed)
    }

    /// Stop applying rectangles, and wait for the thread: what a run does when it is over.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Ok(mut thread) = self.thread.lock() {
            if let Some(handle) = thread.take() {
                let _ = handle.join();
            }
        }
    }

    fn run(&self) {
        let mut announced: Option<dc_fc_display::Surface> = None;
        while !self.stop.load(Ordering::Relaxed) {
            if let Some(surface) = self.channel.surface() {
                if announced != Some(surface) {
                    self.display.set_geometry(Geometry {
                        width: surface.width,
                        height: surface.height,
                        stride: surface.stride(),
                        format: surface.format,
                    });
                    *self.surface.lock().expect("the surface") = Some(surface);
                    announced = Some(surface);
                }
            }
            let damage = self.channel.take_damage();
            if damage.is_empty() {
                std::thread::sleep(std::time::Duration::from_millis(2));
                continue;
            }
            // **The newest whole screen wins.**  When a whole screen is among what arrived, it is
            // the picture — every rectangle before it is inside it, and every rectangle after it
            // is a change that came later and must still be applied.  So: whatever came before the
            // last whole screen is dropped, and the order of the rest is kept.
            let last_whole = damage.iter().rposition(|d| {
                let g = self.display.geometry();
                !g.is_empty()
                    && d.rect.x == 0
                    && d.rect.y == 0
                    && d.rect.width == g.width
                    && d.rect.height == g.height
            });
            let damage = match last_whole {
                Some(at) => damage.into_iter().skip(at).collect(),
                None => damage,
            };
            for rectangle in damage {
                self.apply(rectangle);
            }
        }
    }

    /// One rectangle, applied the way the machine's own `update` applies one.
    ///
    /// **A whole screen is not spliced: it is adopted.**  The guest sends the whole screen in one
    /// rectangle when most of it changed (`desktop-cracker-display.c`), and those bytes are *exactly* the
    /// new picture — so they are moved into place as they are, with no copy at all.  That is the
    /// difference between a video costing a full-screen `memcpy` per frame on the host and costing
    /// nothing but the socket read: at 30 frames a second and 1280x800, the copy alone is 250 MB/s
    /// of memory traffic for a picture that arrived ready-made.
    fn apply(&self, damage: dc_fc_display::Damage) {
        let geometry = self.display.geometry();
        let whole = !geometry.is_empty()
            && damage.rect.x == 0
            && damage.rect.y == 0
            && damage.rect.width == geometry.width
            && damage.rect.height == geometry.height;
        if whole
            && geometry.stride as usize == geometry.width as usize * 4
            && damage.pixels.len() == geometry.stride as usize * geometry.height as usize
        {
            let mut guard = self.display.frames.current_guard();
            *guard = Arc::new(Surface::Copy(damage.pixels));
            drop(guard);
            self.display.stats.updates.fetch_add(1, Ordering::Relaxed);
            self.display.stats.bytes_inline.fetch_add(
                (geometry.width as u64) * (geometry.height as u64) * 4,
                Ordering::Relaxed,
            );
            let timestamp = self.display.now_us();
            let screen = dc_display::frames::Rect::screen(geometry.width, geometry.height);
            self.display.frames.publish_damage(
                dc_display::frames::Rect {
                    x: 0,
                    y: 0,
                    w: geometry.width as i32,
                    h: geometry.height as i32,
                },
                screen,
                timestamp,
                damage.generation,
            );
            self.frames.fetch_add(1, Ordering::Relaxed);
            dc_plugin::frame_ready();
            return;
        }
        let geometry = self.display.geometry();
        if geometry.stride == 0 || geometry.width == 0 {
            // The guest drew before its screen's description arrived: dropped on purpose, and
            // the next whole-screen report carries it (the agent's first frame is the whole
            // screen, which is exactly why that is the first thing it sends).
            return;
        }
        let bytes_per_pixel = (geometry.bpp() as usize).max(1);
        let rect = damage.rect;
        if rect.is_empty() || damage.pixels.len() < rect.bytes() {
            return;
        }

        // **The published surface is the application's own picture, and it is written in place.**
        //
        // It used to be *replaced* on every rectangle — clone the whole screen, splice the rows,
        // publish the clone — which is a full-screen copy per message.  The machine this project started with can afford
        // that: its frames arrive as one buffer per `update` at the machine's own pace.  This path's
        // guest sends **rows as they change** (a moving pointer, every keystroke's caret, a
        // scrolling page), so a second of a busy screen is hundreds of rectangles, and copying
        // 4096000 bytes for each of them is what makes the picture arrive seconds late and lag
        // behind the pointer until the guest goes idle (measured: the operator's own run —
        // `1451 rectangle(s), 160404480 B`, a pointer that kept moving after they stopped).
        //
        // The swap existed because "the renderer may be reading the current one".  The renderer
        // is `dc-display`'s GL pass, reading the surface through `frames.current()` **under this
        // same lock** — so the two never overlap, and the splice is simply two `memcpy`s instead
        // of a copy of the screen.  `dc-display`'s own frame path keeps the pixels of a
        // `Surface::Copy` it was handed once (it uploads a texture from them when they change),
        // so nothing needs a fresh `Arc` per rectangle either.
        {
            let mut guard = self.display.frames.current_guard();
            let need = geometry.height as usize * geometry.stride as usize;
            // Anything that is not this path's own mutable copy is taken over once: an empty
            // surface, or a mapping this path never makes.
            if !matches!(&**guard, Surface::Copy(_)) {
                *guard = Arc::new(Surface::Copy(vec![0u8; need]));
            }
            // Take the `Arc` out of the slot for the splice and put it straight back: the slot is
            // what the renderer reads to get the pixels, and it reads it **under this same lock**,
            // so nothing can be looking at the pixels while they are written.  (Nothing else holds
            // a clone of this `Arc` at this moment: it is this path's own picture, published once,
            // and the frame path reads it through the lock too.)
            let taken = std::mem::replace(&mut *guard, Arc::new(Surface::Empty));
            'splice: {
                let Surface::Copy(copy) = &*taken else {
                    break 'splice;
                };
                // The pixels live inside the `Arc`, and the `Arc` is kept alive by `taken`: the
                // address is stable for as long as it is, which is what lets the splice write
                // through it without a clone of the screen.
                let base = copy.as_ptr() as *mut u8;
                let len = copy.len();
                if len < need {
                    break 'splice;
                }
                // SAFETY: `taken` owns the `Vec` these bytes belong to and is not dropped before
                // the writes end; no other reader can reach it (the lock is held, and the slot
                // holds an empty surface meanwhile).
                let target = unsafe { std::slice::from_raw_parts_mut(base, len) };
                for row in 0..rect.height as usize {
                    let dst_y = rect.y as usize + row;
                    if dst_y >= geometry.height as usize {
                        break;
                    }
                    let src = row * rect.width as usize * bytes_per_pixel;
                    let dst = dst_y * geometry.stride as usize + rect.x as usize * bytes_per_pixel;
                    let count = rect.width as usize * bytes_per_pixel;
                    if src + count > damage.pixels.len() || dst + count > target.len() {
                        break;
                    }
                    target[dst..dst + count].copy_from_slice(&damage.pixels[src..src + count]);
                }
            }
            *guard = taken;
        }

        self.display.stats.updates.fetch_add(1, Ordering::Relaxed);
        self.display
            .stats
            .bytes_inline
            .fetch_add(damage.pixels.len() as u64, Ordering::Relaxed);
        let timestamp = self.display.now_us();
        let screen = dc_display::frames::Rect::screen(geometry.width, geometry.height);
        self.display.frames.publish_damage(
            dc_display::frames::Rect {
                x: rect.x as i32,
                y: rect.y as i32,
                w: rect.width as i32,
                h: rect.height as i32,
            },
            screen,
            timestamp,
            damage.generation,
        );
        self.frames.fetch_add(1, Ordering::Relaxed);
        // **A new frame is here** — the same hook the machine this project started with calls: the plugin's clients are
        // told, and `POST /frame` reads what this just put in the picture.
        dc_plugin::frame_ready();
    }
}

/// **The window's input, on its way into the guest.**
pub struct Input {
    channel: Arc<dyn Channel>,
    /// Where the pointer was last seen: a button event is sent with the position the window last
    /// reported, because the guest's pointer device takes the two together.
    pointer: Mutex<(u32, u32)>,
    /// **The buttons the guest is being held to** (bit 0 left, 1 middle, 2 right).
    ///
    /// The channel's pointer message is a *state*, so the mask the window reports is what the
    /// guest's `uinput` device is told; keeping it here is what lets a wheel or a button event
    /// carry the buttons that are still down without working them out from one event.
    buttons: Mutex<u32>,
}

impl Input {
    pub fn new(channel: Arc<dyn Channel>) -> Arc<Input> {
        Arc::new(Input {
            channel,
            pointer: Mutex::new((0, 0)),
            buttons: Mutex::new(0),
        })
    }

    /// Adopt the window's mask and hand it back.
    fn held(&self, buttons: u32) -> u32 {
        if let Ok(mut held) = self.buttons.lock() {
            *held = buttons;
        }
        buttons
    }
}

impl InputSink for Input {
    fn key_press(&self, code: i32) -> dc_display::Result<()> {
        self.channel.key(code.max(0) as u32, true);
        Ok(())
    }

    fn key_release(&self, code: i32) -> dc_display::Result<()> {
        self.channel.key(code.max(0) as u32, false);
        Ok(())
    }

    fn mouse_move(&self, x: i32, y: i32, buttons: u32) -> dc_display::Result<()> {
        let (x, y) = (x.max(0) as u32, y.max(0) as u32);
        if let Ok(mut pointer) = self.pointer.lock() {
            *pointer = (x, y);
        }
        let buttons = self.held(buttons);
        self.channel.mouse(x, y, buttons);
        Ok(())
    }

    fn mouse_button(&self, button: u32, pressed: bool, buttons: u32) -> dc_display::Result<()> {
        let (x, y) = self.pointer.lock().map(|p| *p).unwrap_or((0, 0));
        // `dc-display`'s buttons are this project's (`0=left, 1=middle, 2=right`) and the mask is
        // bit 0, bit 1, bit 2 — the packing the guest's agent writes into its `uinput` device.
        // Nothing is worked out here from this one event: the mask is the window's, so a release of
        // the left button during a left-and-right hold is not "everything went up".
        debug_assert!(
            bit_of(button).is_some(),
            "the window sent a button this project does not have"
        );
        debug_assert!(
            pressed || bit_of(button).map_or(true, |bit| buttons & bit == 0),
            "a release must not report the button it released as still down"
        );
        let buttons = self.held(buttons);
        self.channel.mouse(x, y, buttons);
        Ok(())
    }

    fn mouse_wheel(&self, steps: i32, hsteps: i32, buttons: u32) -> dc_display::Result<()> {
        let buttons = self.held(buttons);
        self.channel.wheel(steps, hsteps, buttons);
        Ok(())
    }
}

/// The bit one of this project's button numbers has in the mask the guest's device takes.
pub fn bit_of(button: u32) -> Option<u32> {
    match button {
        0 => Some(1),
        1 => Some(2),
        2 => Some(4),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A channel that records what the window sent and hands out what the guest "drew" — the
    /// same shape `dc-display`'s own tests use for the machine's listener.
    #[derive(Default)]
    struct Recorder {
        damage: Mutex<Vec<dc_fc_display::Damage>>,
        keys: Mutex<Vec<(u32, bool)>>,
        mice: Mutex<Vec<(u32, u32, u32)>>,
        wheels: Mutex<Vec<(i32, i32, u32)>>,
        surface: Mutex<Option<dc_fc_display::Surface>>,
    }

    impl Recorder {
        fn with_screen(width: u32, height: u32) -> Arc<Recorder> {
            let recorder = Arc::new(Recorder::default());
            *recorder.surface.lock().unwrap() = Some(dc_fc_display::Surface {
                width,
                height,
                format: 0x2000_0000,
            });
            recorder
        }
    }

    impl Channel for Recorder {
        fn surface(&self) -> Option<dc_fc_display::Surface> {
            *self.surface.lock().unwrap()
        }
        fn take_damage(&self) -> Vec<dc_fc_display::Damage> {
            std::mem::take(&mut *self.damage.lock().unwrap())
        }
        fn key(&self, code: u32, down: bool) {
            self.keys.lock().unwrap().push((code, down));
        }
        fn mouse(&self, x: u32, y: u32, buttons: u32) {
            self.mice.lock().unwrap().push((x, y, buttons));
        }
        fn wheel(&self, steps: i32, hsteps: i32, buttons: u32) {
            self.wheels.lock().unwrap().push((steps, hsteps, buttons));
        }
        fn cursor(&self, _x: u32, _y: u32, _visible: bool) {}
    }

    #[test]
    fn the_windows_own_key_numbers_are_the_guests_own() {
        // The claim this crate rests on: what the window sends is what `uinput` takes.  The window
        // forwards the **kernel key code** its `keymap` read off the X server that reported the key,
        // and the agent's `display` verb writes each one into `EV_KEY` unchanged.  These are the
        // kernel's own numbers (`linux/input-event-codes.h`), reached through the keysym the server
        // names the key by.
        let code = |keysym: u32| dc_display::keymap::kernel_code_of_keysym(keysym);
        assert_eq!(code(0x0061), Some(30), "a");
        assert_eq!(code(0xff1b), Some(1), "Escape");
        assert_eq!(code(0xff0d), Some(28), "Return");
        assert_eq!(code(0xffc6), Some(67), "F9");
        assert_eq!(
            code(0xffc1),
            Some(62),
            "F4 — the key Alt+F4 closes an app with"
        );
        assert_eq!(
            code(0xff52),
            Some(103),
            "Up, which the old table had as 200"
        );
    }

    #[test]
    fn a_rectangle_from_the_guest_becomes_a_damage_the_window_draws() {
        let display = Display::new();
        let channel = Recorder::with_screen(4, 2);
        let pixels = Pixels::start(display.clone(), channel.clone());
        for _ in 0..500 {
            if pixels.surface().is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        assert_eq!(display.geometry().width, 4);
        assert_eq!(display.geometry().height, 2);
        assert_eq!(display.geometry().stride, 16, "four bytes a pixel");

        let rect = dc_fc_display::Rect {
            x: 1,
            y: 1,
            width: 2,
            height: 1,
        };
        let bytes: Vec<u8> = (0..rect.bytes()).map(|i| (i + 1) as u8).collect();
        channel.damage.lock().unwrap().push(dc_fc_display::Damage {
            rect,
            generation: 1,
            pixels: bytes.clone(),
        });
        for _ in 0..500 {
            if display.frames.has_pixels() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        let picture = display.surface();
        let slice = picture.as_slice();
        // Row 1 from pixel 1: the rectangle's own bytes, and the rest of the picture untouched.
        assert_eq!(&slice[16 + 4..16 + 4 + 8], &bytes[..]);
        assert_eq!(&slice[..16], &[0u8; 16], "the first row was not touched");
        assert!(
            display.frames.damage_len() > 0,
            "the window is told what moved"
        );
        pixels.stop();
    }

    #[test]
    fn the_windows_input_reaches_the_channel_it_was_given() {
        let channel = Arc::new(Recorder::default());
        let input = Input::new(channel.clone());
        input.key_press(30).unwrap();
        input.key_release(30).unwrap();
        input.mouse_move(100, 200, 0).unwrap();
        input.mouse_button(0, true, 1).unwrap();
        input.mouse_move(140, 240, 1).unwrap();
        input.mouse_button(0, false, 0).unwrap();
        assert_eq!(*channel.keys.lock().unwrap(), vec![(30, true), (30, false)]);
        // The move, the press, **the drag with the button still held**, then the release.  A drag
        // that reported `0` on its moves is a click the guest saw let go.
        assert_eq!(
            *channel.mice.lock().unwrap(),
            vec![(100, 200, 0), (100, 200, 1), (140, 240, 1), (140, 240, 0)]
        );
    }

    #[test]
    fn a_wheel_step_carries_the_buttons_still_held() {
        let channel = Arc::new(Recorder::default());
        let input = Input::new(channel.clone());
        input.mouse_button(2, true, 4).unwrap();
        input.mouse_wheel(-3, 0, 4).unwrap();
        input.mouse_wheel(0, 2, 4).unwrap();
        assert_eq!(
            *channel.wheels.lock().unwrap(),
            vec![(-3, 0, 4), (0, 2, 4)],
            "the wheel is a step on the guest's relative axes, with the right button down"
        );
        assert_eq!(*channel.mice.lock().unwrap(), vec![(0, 0, 4)]);
    }
}
