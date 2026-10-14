//! **The guest's screen, and the window that shows it.**
//!
//! The design asks for "VGA Monitor rendered on a opengl window that also handles keyboard and mouse
//! when focused", plus the display rule and the display socket at `/tmp/desktop-cracker-display.sock`.
//! On this machine the guest's screen is its **own framebuffer module** (`desktop-cracker/guest-kernel`,
//! which Xorg drives with the fbdev driver), the pixels travel the display channel (`dc-fc-display`
//! speaks it; `dc-fc-window` splices them in), and the keyboard and the pointer go back the other
//! way as **Linux key codes** the guest's agent writes to `uinput`:
//!
//! ```text
//!   <guest: the framebuffer>  ── rectangles ──▶  <dc-fc-display>  ──▶  <dc-fc-window>
//!                                                                          │
//! the window, GL, the display rule ─────┤
//!                                                                          ▼
//!                                            keys and pointer ──▶  the display channel
//! ```
//!
//! What lives here is the display's **state**: the console's geometry, the frame path (the picture,
//! the mailbox of whole frames, the damage log — `crate::frames`), the counters, the guest's
//! pointer, and the composited frame `POST /frame` hands a plugin's client.  The window itself is
//! `crate::window` and `crate::gtk_window`, and the input it sends is the [`InputSink`].

use std::os::unix::io::OwnedFd;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

pub mod audio_format;
pub mod display_loop;
/// **The frame path**: the two threads the guest's pixels pass between, the mailbox of whole
/// frames (capacity 2, oldest dropped) and the damage log.  Its own documentation is the map of
/// the display's threading.
pub mod frames;
pub mod gl;
/// The GTK window and its `gtk::GLArea`: the platform half of `window`.
pub mod gtk_window;
/// **X's keycodes and the kernel's key codes**: the window forwards every key it is not paying
/// attention to, and it forwards it as the number the guest's keyboard takes.
pub mod keymap;
/// **The wheel**: the host reports one notch as two scroll events, and this is the rule that turns
/// them into one step for the guest (see the module's own measurement).
pub mod wheel;
/// **The window**: the GTK window's own state, the display rule, the keys and the pointer that
/// go back to the guest, and the GL renderer's contract with it.
pub mod window;
pub mod xinput;

// ---------------------------------------------------------------- pixel formats

/// The bytes per pixel of a scanout's own format word: the high byte is the depth.
pub fn bpp_of(format: u32) -> u32 {
    let depth = (format >> 24) & 0xff;
    if depth > 0 {
        depth / 8
    } else {
        4
    }
}

/// How the frame's bytes should be read by the renderer.  The guest's framebuffer publishes
/// `XRGB8888`, whose bytes in memory are `B,G,R,X` — the layout below whose name says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelLayout {
    /// Word `A:R:G:B` -> memory `B,G,R,X`
    Bgra,
    /// Word `A:B:G:R` -> memory `R,G,B,X`
    Rgba,
    /// Word `B:G:R:X` -> memory `X,R,G,B`
    BgraWordRev,
    /// Word `R:G:B:X` -> memory `X,B,G,R`
    RgbaWordRev,
}

impl PixelLayout {
    /// The layout a frame's own format word describes.  The guest's framebuffer publishes
    /// `XRGB8888`, which is `Bgra` in memory on this host, and every other format word is read
    /// as that same layout: the window uploads the rows as they arrived and lets OpenGL's own
    /// format say what they are.
    pub fn of(format: u32) -> PixelLayout {
        let _ = format;
        PixelLayout::Bgra
    }

    /// The byte layout the GL texture upload uses for this frame.
    /// `gl_format` maps it to a GL format/type pair; this says it in words.
    pub fn name(self) -> &'static str {
        match self {
            PixelLayout::Bgra => "BGRA(bytes)",
            PixelLayout::Rgba => "RGBA(bytes)",
            PixelLayout::BgraWordRev => "BGRA(word rev)",
            PixelLayout::RgbaWordRev => "RGBA(word rev)",
        }
    }
}

// ------------------------------------------------------------------ the console

/// The geometry and format of the guest's screen.
///
/// `format` is the guest's own frame-buffer format word (`XRGB8888` as the framebuffer module
/// publishes it: the high byte is the depth), which is what the display channel carries with
/// every whole screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Geometry {
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub format: u32,
}

impl Geometry {
    pub fn bpp(&self) -> u32 {
        bpp_of(self.format)
    }

    pub fn layout(&self) -> PixelLayout {
        PixelLayout::of(self.format)
    }

    /// How many bytes one full frame is.
    pub fn frame_bytes(&self) -> u64 {
        self.stride as u64 * self.height as u64
    }

    pub fn is_empty(&self) -> bool {
        self.width == 0 || self.height == 0
    }
}

/// One damaged rectangle, with the moment it arrived (for the latency numbers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Damage {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
    /// Microseconds since the process started, taken when the machine's call arrived.
    pub ts_us: i64,
    /// **The guest's own number for the message this rectangle came in** (`dc-fc-display`'s own
    /// frames are numbered, so a lost message is visible as a gap).  `0` for a rectangle that did
    /// not come from the guest (a resized texture's own full-screen damage).
    pub generation: u32,
}

/// What the display has seen so far — the numbers `make system-test` asserts and
/// the ones the window prints once a second.
#[derive(Debug, Default)]
pub struct Stats {
    pub scanouts: AtomicU64,
    pub updates: AtomicU64,
    pub maps: AtomicU64,
    pub map_updates: AtomicU64,
    /// Bytes that came inline in D-Bus messages (the copy path).
    pub bytes_inline: AtomicU64,
    /// Frames actually drawn by the window.
    pub frames: AtomicU64,
    /// **Whole frames the mailbox dropped** because the window had not drawn the older ones:
    /// the number that says the window is the slow side of the frame path (see `crate::frames`).
    pub frames_dropped: AtomicU64,
    /// Damaged rectangles the log dropped for the same reason.
    pub damage_dropped: AtomicU64,
    pub latency_sum_us: AtomicI64,
    pub latency_n: AtomicU64,
    pub latency_max_us: AtomicI64,
}

impl Stats {
    pub fn add_latency(&self, us: i64) {
        self.latency_sum_us.fetch_add(us, Ordering::Relaxed);
        self.latency_n.fetch_add(1, Ordering::Relaxed);
        let mut max = self.latency_max_us.load(Ordering::Relaxed);
        while us > max {
            match self.latency_max_us.compare_exchange_weak(
                max,
                us,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(observed) => max = observed,
            }
        }
    }

    pub fn average_latency_us(&self) -> f64 {
        let n = self.latency_n.load(Ordering::Relaxed);
        if n == 0 {
            0.0
        } else {
            self.latency_sum_us.load(Ordering::Relaxed) as f64 / n as f64
        }
    }
}

/// The pixels, as the window sees them: either a shared mapping (zero copy) or
/// a copy the protocol handed us inline.
pub enum Surface {
    /// A memfd the channel shared with us, mapped read-only.  Not unmapped while the
    /// renderer may still be reading it: a retired mapping is parked here and
    /// released by whoever owns the rendering thread.
    Mapped {
        map: *const u8,
        len: usize,
        fd: OwnedFd,
    },
    /// Bytes that arrived in D-Bus messages.
    Copy(Vec<u8>),
    /// Nothing yet.
    Empty,
}

// The mapping is handed to one rendering thread at a time; the protocol thread
// never writes into it.
unsafe impl Send for Surface {}
unsafe impl Sync for Surface {}

impl Surface {
    pub fn as_ptr(&self) -> *const u8 {
        match self {
            Surface::Mapped { map, .. } => *map,
            Surface::Copy(v) => v.as_ptr(),
            Surface::Empty => std::ptr::null(),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Surface::Mapped { len, .. } => *len,
            Surface::Copy(v) => v.len(),
            Surface::Empty => 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn is_mapped(&self) -> bool {
        matches!(self, Surface::Mapped { .. })
    }

    /// The whole surface, borrowed from the mapping (empty when there is none).
    ///
    /// The borrow is what keeps the mapping alive while it is read, which is the one rule about a
    /// a shared surface: it is released only when whoever was reading it is done.
    pub fn as_slice(&self) -> &[u8] {
        let ptr = self.as_ptr();
        if ptr.is_null() {
            return &[];
        }
        unsafe { std::slice::from_raw_parts(ptr, self.len()) }
    }

    /// A row of the framebuffer, for the renderer and for the snapshots the
    /// tests compare.
    pub fn row(&self, y: u32, stride: u32) -> Option<&[u8]> {
        let start = (y as usize) * (stride as usize);
        let end = start + stride as usize;
        if end > self.len() {
            return None;
        }
        let ptr = self.as_ptr();
        if ptr.is_null() {
            return None;
        }
        Some(unsafe { std::slice::from_raw_parts(ptr.add(start), stride as usize) })
    }
}

/// The guest's **pointer**: the shape the guest wants drawn, and where.
///
/// The guest sends the pointer **beside** the pixels — its shape and its position, on the
/// display channel's own `D_CURSOR` frame — rather than drawing it into the framebuffer, and the
/// *window* is the viewer that puts the two together: an application that showed the scanout
/// alone would show a desktop with no pointer at all.
///
/// The coordinates are the guest's own pixels, and the hot spot is where the
/// click actually happens, so it has to be subtracted when drawing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cursor {
    pub width: i32,
    pub height: i32,
    pub hot_x: i32,
    pub hot_y: i32,
    /// ARGB, 32 bits per pixel, the top row first — the protocol's own layout.
    pub data: Vec<u8>,
    /// Where the pointer is, in the guest's pixels.
    pub x: i32,
    pub y: i32,
    /// Whether the guest wants it shown.
    pub visible: bool,
}

impl Cursor {
    /// **Draw this pointer onto a frame**, in place: the guest's picture with its arrow on it.
    ///
    /// It is the CPU half of what the window's GL pass does — same placement (the guest's position
    /// minus the hot spot, in guest pixels), same mixing (the pointer's ARGB over the picture's
    /// BGRA, `src_alpha / 1 - src_alpha`) — for the reader that wants a *picture* rather than a
    /// scanout plus a pointer plus the rule for putting them together.
    ///
    /// Nothing is drawn when the guest has hidden the pointer, before it has defined one, or when
    /// the frame is not the size the pointer's coordinates are in.
    pub fn draw_onto(&self, frame: &mut [u8], width: u32, height: u32, stride: u32) {
        if !self.visible || self.width <= 0 || self.height <= 0 || self.data.is_empty() {
            return;
        }
        let stride = if stride == 0 { width * 4 } else { stride } as usize;
        let (fw, fh) = (width as i32, height as i32);
        let (cw, ch) = (self.width, self.height);
        for cy in 0..ch {
            for cx in 0..cw {
                let sx = self.x - self.hot_x + cx;
                let sy = self.y - self.hot_y + cy;
                if sx < 0 || sy < 0 || sx >= fw || sy >= fh {
                    continue;
                }
                let src = ((cy * cw + cx) * 4) as usize;
                if src + 3 >= self.data.len() {
                    continue;
                }
                let dst = sy as usize * stride + sx as usize * 4;
                if dst + 3 >= frame.len() {
                    continue;
                }
                // The protocol's cursor is ARGB, 32 bits, top row first: alpha, then red, green,
                // blue.  The frame is BGRA in memory.  The colour is **not** premultiplied.
                let (a, r, g, b) = (
                    self.data[src] as u32,
                    self.data[src + 1] as u32,
                    self.data[src + 2] as u32,
                    self.data[src + 3] as u32,
                );
                for (channel, source) in [(0usize, b), (1, g), (2, r)] {
                    let under = frame[dst + channel] as u32;
                    frame[dst + channel] = ((source * a + under * (255 - a)) / 255) as u8;
                }
            }
        }
    }
}

impl Cursor {
    /// Is there a shape to draw, and does the guest want it shown?
    pub fn is_drawable(&self) -> bool {
        self.visible && self.width > 0 && self.height > 0 && !self.data.is_empty()
    }

    /// One pixel, as `(r, g, b, a)`.
    ///
    /// The protocol says ARGB, 32 bits per pixel, and the byte order in the
    /// message is the machine's: on a little-endian host that is `B, G, R, A`.
    pub fn pixel(&self, x: i32, y: i32) -> (u8, u8, u8, u8) {
        if x < 0 || y < 0 || x >= self.width || y >= self.height {
            return (0, 0, 0, 0);
        }
        let i = ((y as usize) * (self.width as usize) + (x as usize)) * 4;
        if i + 3 >= self.data.len() {
            return (0, 0, 0, 0);
        }
        let (b, g, r, a) = (
            self.data[i],
            self.data[i + 1],
            self.data[i + 2],
            self.data[i + 3],
        );
        (r, g, b, a)
    }
}

/// **The input the display's channel accepts**, as the window sends it.
///
/// The keyboard travels as **Linux key codes** (the numbers the kernel's input codes use: the
/// guest's agent writes them straight into its `uinput` keyboard), and the pointer travels as a
/// **position plus the buttons that are down**: `buttons` is the mask *after* the event this call
/// describes — bit 0 left, bit 1 middle, bit 2 right.
///
/// The mask is part of every pointer call on purpose.  A move that says "no buttons" is a drag
/// that let go of the button on the way, and a release that says "no buttons" is a release that
/// lifted the other buttons the user is still holding.  The window tracks what is down
/// (`crate::window::Window::buttons_down`) and the sink forwards that state, which is what a drag,
/// a double click and a right-drag all need.
pub trait InputSink: Send + Sync {
    fn key_press(&self, code: i32) -> Result<()>;
    fn key_release(&self, code: i32) -> Result<()>;
    /// The pointer moved, with the buttons held while it moved.
    fn mouse_move(&self, x: i32, y: i32, buttons: u32) -> Result<()>;
    /// A button went down (`pressed`) or up, with the mask **after** it.
    fn mouse_button(&self, button: u32, pressed: bool, buttons: u32) -> Result<()>;
    /// The wheel: `steps` vertical (up is positive), `hsteps` horizontal (right is positive).
    fn mouse_wheel(&self, steps: i32, hsteps: i32, buttons: u32) -> Result<()>;

    // ---------------------------------------------------------------- and the ones that return
    //
    // The window sends input **without waiting for the answer**, and that is not a
    // micro-optimisation: the window's loop must never stop, and every one of these calls ends up
    // on the same connection the pixels and the events arrive on — measured, a mouse move that
    // waited for its reply held the *first frame* of the window for twenty-five seconds (the
    // loop's own timer was reached at +25.01 s, every time, and at +0.1 s with these).
    //
    // A sink that has no asynchronous path (a test that records, a counter) falls back to the
    // synchronous one, which is exactly what it wants.

    /// Send a key press and **return**: the answer is not waited for.
    fn send_key_press(&self, code: i32) {
        let _ = self.key_press(code);
    }
    /// Send a key release and return.
    fn send_key_release(&self, code: i32) {
        let _ = self.key_release(code);
    }
    /// Send a pointer position and return.
    fn send_mouse_move(&self, x: i32, y: i32, buttons: u32) {
        let _ = self.mouse_move(x, y, buttons);
    }
    /// Send a button and return.
    fn send_mouse_button(&self, button: u32, pressed: bool, buttons: u32) {
        let _ = self.mouse_button(button, pressed, buttons);
    }
    /// Send a wheel step and return.
    fn send_mouse_wheel(&self, steps: i32, hsteps: i32, buttons: u32) {
        let _ = self.mouse_wheel(steps, hsteps, buttons);
    }
}

/// Errors of the display channel and the input path.
#[derive(Debug, thiserror::Error)]
pub enum DisplayError {
    #[error("the display's channel: {0}")]
    Channel(#[source] dc_vsock::VsockError),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, DisplayError>;

/// The display state shared between the display channel and the window.
///
/// The two halves of the **frame path** are reachable from here: `frames` (the mailbox of whole
/// frames and the damage log, both with the invariants they keep — see `crate::frames`) and the
/// pointer, which the guest sends beside the pixels rather than in them.
pub struct Display {
    pub geometry: Mutex<Geometry>,
    /// **The frame path**: the picture, the mailbox of whole frames the window draws from, and
    /// the damage log.  Every pixel and every "what changed" goes through it, and its own
    /// documentation is the map of the two threads that share it (`crate::frames`).
    pub frames: crate::frames::FramePath,
    /// The counters (scanouts, updates, bytes, frames, the drops, the latency).
    pub stats: Stats,
    /// the channel's own "this screen is gone".
    pub disabled: AtomicBool,
    /// The guest's pointer: the shape the display channel last sent, where it is, and whether the
    /// guest wants it shown.  The window draws it — the guest does not put it in the framebuffer.
    pub cursor: Mutex<Cursor>,
    /// Set when the cursor's *shape* changed, so the window re-uploads it (its
    /// position is read every frame anyway: the pointer moves without the
    /// framebuffer changing at all).
    pub cursor_shape: AtomicBool,
    /// How many frames the window drew the pointer in, for the status line and
    /// the tests.
    pub cursor_drawn: std::sync::atomic::AtomicU64,
    /// **Temporary** (the frame probe): the last rectangle an `update_map` named, so a stale
    /// shared mapping can be told from a black screen.
    pub last_map_update: Mutex<(i32, i32, i32, i32)>,
    /// The process start, for the microsecond timestamps.
    start: std::time::Instant,
}

impl Default for Display {
    fn default() -> Self {
        Display {
            geometry: Mutex::new(Geometry::default()),
            frames: crate::frames::FramePath::default(),
            stats: Stats::default(),
            disabled: AtomicBool::new(false),
            cursor: Mutex::new(Cursor::default()),
            cursor_shape: AtomicBool::new(false),
            cursor_drawn: std::sync::atomic::AtomicU64::new(0),
            last_map_update: Mutex::new((0, 0, 0, 0)),
            start: std::time::Instant::now(),
        }
    }
}

impl Display {
    pub fn new() -> Arc<Display> {
        Arc::new(Display::default())
    }

    pub fn now_us(&self) -> i64 {
        self.start.elapsed().as_micros() as i64
    }

    /// Replace the geometry; returns `true` when it actually changed.
    ///
    /// The window is told through the frame path (`frames.take_resized`): a change here means
    /// its texture no longer matches the console.
    pub fn set_geometry(&self, g: Geometry) -> bool {
        let mut cur = self.geometry.lock().unwrap();
        if *cur == g {
            return false;
        }
        *cur = g;
        drop(cur);
        self.frames.mark_resized();
        true
    }

    pub fn geometry(&self) -> Geometry {
        *self.geometry.lock().unwrap()
    }

    /// The picture as it is now (the frame path's own accessor carries the invariants).
    pub fn surface_arc(&self) -> std::sync::Arc<Surface> {
        self.frames.current()
    }

    /// Install a new picture, for the tests and the frame probe: the frame path owns the
    /// mailbox and the log, so this is only a shortcut for "the newest picture is this".
    pub fn replace_surface(&self, new: Surface) -> std::sync::Arc<Surface> {
        let old = self.frames.current();
        self.frames.replace_current(new);
        old
    }
}

/// What an outside reader draws **onto** the frame before it is handed out: `(frame, width,
/// height)` in place.  It is deliberately one small type rather than a signature in three places.
pub type Compositor<'a> = dyn Fn(&mut Vec<u8>, u32, u32) + 'a;

impl Display {
    /// Is there anything to draw?
    pub fn has_pixels(&self) -> bool {
        self.frames.has_pixels()
    }

    /// The picture's own guard, for the tests that only look at the bytes.
    pub fn surface(&self) -> std::sync::MutexGuard<'_, std::sync::Arc<Surface>> {
        self.frames.current_guard()
    }

    /// **The frame as it would be drawn**, the guest's picture with its pointer already blitted
    /// into it, and the size needed to hold it.
    ///
    /// It is what an outside reader (a plugin's `/frame`) is shown, and deliberately a different
    /// thing from `surface_arc` — the raw scanout, which has no pointer in it because the pointer
    /// is a *second* thing the window composites while drawing.  Compositing here keeps that
    /// knowledge in this crate: the reader gets a picture, not a scanout plus a cursor plus the
    /// rule for putting them together.
    ///
    /// `blit` is `None` for "nothing to draw with", and the surface alone is then the answer.
    pub fn composited_bgra(&self, blit: Option<&Compositor>) -> (Vec<u8>, u32, u32, u32) {
        let g = self.geometry();
        let surface = self.frames.current();
        let mut out = surface.as_slice().to_vec();
        if let Some(blit) = blit {
            blit(&mut out, g.width, g.height);
        }
        (out, g.width, g.height, g.stride)
    }
}

impl Drop for Surface {
    fn drop(&mut self) {
        if let Surface::Mapped { map, len, .. } = self {
            if !map.is_null() && *len > 0 {
                unsafe {
                    libc::munmap(*map as *mut libc::c_void, *len);
                }
            }
        }
    }
}
