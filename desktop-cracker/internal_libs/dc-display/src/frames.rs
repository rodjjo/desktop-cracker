//! **The frame path**: the pixels between the display channel and the window, and the two threads that hand
//! them over.
//!
//! This module exists because of a question about the *architecture* (`fix-vm-bad-performance.txt`,
//! and the operator's own: "can it be split in two threads — one always reading frames from the guest,
//! the other picking frames to draw from a small queue that discards the oldest first?").  Before
//! it, the answer was spread over three files: the `Display` struct's two public fields, the
//! `DisplayListener` that filled them from zbus's thread, and the window that drained them on the
//! GTK thread.  Now the whole path is here, and the window only asks it for work.
//!
//! ## The two threads, and what crosses between them
//!
//! ```text
//!   the D-Bus listener (zbus's task)          the GTK thread (one: it draws and shows dialogs)
//!   ───────────────────────────────────          ────────────────────────────────────────────
//!   scanout / update / scanout_map               a 30 Hz GLib tick
//!        │                                             │
//!        ├─ `publish_frame` → the mailbox (capacity 2)  ├─ `take_frame` → the oldest undrawn frame
//!        ├─ `publish_map`   → the newest picture        ├─ `take_damage` → what to upload
//!        └─ `damage`        → the damage log            └─ `glTexSubImage2D` + one quad
//! ```
//!
//! **The listener never waits.** It does three things: it makes the pixels reachable, it records
//! what changed, and it returns.  No GL, and no lock held across a copy — a reader holds an
//! `Arc<Surface>`, and a replaced mapping is unmapped only when the last reference goes, so an
//! upload in progress cannot have its memory taken away (the 2026-10-08 fix for the stall that
//! made the guest's own watchdog report soft lockups).
//!
//! ## The mailbox: capacity 2, and the **oldest** frame is the one that goes
//!
//! A whole frame (a `scanout`) goes into a mailbox holding at most [`MAX_PENDING_FRAMES`] = **2**
//! frames.  When a third arrives before the window has drawn one, the **oldest** is dropped —
//! the operator's own rule, and the reason for the capacity: one frame is being drawn, one is
//! waiting, and anything older than that is a picture of a moment the guest has already moved
//! past.
//!
//! The window draws from the *front* of the mailbox (the oldest undrawn frame), so frames are
//! drawn in the order they arrived and a lagging window loses the oldest ones instead of being
//! handed a backlog it can never catch up with.  The **newest** frame is also kept apart from
//! the mailbox (`publish_frame` sets it as the current picture): an outside reader — the
//! plugin's `/frame`, the status line — wants the picture as it is now, not the one the window
//! has not drawn yet.
//!
//! ## The damage log: merged rectangles, bounded, dropping the oldest
//!
//! The log is not "a frame per entry": it is what changed, as rectangles, and it is deduplicated
//! where the guest repeats itself.  An identical rectangle keeps its **first** timestamp (the
//! wait a person feels is from the first change), a rectangle that covers others absorbs them,
//! and a full-screen rectangle clears the log because everything else is redundant.  It is
//! bounded at [`MAX_DAMAGE`], and when it is full the oldest entry goes: the newest rectangle is
//! where the guest's pointer and its text cursor are.
//!
//! ## What this deliberately does not do
//!
//! It never waits for anything: a tick with nothing damaged reads two atomics and returns, and a
//! guest that has gone quiet costs the window nothing.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::{Damage, Surface};

/// How many whole frames may wait to be drawn before the oldest is dropped.
///
/// **Two**: the one being drawn and the one waiting. Measured: a guest whose whole screen
/// changes every frame and a window
/// that draws at 30 Hz is a 1-frame lag in the good case, and under a stall the frames that are
/// lost are the *oldest*, so what is on screen is as close to "now" as the window can manage.
pub const MAX_PENDING_FRAMES: usize = 2;

/// How many damaged rectangles one upload may carry before the oldest is dropped.
pub const MAX_DAMAGE: usize = 64;

/// A rectangle of the guest's screen, in the window's own terms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

impl Rect {
    /// The whole rectangle of a `width` × `height` screen.
    pub fn screen(width: u32, height: u32) -> Rect {
        Rect {
            x: 0,
            y: 0,
            w: width as i32,
            h: height as i32,
        }
    }

    /// Does this rectangle cover `other` completely?
    pub fn covers(&self, other: &Rect) -> bool {
        self.x <= other.x
            && self.y <= other.y
            && self.x + self.w >= other.x + other.w
            && self.y + self.h >= other.y + other.h
    }
}

impl From<&Damage> for Rect {
    fn from(d: &Damage) -> Rect {
        Rect {
            x: d.x,
            y: d.y,
            w: d.w,
            h: d.h,
        }
    }
}

/// **The frame path**, as one thing: the picture the guest has sent, the whole frames waiting to
/// be drawn (the mailbox), and what changed since the last upload (the damage log).
///
/// It is the whole of the state the two threads share, and every method on it is either the
/// listener's (publish) or the window's (take).  The picture itself is `Arc<Surface>` throughout:
/// a replaced frame is released when the last reader is done with it, never while one is reading
/// it.
pub struct FramePath {
    /// **The newest picture** the guest has sent: what an outside reader (the plugin's `/frame`)
    /// and the window's first frame ever see.  It is not what the window draws from — that is the
    /// mailbox, which keeps the order the frames arrived in — but it is always at least as new.
    current: Mutex<Arc<Surface>>,
    /// Whole frames waiting to be drawn, oldest first, capacity [`MAX_PENDING_FRAMES`].
    pending: Mailbox,
    /// What changed since the last upload.
    damage: DamageLog,
    /// The geometry changed under the window: it must rebuild its texture.
    resized: std::sync::atomic::AtomicBool,
    /// A frame arrived at all: what the window waits for before it shows anything.
    ready: std::sync::atomic::AtomicBool,
    /// The last frame's arrival, in microseconds since the process started: how the window tells
    /// a quiet guest from a broken path.
    last_event_us: std::sync::atomic::AtomicI64,
}

impl Default for FramePath {
    fn default() -> Self {
        FramePath {
            current: Mutex::new(Arc::new(Surface::Empty)),
            pending: Mailbox::default(),
            damage: DamageLog::default(),
            resized: std::sync::atomic::AtomicBool::new(false),
            ready: std::sync::atomic::AtomicBool::new(false),
            last_event_us: std::sync::atomic::AtomicI64::new(0),
        }
    }
}

impl FramePath {
    pub fn new() -> FramePath {
        FramePath::default()
    }

    // -------------------------------------------------------------- the reader (the window)

    /// **The frame to draw now**: the oldest whole frame the window has not drawn, or the newest
    /// picture when nothing is waiting.  `None` means the guest has sent nothing at all.
    pub fn take_frame(&self) -> Option<Arc<Surface>> {
        if let Some(frame) = self.pending.take() {
            return Some(frame);
        }
        let current = self.current.lock().unwrap().clone();
        if current.is_empty() {
            None
        } else {
            Some(current)
        }
    }

    /// Everything to upload now, and an empty log afterwards.
    pub fn take_damage(&self) -> Vec<Damage> {
        self.damage.take()
    }

    /// Take the "rebuild the texture" flag.
    pub fn take_resized(&self) -> bool {
        self.resized
            .swap(false, std::sync::atomic::Ordering::Relaxed)
    }

    /// The picture as it is **now**, for a reader that is not drawing (the plugin, a report).
    pub fn current(&self) -> Arc<Surface> {
        self.current.lock().unwrap().clone()
    }

    /// The picture **under its lock**, for the one caller that must write into it: the inline
    /// `update`, which splices a rectangle into our own copy of the frame (a mapping is written
    /// by the guest itself, never by us).  The lock is held for that splice and no longer.
    pub fn current_guard(&self) -> std::sync::MutexGuard<'_, Arc<Surface>> {
        self.current.lock().unwrap()
    }

    pub fn has_pixels(&self) -> bool {
        !self.current.lock().unwrap().is_empty()
    }

    pub fn is_ready(&self) -> bool {
        self.ready.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn last_event_us(&self) -> i64 {
        self.last_event_us
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// How many whole frames are waiting (a window that is falling behind shows it here).
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// How many whole frames have been dropped for being older than what is waiting.
    pub fn dropped_frames(&self) -> u64 {
        self.pending.dropped()
    }

    /// How many rectangles are waiting to be uploaded (a window that is behind shows it here).
    pub fn damage_waiting(&self) -> u64 {
        self.damage.waiting()
    }

    /// When the oldest waiting rectangle arrived (`0` when none is).
    pub fn damage_oldest_us(&self) -> i64 {
        self.damage.oldest_us()
    }

    pub fn damage_len(&self) -> usize {
        self.damage.len()
    }

    pub fn dropped_damage(&self) -> u64 {
        self.damage.dropped()
    }

    // -------------------------------------------------------- the publisher (the machine's listener)

    /// **A whole new frame** (a `scanout`): the picture replaces the last one, it joins the
    /// mailbox's queue, and the whole screen is damaged.
    ///
    /// Returns the frame the mailbox dropped for being too old, so a caller can report the window
    /// falling behind.  The surface this replaces is *not* dropped here: the mailbox and
    /// [`FramePath::current`] both hold it, and it goes when the last reader has it no more.
    pub fn publish_scanout(&self, new: Surface, screen: Rect, ts_us: i64) -> Option<Arc<Surface>> {
        let frame = Arc::new(new);
        self.set_current(frame.clone());
        self.damage.add(screen, ts_us, screen, 0);
        self.ready.store(true, std::sync::atomic::Ordering::Relaxed);
        self.last_event_us
            .store(ts_us, std::sync::atomic::Ordering::Relaxed);
        self.pending.push(frame)
    }

    /// A **rectangle** of the current picture changed (an inline `update`, or the `update_map`
    /// that names what changed inside the guest's own shared mapping).
    pub fn publish_damage(&self, rect: Rect, screen: Rect, ts_us: i64, generation: u32) {
        self.damage.add(rect, ts_us, screen, generation);
        self.ready.store(true, std::sync::atomic::Ordering::Relaxed);
        self.last_event_us
            .store(ts_us, std::sync::atomic::Ordering::Relaxed);
    }

    /// The console is now a shared mapping (a `scanout_map`): the picture is that mapping, and
    /// everything on it counts as changed.
    pub fn publish_map(&self, new: Surface, screen: Rect, ts_us: i64) -> Option<Arc<Surface>> {
        let frame = Arc::new(new);
        self.set_current(frame.clone());
        self.damage.add(screen, ts_us, screen, 0);
        self.ready.store(true, std::sync::atomic::Ordering::Relaxed);
        self.last_event_us
            .store(ts_us, std::sync::atomic::Ordering::Relaxed);
        self.pending.push(frame)
    }

    /// The console went away.
    pub fn publish_disabled(&self) {
        self.set_current(Arc::new(Surface::Empty));
    }

    /// The geometry changed: the window must rebuild its texture (the caller compares the
    /// geometry, so this is only called when it really did).
    pub fn mark_resized(&self) {
        self.resized
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Install a new picture, dropping the reference to the one before it.
    ///
    /// It is a whole-frame publish without the damage or the mailbox: the tests and the frame
    /// probe use it to put a picture in place, and the listener never does (it publishes **and**
    /// makes the window draw it).
    pub fn replace_current(&self, new: Surface) {
        let mut cur = self.current.lock().unwrap();
        *cur = Arc::new(new);
    }

    fn set_current(&self, new: Arc<Surface>) {
        let mut cur = self.current.lock().unwrap();
        *cur = new;
    }
}

impl std::fmt::Debug for Mailbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // A frame is a pointer (or a copy) and has no useful `Debug` of its own; the queue's
        // *length* and what it dropped are the interesting facts, and those are printed.
        f.debug_struct("Mailbox")
            .field("frames", &self.len())
            .field("dropped", &self.dropped())
            .finish()
    }
}

/// **The mailbox**: whole frames waiting to be drawn, oldest first, dropping the oldest.
///
/// A `Mutex<VecDeque<Arc<Surface>>>` with a capacity, and nothing else — the frames themselves
/// are `Arc`s, so "dropping" one is dropping a reference and the mapping it points at goes only
/// when the window is done reading it.
#[derive(Default)]
pub struct Mailbox {
    frames: Mutex<VecDeque<Arc<Surface>>>,
    /// How many frames were dropped because the window had not drawn the older ones: the number
    /// that says the window is the slow side.
    dropped: Mutex<u64>,
}

impl Mailbox {
    pub fn new() -> Mailbox {
        Mailbox::default()
    }

    /// A new whole frame arrived.  Returns the frame the mailbox had to drop, if any (so the
    /// caller can say when the window is falling behind).
    pub fn push(&self, frame: Arc<Surface>) -> Option<Arc<Surface>> {
        let mut q = self.frames.lock().unwrap();
        q.push_back(frame);
        let mut dropped = None;
        while q.len() > MAX_PENDING_FRAMES {
            dropped = q.pop_front();
            if let Ok(mut n) = self.dropped.lock() {
                *n += 1;
            }
        }
        dropped
    }

    /// **The oldest undrawn frame**, or `None` when the window is up to date.
    pub fn take(&self) -> Option<Arc<Surface>> {
        let mut q = self.frames.lock().unwrap();
        q.pop_front()
    }

    /// How many frames are waiting.
    pub fn len(&self) -> usize {
        self.frames.lock().map(|q| q.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// How many frames have been dropped for being older than what is waiting.
    pub fn dropped(&self) -> u64 {
        self.dropped.lock().map(|n| *n).unwrap_or(0)
    }
}

/// **The damage log**: what changed since the last upload, merged and bounded.
#[derive(Debug, Default)]
pub struct DamageLog {
    rects: Mutex<VecDeque<Damage>>,
    /// How many rectangles were dropped for being older than the newest ones.
    dropped: Mutex<u64>,
    /// How many rectangles are waiting, and when the oldest one arrived (`/status` reports both;
    /// see `add`).
    waiting: AtomicU64,
    oldest_us: AtomicI64,
}

impl DamageLog {
    pub fn new() -> DamageLog {
        DamageLog::default()
    }

    /// Add a rectangle, merging what it makes redundant, and dropping the oldest when the log
    /// is full.
    ///
    /// The rectangle is **clipped to `screen` first**: the guest may name more than it defined
    /// (a console that shrank, a stale rectangle), and an upload of what is off the screen is
    /// an upload of nothing.
    pub fn add(&self, rect: Rect, ts_us: i64, screen: Rect, generation: u32) {
        if rect.w <= 0 || rect.h <= 0 {
            return;
        }
        let x = rect.x.max(screen.x);
        let y = rect.y.max(screen.y);
        let right = (rect.x + rect.w).min(screen.x + screen.w);
        let bottom = (rect.y + rect.h).min(screen.y + screen.h);
        let rect = Rect {
            x,
            y,
            w: (right - x).max(0),
            h: (bottom - y).max(0),
        };
        if rect.w <= 0 || rect.h <= 0 {
            return;
        }
        let mut q = self.rects.lock().unwrap();
        // **How many rectangles are waiting to be uploaded.**  A window that draws at 30 Hz and a
        // guest that reports 600 rectangles a second is a window whose uploads are always behind —
        // and the *only* way to see that from outside is to count what is waiting.  The earliest
        // `ts_us` in the queue is kept beside it, so the age of the oldest un-uploaded rectangle
        // (which is what a person feels as lag) is readable too.
        self.waiting.store(q.len() as u64 + 1, Ordering::Relaxed);
        if q.is_empty() {
            self.oldest_us.store(ts_us, Ordering::Relaxed);
        }
        if rect.covers(&screen) {
            // The whole screen: everything already waiting is redundant.
            q.clear();
            q.push_back(Damage {
                x: rect.x,
                y: rect.y,
                w: rect.w,
                h: rect.h,
                ts_us,
                generation,
            });
            return;
        }
        // Already covered by something in the log (or identical to it): the guest repeated
        // itself, and the earlier timestamp is the one that matters.
        if q.iter().any(|d| Rect::from(d).covers(&rect)) {
            return;
        }
        // Anything this rectangle covers is absorbed by it.
        q.retain(|d| !rect.covers(&Rect::from(d)));
        q.push_back(Damage {
            x: rect.x,
            y: rect.y,
            w: rect.w,
            h: rect.h,
            ts_us,
            generation,
        });
        while q.len() > MAX_DAMAGE {
            q.pop_front();
            if let Ok(mut n) = self.dropped.lock() {
                *n += 1;
            }
        }
    }

    /// Everything to upload now, and an empty log afterwards.
    pub fn take(&self) -> Vec<Damage> {
        let mut q = self.rects.lock().unwrap();
        let taken: Vec<Damage> = q.drain(..).collect();
        // Nothing is waiting any more: the numbers an outside reader watches (`waiting`,
        // `oldest_us`) go back to zero with the queue.
        self.waiting.store(0, Ordering::Relaxed);
        self.oldest_us.store(0, Ordering::Relaxed);
        taken
    }

    pub fn len(&self) -> usize {
        self.rects.lock().map(|q| q.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// How many rectangles are waiting to be uploaded (`/status`'s own number).
    pub fn waiting(&self) -> u64 {
        self.waiting.load(Ordering::Relaxed)
    }

    /// When the oldest waiting rectangle arrived, in the display's own microseconds — so an
    /// outside reader can say how far behind the picture is.  `0` when nothing is waiting.
    pub fn oldest_us(&self) -> i64 {
        self.oldest_us.load(Ordering::Relaxed)
    }

    /// How many rectangles have been dropped for being older than the newest ones.
    pub fn dropped(&self) -> u64 {
        self.dropped.lock().map(|n| *n).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(byte: u8) -> Arc<Surface> {
        Arc::new(Surface::Copy(vec![byte; 16]))
    }

    fn rect(x: i32, y: i32, w: i32, h: i32) -> Rect {
        Rect { x, y, w, h }
    }

    #[test]
    fn the_mailbox_hands_frames_over_in_the_order_they_arrived() {
        let m = Mailbox::new();
        assert!(m.take().is_none(), "nothing has arrived yet");
        m.push(frame(1));
        m.push(frame(2));
        assert_eq!(m.len(), 2);
        assert_eq!(m.take().unwrap().as_slice()[0], 1, "the oldest first");
        assert_eq!(m.take().unwrap().as_slice()[0], 2);
        assert!(m.take().is_none());
        assert_eq!(m.dropped(), 0);
    }

    #[test]
    fn a_third_frame_drops_the_oldest_and_the_window_stays_two_behind_at_most() {
        let m = Mailbox::new();
        m.push(frame(1));
        m.push(frame(2));
        let dropped = m.push(frame(3));
        assert_eq!(
            dropped.map(|f| f.as_slice()[0]),
            Some(1),
            "the oldest is the one that goes"
        );
        assert_eq!(m.len(), MAX_PENDING_FRAMES);
        assert_eq!(m.take().unwrap().as_slice()[0], 2);
        assert_eq!(m.take().unwrap().as_slice()[0], 3);
        assert_eq!(m.dropped(), 1);
    }

    #[test]
    fn a_window_that_never_draws_loses_frames_but_never_grows_a_backlog() {
        let m = Mailbox::new();
        for i in 0..100 {
            m.push(frame(i as u8));
        }
        assert_eq!(
            m.len(),
            MAX_PENDING_FRAMES,
            "bounded, whatever the guest does"
        );
        assert_eq!(m.dropped(), 98);
        assert_eq!(m.take().unwrap().as_slice()[0], 98);
        assert_eq!(m.take().unwrap().as_slice()[0], 99);
    }

    #[test]
    fn the_damage_log_merges_a_repeated_rectangle_and_keeps_its_first_instant() {
        let log = DamageLog::new();
        let screen = Rect::screen(16, 16);
        log.add(rect(2, 2, 4, 4), 100, screen, 1);
        log.add(rect(2, 2, 4, 4), 200, screen, 2);
        let dmg = log.take();
        assert_eq!(
            dmg.len(),
            1,
            "the same rectangle twice is one upload: {dmg:?}"
        );
        assert_eq!(dmg[0].ts_us, 100, "the wait started with the first change");
        assert_eq!(
            dmg[0].generation, 1,
            "and it keeps the message the first one came in"
        );
    }

    #[test]
    fn a_rectangle_absorbs_the_ones_it_covers() {
        let log = DamageLog::new();
        let screen = Rect::screen(16, 16);
        log.add(rect(1, 1, 2, 2), 10, screen, 1);
        log.add(rect(8, 8, 2, 2), 20, screen, 2);
        log.add(rect(0, 0, 12, 12), 30, screen, 3);
        let dmg = log.take();
        assert_eq!(dmg.len(), 1, "one upload covers all three: {dmg:?}");
        assert_eq!((dmg[0].w, dmg[0].h), (12, 12));
        assert_eq!(
            dmg[0].generation, 3,
            "the newest message is the one that carries it"
        );
    }

    #[test]
    fn a_full_screen_rectangle_clears_everything_before_it() {
        let log = DamageLog::new();
        let screen = Rect::screen(8, 8);
        for i in 0..5 {
            log.add(rect(i, i, 1, 1), i as i64, screen, i as u32);
        }
        log.add(screen, 99, screen, 99);
        let dmg = log.take();
        assert_eq!(
            dmg.len(),
            1,
            "the full frame makes the rest redundant: {dmg:?}"
        );
        assert_eq!((dmg[0].w, dmg[0].h, dmg[0].ts_us), (8, 8, 99));
    }

    #[test]
    fn the_damage_log_is_bounded_and_drops_the_oldest() {
        let log = DamageLog::new();
        // A screen wide enough for every rectangle to be real damage: the clipping is a separate
        // rule, tested on its own below.
        let screen = Rect::screen(1024, 4);
        for i in 0..(MAX_DAMAGE + 10) {
            log.add(rect(i as i32, 0, 1, 1), i as i64, screen, i as u32);
        }
        assert_eq!(log.len(), MAX_DAMAGE, "one frame's worth of rectangles");
        let dmg = log.take();
        assert_eq!(
            dmg.last().unwrap().x,
            (MAX_DAMAGE + 9) as i32,
            "the newest is the one that stays"
        );
        assert!(
            dmg.iter().all(|d| d.x >= 10),
            "the first ten were the ones dropped: {dmg:?}"
        );
        assert_eq!(log.dropped(), 10);
    }

    #[test]
    fn a_rectangle_off_the_screen_is_clipped_and_a_degenerate_one_is_not_damage() {
        let log = DamageLog::new();
        let screen = Rect::screen(4, 4);
        // Partly off: only the part on the screen is damage.
        log.add(rect(-2, -2, 4, 4), 1, screen, 1);
        let dmg = log.take();
        assert_eq!((dmg[0].x, dmg[0].y, dmg[0].w, dmg[0].h), (0, 0, 2, 2));
        // Entirely off, and empty: neither is damage at all.
        log.add(rect(100, 100, 4, 4), 2, screen, 2);
        assert!(log.is_empty());
    }

    #[test]
    fn a_degenerate_rectangle_is_not_damage() {
        let log = DamageLog::new();
        let screen = Rect::screen(4, 4);
        log.add(rect(0, 0, 0, 4), 1, screen, 1);
        log.add(rect(0, 0, 4, 0), 2, screen, 2);
        assert!(log.is_empty());
        assert!(log.take().is_empty());
    }
}
