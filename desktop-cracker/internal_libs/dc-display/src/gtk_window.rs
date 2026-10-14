//! The display window as GTK sees it: a `gtk::Window` whose whole content is a
//! `gtk::GLArea`, with the OpenGL calls reached through `glow`.
//!
//! This is the platform half of `crate::window`.  It owns:
//!
//! * the **GTK window** and its **GLArea** — the drawing surface is GTK's, so the display
//!   window is one more GTK window in the session, on the same thread and in the same main
//!   loop as every dialog the application puts up;
//! * the **GL loader**: GTK draws through libepoxy, and libepoxy's own dispatcher
//!   (`epoxy_glXGetProcAddress` / `epoxy_eglGetProcAddress`) is what `glow` needs to reach the
//!   driver for *GTK's* context.  Those symbols are already in the process — GTK links them —
//!   so this is a `dlsym`, not a new dependency;
//! * the window's **X id**, which a dialog attaches itself to so a question lands over the
//!   guest's screen.  `gdk_x11_window_get_xid` is in the libgdk-3 that is already linked;
//!   `gdk-sys` simply does not declare the X11 half of its own API, so it is reached the same
//!   way.
//!
//! What this module is *not*: it is not the display rule, the frame path or the input
//! translation.  Those stay in `crate::window`, which reads the platform through the small
//! vocabulary here.

use std::os::raw::{c_char, c_void};

use gtk::prelude::*;

/// A GL function loader, as `glow` wants one.
type GetProcAddress = unsafe extern "C" fn(*const c_char) -> *const c_void;

/// Look a symbol up in the libraries this process has already loaded.
fn symbol(name: &str) -> Option<*mut c_void> {
    let c = match std::ffi::CString::new(name) {
        Ok(c) => c,
        Err(_) => return None,
    };
    // SAFETY: `RTLD_DEFAULT` searches the global scope; a miss is a null pointer, which the
    // caller reads as "not here".
    let sym = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c.as_ptr()) };
    (!sym.is_null()).then_some(sym)
}

/// **The GL loader: libepoxy's own dispatcher.**
///
/// GTK draws through libepoxy, and libepoxy opens libGL with `RTLD_LOCAL` — so a plain
/// `dlsym(RTLD_DEFAULT, "glTexImage2D")` finds nothing, which is exactly the "glow loaded but
/// every call is null" failure this had before.  What *is* in the global scope is libepoxy's
/// dispatcher, and it is exported as a **variable holding the function pointer**
/// (`extern PFNGLXGETPROCADDRESSPROC epoxy_glXGetProcAddress;`), not as a symbol whose address
/// is the code: the extra load below is that indirection, not a flourish.
fn epoxy_loader() -> Option<GetProcAddress> {
    for name in ["epoxy_glXGetProcAddress", "epoxy_eglGetProcAddress"] {
        let Some(sym) = symbol(name) else { continue };
        // SAFETY: libepoxy exports these two as function-pointer *variables*; a null one is
        // skipped, and the result is only used as a loader.
        let held = unsafe { *(sym as *const *const c_void) };
        if held.is_null() {
            continue;
        }
        return Some(unsafe { std::mem::transmute::<*const c_void, GetProcAddress>(held) });
    }
    None
}

/// `gdk_x11_window_get_xid`, which `gdk-sys` does not declare (its X11 half is generated
/// behind a feature the crate does not carry).  The symbol is in the libgdk-3 already linked.
fn x11_window_id(window: &gtk::Window) -> Option<u64> {
    type GetXid = unsafe extern "C" fn(*mut gdk::ffi::GdkWindow) -> libc::c_uint;
    let sym = symbol("gdk_x11_window_get_xid")?;
    // SAFETY: the symbol is GDK's own, and the `GdkWindow` borrowed here is the one GTK owns
    // for as long as this window exists.
    Some(unsafe {
        let f: GetXid = std::mem::transmute::<*mut c_void, GetXid>(sym);
        let gdk_window = window.window()?;
        use gtk::glib::translate::ToGlibPtr;
        f(gdk_window.to_glib_none().0) as u64
    })
}

/// What the window manager may do with a window: **move, minimize, close** while it is on
/// screen, everything while it is full screen (there is no decoration to get wrong then).
///
/// It is a free function because it runs from two places — the window's creation, when there
/// is no `Platform` yet, and every shape change (`Platform::apply_chrome`).
fn apply_chrome_to(window: &gtk::Window, fullscreen: bool) {
    let Some(gdk_window) = window.window() else {
        return;
    };
    if fullscreen {
        gdk_window.set_functions(gdk::WMFunction::ALL);
    } else {
        gdk_window.set_functions(
            gdk::WMFunction::MOVE | gdk::WMFunction::MINIMIZE | gdk::WMFunction::CLOSE,
        );
    }
}

/// **Where the pointer is, as this window's two halves see it** (see
/// [`Platform::pointer_state`]).
///
/// `client` is the position inside the **display area** — the guest's screen — in window pixels, and
/// `None` means the pointer is not there.  `over_our_chrome` is "inside the frame the window manager
/// drew for this window, but outside the display area": the title bar and the border, which are the
/// window's own and the reason a title-bar drag has to be the window manager's, not the guest's.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct PointerState {
    pub client: Option<(f64, f64)>,
    pub over_our_chrome: bool,
}

/// **The rule, in numbers** (what [`Platform::pointer_state`] measures and hands here).
///
/// * `pointer` — the pointer's position on the **root** window (`gdk_device_get_position`);
/// * `window` — our own X window: its absolute origin (`gdk_window_get_root_coords(0, 0)`) and its
///   size (`gdk_window_get_geometry`);
/// * `frame` — the whole decorated rectangle the window manager drew for us
///   (`gdk_window_get_frame_extents`), which is bigger than our own window by exactly the title bar
///   and the border.
///
/// The display area is our own window's rectangle; the chrome is everything the manager drew that is
/// not it.  Measured on this host (a decorated `gtk::Window` with a `gtk::GLArea`, under mutter 42.9
/// both nested and on the operator's own session): our window at absolute (120, 157) of size 400x300
/// inside a frame of (120, 120, 400, 337) — `_NET_FRAME_EXTENTS = 0, 0, 37, 0` — so a pointer at root
/// (320, 270) is at (200, 113) in the display area, and one at (320, 121) is on the bar.
fn place_pointer(
    pointer: (i32, i32),
    window: (i32, i32, i32, i32),
    frame: (i32, i32, i32, i32),
) -> PointerState {
    let (x, y) = pointer;
    let (wx, wy, width, height) = window;
    let (fx, fy, fwidth, fheight) = frame;
    let (width, height) = (i64::from(width), i64::from(height));
    let in_window = i64::from(x) >= i64::from(wx)
        && i64::from(x) < i64::from(wx) + width
        && i64::from(y) >= i64::from(wy)
        && i64::from(y) < i64::from(wy) + height;
    if in_window {
        return PointerState {
            client: Some((f64::from(x - wx), f64::from(y - wy))),
            over_our_chrome: false,
        };
    }
    let in_frame = i64::from(x) >= i64::from(fx)
        && i64::from(x) < i64::from(fx) + i64::from(fwidth)
        && i64::from(y) >= i64::from(fy)
        && i64::from(y) < i64::from(fy) + i64::from(fheight);
    PointerState {
        client: None,
        over_our_chrome: in_frame,
    }
}

/// The GTK window, its GLArea, and the GL context they were realized with.
pub struct Platform {
    window: gtk::Window,
    area: gtk::GLArea,
    /// The GL calls, loaded from the context the GLArea was realized with.  It is `None` until
    /// the first frame, because the context only exists once GTK has realized the area.
    gl: Option<glow::Context>,
    /// The size the window last reported (the GL viewport is drawn at this).
    size: (u32, u32),
    /// The size the **rule** last asked for.  The window manager may still be catching up, and
    /// the frame is drawn at the rule's size, not at the manager's opinion of it.
    pinned: Option<(u32, u32)>,
    fullscreen: bool,
    x11_id: Option<u64>,
}

impl Platform {
    /// Make the window and its drawing area.  `visible` is the window's first state: a run
    /// that starts hidden (`--window-hidden`, or a window that comes back past a password)
    /// creates it unmapped, exactly as the old platform path did.
    pub fn open(title: &str, width: u32, height: u32, visible: bool) -> Result<Platform, String> {
        if !gtk::is_initialized() && gtk::init().is_err() {
            return Err("no display server for the window".into());
        }
        let window = gtk::Window::new(gtk::WindowType::Toplevel);
        window.set_title(title);
        window.set_default_size(width as i32, height as i32);
        // **The size is the rule's, never the user's**: the picture is the guest's whole screen,
        // and dragging an edge would stretch a desktop the guest believes has another size.  What
        // stops that is the window's own **functions** (`apply_chrome_to`: move, minimize, close —
        // no resize, no maximize), NOT `set_resizable(false)`: GTK answers that one by making the
        // window's minimum size equal its maximum, and the *content's* natural size (200x200 for
        // an empty GLArea — measured) then wins over every `resize` the display rule asks for.
        window.set_resizable(true); // **Where it opens**: the middle of the screen (`dc-ui`, the one placement rule).
                                    // `set_default_size` above is what the rule measures before the window exists, and the
                                    // move happens before `show_all` below — there is no jump for the user to see.
        window.set_position(gtk::WindowPosition::Center);
        dc_ui::center(&window);

        let area = gtk::GLArea::new();
        area.set_required_version(3, 3);
        area.set_has_depth_buffer(false);
        area.set_has_stencil_buffer(false);
        // The frame is queued by the loop (30 Hz), not by GTK on every draw: the display path
        // is measured, and a window that redraws whenever the session feels like it is a window
        // whose cost nobody can account for.
        area.set_auto_render(false);
        area.set_can_focus(true);
        // **The pointer events the signals below are connected to.**
        //
        // A GTK widget receives only the events its **window mask** asks for, and the motion events
        // are not in GTK's default set for a `GLArea`: its `motion_notify_event` signal therefore
        // never fires and the guest is never told where the pointer is — measured on this host, a
        // GLArea-only window received **no** motion and no button event at all, while the same
        // window in plain C with `add_events` received both.  The keyboard is not affected: GTK's
        // default mask already asks for the key events, which is why the keys worked and the mouse
        // did not.
        // The mask goes on the **toplevel**, which is where the pointer's events are delivered
        // (the area is windowless: GDK hands the pointer's events to the window that owns the
        // surface).  Measured on this host: without this line the toplevel's mask has the button
        // motions and NOT the plain one, so the pointer moved and nothing at all was said about it.
        window.add_events(
            gdk::EventMask::POINTER_MOTION_MASK
                | gdk::EventMask::BUTTON_MOTION_MASK
                | gdk::EventMask::BUTTON_PRESS_MASK
                | gdk::EventMask::BUTTON_RELEASE_MASK
                | gdk::EventMask::SCROLL_MASK
                | gdk::EventMask::SMOOTH_SCROLL_MASK
                | gdk::EventMask::ENTER_NOTIFY_MASK
                | gdk::EventMask::LEAVE_NOTIFY_MASK,
        );
        window.add(&area);

        if visible {
            window.show_all();
            // The window's own chrome — no border, no maximize button, only minimize and close
            // (see `apply_chrome`) — is applied as it is created, so the first frame is already
            // the shape the rule asks for.
            apply_chrome_to(&window, false);
            // The guest's own pointer is in the picture; the session's would be a second arrow
            // over it (see `hide_host_cursor`).  It is set at creation and again on every Show,
            // because a window GTK has just mapped is a window whose cursor is GTK's default.
            let blank = gdk::Display::default()
                .and_then(|d| gdk::Cursor::for_display(&d, gdk::CursorType::BlankCursor));
            if let Some(gdk_window) = window.window() {
                gdk_window.set_cursor(blank.as_ref());
            }
        }
        let x11_id = window.window().and_then(|_| x11_window_id(&window));
        Ok(Platform {
            window,
            area,
            gl: None,
            size: (width.max(1), height.max(1)),
            pinned: Some((width.max(1), height.max(1))),
            fullscreen: false,
            x11_id,
        })
    }
    pub fn window(&self) -> &gtk::Window {
        &self.window
    }

    pub fn area(&self) -> &gtk::GLArea {
        &self.area
    }

    /// Ask GTK for the next frame.  The drawing itself happens in the `render` signal, which
    /// is where GTK's GL context is current.
    pub fn queue_render(&self) {
        self.area.queue_render();
    }

    /// The GL calls, loaded once from the context the GLArea was realized with.
    ///
    /// # Safety of the context
    ///
    /// `glow::Context` is not `Sync`, and every call to it happens inside the `render` signal
    /// of this window's own GLArea — that is, on the thread running the GTK main loop, with
    /// this context current.  That is what makes handing out the reference safe.
    pub fn gl(&mut self, area: &gtk::GLArea) -> Result<&glow::Context, String> {
        if self.gl.is_none() {
            let loader = epoxy_loader().ok_or_else(|| {
                "no libepoxy GL dispatcher in this process (GTK draws through libepoxy)".to_string()
            })?;
            // SAFETY: the loader is libepoxy's dispatcher, and `from_loader_function_cstr` only
            // calls it to resolve names.
            // SAFETY: the loader is libepoxy's dispatcher, and `from_loader_function_cstr`
            // only calls it to resolve names.
            let context = unsafe {
                glow::Context::from_loader_function_cstr(|name| {
                    loader(name.as_ptr() as *const c_char)
                })
            };
            if let Some(error) = area.error() {
                return Err(format!("the GL area could not get a context: {error}"));
            }
            self.gl.replace(context);
        }
        Ok(self.gl.as_ref().expect("just loaded"))
    }

    pub fn gl_loaded(&self) -> bool {
        self.gl.is_some()
    }

    /// The size the window **is** (what the GL viewport is drawn at).
    pub fn size(&self) -> (u32, u32) {
        self.size
    }

    /// **The pointer's position inside the window**, in window pixels.
    ///
    /// The pointer's events are the **toplevel's** (a `gtk::GLArea` is a windowless widget: GTK
    /// delivers the pointer's events to the window that owns the surface — measured, the area's
    /// `motion_notify_event` never fires), so the position a callback receives is asked from GDK
    /// rather than read off the signal.  It is the position *in this window*, which is what
    /// `Window::to_guest` scales into the guest's own coordinates.
    ///
    /// `None` when the pointer is not in the **display area**: over another window, over this
    /// window's own title bar or border, or when GDK has nothing to say (no pointer on this seat, a
    /// window not yet mapped).  The caller reads that as "nothing moved".
    pub fn pointer_position(&self) -> Option<(f64, f64)> {
        self.pointer_state().client
    }

    /// **Where the pointer is: in the guest's display area, or on this window's own chrome.**
    ///
    /// Measured on this host, both window kinds (a decorated `gtk::Window` with a `gtk::GLArea`):
    ///
    /// * under mutter (`Xephyr` + `mutter --x11 -d :9`, and the operator's own GNOME session on
    ///   `:1`) the title bar is the window manager's **frame**: `gdk_window_get_root_origin` answers
    ///   the frame's origin (120, 120), `gdk_window_get_geometry` answers our own X window at
    ///   absolute (120, **157**) — 37 px lower, `_NET_FRAME_EXTENTS = 0, 0, 37, 0` — and
    ///   `gdk_window_get_frame_extents` answers the whole decorated rectangle (120, 120, 400, 337);
    /// * **no pointer event of ours fires on the title bar** — no motion, no press, no wheel: the
    ///   frame window has them, which is why the bar can be dragged at all;
    /// * `gdk_window_get_device_position` on our own window answers the position **relative to our X
    ///   window** — `(200, 113)` for a pointer at root (320, 270), matching the `motion_notify_event`
    ///   position exactly, and a **negative y** for a pointer on the bar (`(200, -36)` at root
    ///   (320, 121));
    /// * `gdk_seat_get_pointer`'s `window_at_position` answers **our window** over the display area
    ///   and `None`/`(-1,-1)` over the bar and over any other window.
    ///
    /// So the display area is `0 ≤ y < height` under our own window, and the chrome is everything
    /// inside `frame_extents` that is not that: the bar mutter drew for us, which is the window's,
    /// not the guest's screen.
    pub fn pointer_state(&self) -> PointerState {
        let Some(ours) = self.window.window() else {
            return PointerState::default();
        };
        let Some(display) = gdk::Display::default() else {
            return PointerState::default();
        };
        let Some(seat) = display.default_seat() else {
            return PointerState::default();
        };
        let Some(pointer) = seat.pointer() else {
            return PointerState::default();
        };
        // The pointer on the **root** (`gdk_device_get_position`): the one reading that exists for a
        // pointer over the title bar, where `window_at_position` answers `None` and no signal of ours
        // fires at all.
        let (_screen, x, y) = pointer.position();
        // Our own X window, in root coordinates: `gdk_window_get_root_coords(0, 0)` is where our
        // window **is**, which is not where the frame starts (`gdk_window_get_root_origin` answers the
        // frame's origin, 37 px higher under mutter).
        let (wx, wy) = ours.root_coords(0, 0);
        let (_x, _y, width, height) = ours.geometry();
        let frame = ours.frame_extents();
        place_pointer(
            (x, y),
            (wx, wy, width.max(1), height.max(1)),
            (
                frame.x(),
                frame.y(),
                frame.width().max(1),
                frame.height().max(1),
            ),
        )
    }

    /// The size the rule last asked for.
    pub fn pinned_size(&self) -> (u32, u32) {
        self.pinned.unwrap_or_else(|| self.size())
    }

    /// Record the size GTK says the window has.
    pub fn report_size(&mut self, width: u32, height: u32) {
        self.size = (width.max(1), height.max(1));
    }

    /// Ask for a size.  The window is **left resizable** and its size is followed: the
    /// operator's own words — "Instead of not allowing the window being resizable, why do not we
    /// monitor the resize event?" — and the fix for a resize that never landed.
    ///
    /// The window is re-centered as it changes shape: a window that grew into a corner is a
    /// window the user has to hunt for, and the rule is that every one of this application's
    /// windows is in the middle of the screen (see `dc_ui::center`).
    pub fn set_size(&mut self, width: u32, height: u32) {
        let (width, height) = (width.max(1), height.max(1));
        self.pinned = Some((width, height));
        if self.fullscreen {
            self.set_fullscreen(false);
        }
        self.window.resize(width as i32, height as i32);
        // GTK reports the real size through the configure event; assume it for the frame until
        // it says otherwise, which is what keeps the picture the rule's size for one frame.
        self.size = (width, height);
        // **The size is fixed while the window is one of the rule's shapes**: the hints tell the
        // window manager that this window's minimum and maximum size are the same number, which is
        // what takes the resize handles away (the title bar keeps only minimize and close — the
        // operator, 2026-10-09).  The rule's own `resize` above is not a user resize and is applied
        // before the hint, so nothing clamps it. The guest's window is fixed; only while the
        // window is hidden is the hint dropped.
        let hints = gdk::Geometry::new(
            width as i32,
            height as i32,
            width as i32,
            height as i32,
            0,
            0,
            0,
            0,
            0f64,
            0f64,
            gdk::Gravity::NorthWest,
        );
        self.window.set_geometry_hints(
            None::<&gtk::Widget>,
            Some(&hints),
            gdk::WindowHints::MIN_SIZE | gdk::WindowHints::MAX_SIZE,
        );
        if !self.fullscreen {
            // A full-screen window is the whole screen already: there is no middle to ask for.
            let (x, y) = dc_ui::centered_at(
                (width as i32, height as i32),
                dc_ui::screen_size().unwrap_or((width as i32, height as i32)),
            );
            self.window.move_(x, y);
        }
        self.queue_render();
    }

    /// Show or hide the window.  A hidden window is not a destroyed one: the guest keeps
    /// running, and `numlock + F9` brings it back.
    pub fn set_visible(&self, visible: bool) {
        if visible {
            self.window.show_all();
        } else {
            self.window.hide();
        }
    }

    /// **The host's own pointer goes away over this window.**
    ///
    /// The picture inside the window already carries the **guest's** pointer: the channel sends it as
    /// its own cursor resource and the frame path composites it ("the guest's pointer is drawn,
    /// in the right place and with its own pixels", postmortem of 2026-10-08).  The session's own
    /// pointer would be a second arrow wherever the host's mouse happens to be — which is the
    /// "two cursors" the operator saw, one of them not the guest's.
    ///
    /// `BlankCursor` is GDK's "no cursor at all", and it is set **on this window**: the user's
    /// pointer is untouched everywhere else on their desktop, and this only applies while the
    /// window is under it.  A session that cannot make the cursor keeps its own; the window is
    /// still usable that way.
    pub fn hide_host_cursor(&self) {
        let Some(gdk_window) = self.window.window() else {
            return;
        };
        let Some(display) = gdk::Display::default() else {
            return;
        };
        if let Some(blank) = gdk::Cursor::for_display(&display, gdk::CursorType::BlankCursor) {
            gdk_window.set_cursor(Some(&blank));
        }
    }

    /// Borderless full screen, or the decorated window again.
    ///
    /// **The title bar's buttons are the whole of the window's chrome** (the operator,
    /// 2026-10-09: "the title bar has only minimize and close button"): while the window is the
    /// guest's screen it is **not resizable** — the picture is the guest's, and a drag of its edge
    /// would stretch the desktop the guest believes it has — so its window-manager functions are
    /// exactly *move, minimize, close*.  Full screen takes the decoration away entirely
    /// (borderless, no title bar); the window at the guest's own size keeps it.
    pub fn set_fullscreen(&mut self, fullscreen: bool) {
        if fullscreen && !self.fullscreen {
            self.window.fullscreen();
            self.fullscreen = true;
        } else if !fullscreen && self.fullscreen {
            self.window.unfullscreen();
            self.fullscreen = false;
        }
        // The window at the guest's own size is the **bordered** one ("a small window with
        // minimize button and close-button", Display: ), and the full-screen one has no
        // border and no title bar at all.
        self.window.set_decorated(!fullscreen);
        self.apply_chrome();
    }

    /// What the window manager is allowed to do with this window (see [`Self::set_fullscreen`]).
    ///
    /// Setting the functions is what removes the *maximize* button and the resize handles on a
    /// session that reads them: `set_resizable(false)` asks for the size to be fixed, and
    /// `set_functions` asks for the title bar's buttons.  Both are needed, and the second is what
    /// makes the first visible to a window manager that offers a maximize button regardless.
    fn apply_chrome(&self) {
        apply_chrome_to(&self.window, self.fullscreen);
    }

    pub fn is_fullscreen(&self) -> bool {
        self.fullscreen
    }

    /// Ask the window manager to focus the window (the `Show` half of `numlock + F9`).
    pub fn focus(&self) {
        self.window.present();
    }

    /// The window's **X id**, when the session is X11: what a dialog attaches itself to.
    pub fn x11_id(&self) -> Option<u64> {
        self.x11_id
    }

    /// The window's X id, read again (a window that was created unmapped has no GDK window yet,
    /// so the id is re-read the first time it is shown).
    pub fn refresh_x11_id(&mut self) {
        if self.x11_id.is_none() {
            self.x11_id = x11_window_id(&self.window);
        }
    }
}

impl Drop for Platform {
    fn drop(&mut self) {
        // GTK owns the window and the GLArea, and GDK owns the context: dropping the `glow`
        // loader releases nothing the driver has not already been told to release.
        self.gl = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The numbers a real window produced (mutter 42.9, a decorated `gtk::Window` with a
    /// `gtk::GLArea`): our own X window at absolute (120, 157) of 400x300, inside the frame the
    /// manager drew at (120, 120) of 400x337 — `_NET_FRAME_EXTENTS = 0, 0, 37, 0`.
    const WINDOW: (i32, i32, i32, i32) = (120, 157, 400, 300);
    const FRAME: (i32, i32, i32, i32) = (120, 120, 400, 337);

    /// **The display area is our own window**, and the position the guest gets is measured from its
    /// origin — the same numbers a `motion_notify_event` carries.
    #[test]
    fn a_pointer_in_the_window_is_the_guests_at_the_position_it_reports() {
        assert_eq!(
            place_pointer((320, 270), WINDOW, FRAME),
            PointerState {
                client: Some((200.0, 113.0)),
                over_our_chrome: false
            }
        );
        assert_eq!(
            place_pointer((120, 157), WINDOW, FRAME).client,
            Some((0.0, 0.0)),
            "the very corner of the display area"
        );
        assert_eq!(
            place_pointer((519, 456), WINDOW, FRAME).client,
            Some((399.0, 299.0)),
            "the last pixel that is still the guest's"
        );
    }

    /// **The title bar and the border are the window's**, not the guest's screen: they are inside the
    /// frame the manager drew and outside our own window.  A pointer there sends nothing to the guest,
    /// and it is the moment the keyboard grab is let go so the manager's own drag can happen.
    #[test]
    fn a_pointer_on_the_windows_own_bar_is_the_windows_not_the_guests() {
        // The bar mutter drew for us: 37 px above our own window's top edge, and nothing on the
        // other three sides (`_NET_FRAME_EXTENTS = 0, 0, 37, 0`).
        assert_eq!(
            place_pointer((320, 121), WINDOW, FRAME),
            PointerState {
                client: None,
                over_our_chrome: true
            },
            "the title bar"
        );
        assert!(
            place_pointer((120, 156), WINDOW, FRAME).over_our_chrome,
            "one pixel above the display area is still the bar"
        );
        assert!(
            place_pointer((120, 120), WINDOW, FRAME).over_our_chrome,
            "the frame's own corner"
        );
        // A manager that draws a border on every side: 10 px left and right, 37 above, 6 below.
        let bordered: (i32, i32, i32, i32) = (110, 120, 420, 343);
        for at in [(112, 300), (528, 300), (320, 458), (112, 122)] {
            assert!(
                place_pointer(at, WINDOW, bordered).over_our_chrome,
                "root {at:?} is the border"
            );
        }
    }

    /// A pointer over **another application** is neither: it is outside the frame, so it is not the
    /// window's chrome and nothing is sent to the guest.
    #[test]
    fn a_pointer_outside_the_frame_is_nobody_s() {
        for at in [(119, 300), (520, 300), (320, 119), (320, 457), (0, 0)] {
            assert_eq!(
                place_pointer(at, WINDOW, FRAME),
                PointerState::default(),
                "root {at:?} is outside the frame"
            );
        }
    }
}
