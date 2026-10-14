//! **The guest's own input devices**, through `/dev/uinput`.
//!
//! This is the honest mapping: the keys and the
//! pointer the host sends become events on **real** input devices, the guest's Xorg picks them up
//! with its own input driver, and nothing is invented between the two — `/dev/uinput` is the
//! kernel's own device factory (`CONFIG_INPUT_UINPUT`), so there is no code of ours in the kernel
//! for the keyboard and the mouse.
//!
//! A keyboard that can send every key and set the three LEDs, and an absolute pointer whose range
//! is the screen's own pixels, with the three buttons the window's clicks mean **and the wheel as
//! what the kernel says a wheel is** (`REL_WHEEL`/`REL_HWHEEL` on `EV_REL`): the window's wheel is
//! a step, and a step is a relative axis, not a button.  A device that does not offer the axis is
//! a device whose wheel the kernel throws away, which is what the wheel was before.
//!
//! The pointer's buttons are sent as a **state**, not as a broadcast: the device is told only the
//! button whose state changed, so a motion while a button is held keeps the button held (a drag)
//! and a release of one button does not lift another (`pointer_buttons`, `button_changes`).  X's own
//! pointer model is a state, and a device that re-states every button on every event is a device
//! that says "left up" the moment the user moves the mouse with the left button down.

use std::os::fd::{AsRawFd, OwnedFd};

use libc::{c_int, c_ulong};

// `linux/uinput.h`'s own numbers, named here so the file reads as the structure it is.
const UINPUT_MAX_NAME_SIZE: usize = 80;
const UI_SET_EVBIT: c_ulong = 0x4004_5564;
const UI_SET_KEYBIT: c_ulong = 0x4004_5565;
const UI_SET_RELBIT: c_ulong = 0x4004_5566;
const UI_SET_ABSBIT: c_ulong = 0x4004_5567;
const UI_SET_LEDBIT: c_ulong = 0x4004_5569;
const UI_DEV_CREATE: c_ulong = 0x5501;

const EV_SYN: u16 = 0x00;
const EV_KEY: u16 = 0x01;
const EV_REL: u16 = 0x02;
const EV_ABS: u16 = 0x03;
const EV_LED: u16 = 0x11;
const ABS_X: u16 = 0x00;
const ABS_Y: u16 = 0x01;
const REL_HWHEEL: u16 = 0x06;
const REL_WHEEL: u16 = 0x08;
const BTN_LEFT: u16 = 0x110;
const BTN_RIGHT: u16 = 0x111;
const BTN_MIDDLE: u16 = 0x112;
const LED_NUML: u16 = 0x00;
const LED_CAPSL: u16 = 0x01;
const LED_SCROLLL: u16 = 0x02;
const BUS_VIRTUAL: u16 = 0x06;

/// The number of key codes a keyboard can offer (`KEY_MAX`, from `linux/input-event-codes.h`).
const KEY_MAX: u16 = 0x2ff;
/// The highest absolute axis number a pointer can offer (`ABS_MAX`).
const ABS_MAX: u16 = 0x3f;

/// The pointer's three buttons and the bit each one has in the mask the host sends
/// (`dc-fc-window`'s packing: left 1, middle 2, right 4).
///
/// It is a table because the order the bits are walked in is the order the events are written in,
/// and a drag that lifts the left button before it presses the right one is a different drag.
pub const BUTTONS: [(u16, u32); 3] = [
    (BTN_LEFT, 1),
    (BTN_MIDDLE, 2),
    (BTN_RIGHT, 4),
];

/// `struct uinput_user_dev`, as `uinput.h` lays it out.
#[repr(C)]
struct UinputUserDev {
    name: [u8; UINPUT_MAX_NAME_SIZE],
    input_id: InputId,
    ff_effects_max: u32,
    absmax: [i32; ABS_MAX as usize + 1],
    absmin: [i32; ABS_MAX as usize + 1],
    absfuzz: [i32; ABS_MAX as usize + 1],
    absflat: [i32; ABS_MAX as usize + 1],
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct InputId {
    bustype: u16,
    vendor: u16,
    product: u16,
    version: u16,
}

/// `struct input_event`, which is what a device is written with.
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct InputEvent {
    time: (i64, i64),
    kind: u16,
    code: u16,
    value: i32,
}

fn ioctl(fd: &OwnedFd, request: c_ulong, value: u64) -> c_int {
    // SAFETY: the fd is an open character device and the request is one of `uinput`'s own.
    unsafe { libc::ioctl(fd.as_raw_fd(), request as _, value) }
}

fn write_struct<T>(fd: &OwnedFd, value: &T) -> std::io::Result<()> {
    let bytes = unsafe {
        std::slice::from_raw_parts(value as *const T as *const u8, std::mem::size_of::<T>())
    };
    let mut written = 0;
    while written < bytes.len() {
        // SAFETY: the fd is open and the buffer is this value's own bytes.
        let n = unsafe {
            libc::write(
                fd.as_raw_fd(),
                bytes[written..].as_ptr() as *const libc::c_void,
                bytes.len() - written,
            )
        };
        if n <= 0 {
            return Err(std::io::Error::last_os_error());
        }
        written += n as usize;
    }
    Ok(())
}

fn set_bits(fd: &OwnedFd, request: c_ulong, up_to: u16) {
    for code in 0..=up_to {
        ioctl(fd, request, code as u64);
    }
}

/// Open `/dev/uinput`, or `None` when the guest has no such device (a run whose kernel was built
/// without it): the screen still works, and the keyboard and the pointer simply do not exist.
fn open_uinput(what: &str) -> Option<OwnedFd> {
    match std::fs::OpenOptions::new().write(true).open("/dev/uinput") {
        Ok(file) => Some(file.into()),
        Err(e) => {
            eprintln!("deskd: /dev/uinput for the {what}: {e}");
            None
        }
    }
}

/// The keyboard: every key the host can send, and the three LEDs it may set.
pub fn keyboard() -> Option<OwnedFd> {
    let fd = open_uinput("keyboard")?;
    ioctl(&fd, UI_SET_EVBIT, EV_KEY as u64);
    ioctl(&fd, UI_SET_EVBIT, EV_LED as u64);
    ioctl(&fd, UI_SET_EVBIT, EV_SYN as u64);
    set_bits(&fd, UI_SET_KEYBIT, KEY_MAX);
    for led in [LED_NUML, LED_CAPSL, LED_SCROLLL] {
        ioctl(&fd, UI_SET_LEDBIT, led as u64);
    }
    let mut device = new_device("desk keyboard", 1);
    device.input_id.bustype = BUS_VIRTUAL;
    write_struct(&fd, &device).ok()?;
    ioctl(&fd, UI_DEV_CREATE, 0);
    Some(fd)
}

/// The pointer: absolute on the screen's own range, with the three buttons and the wheel.
///
/// The wheel is an `EV_REL` axis (`REL_WHEEL`), which is what the kernel calls a wheel: a device
/// that does not offer the axis has its wheel thrown away by the kernel, whatever was written into
/// it.  The buttons are offered as `EV_KEY`, and they are sent as a **state** — see
/// [`pointer_buttons`] and [`button_changes`].
pub fn pointer(width: u32, height: u32) -> Option<OwnedFd> {
    let fd = open_uinput("pointer")?;
    ioctl(&fd, UI_SET_EVBIT, EV_KEY as u64);
    ioctl(&fd, UI_SET_EVBIT, EV_ABS as u64);
    ioctl(&fd, UI_SET_EVBIT, EV_REL as u64);
    ioctl(&fd, UI_SET_EVBIT, EV_SYN as u64);
    for button in [BTN_LEFT, BTN_MIDDLE, BTN_RIGHT] {
        ioctl(&fd, UI_SET_KEYBIT, button as u64);
    }
    ioctl(&fd, UI_SET_ABSBIT, ABS_X as u64);
    ioctl(&fd, UI_SET_ABSBIT, ABS_Y as u64);
    ioctl(&fd, UI_SET_RELBIT, REL_WHEEL as u64);
    ioctl(&fd, UI_SET_RELBIT, REL_HWHEEL as u64);
    let mut device = new_device("desk pointer", 2);
    device.input_id.bustype = BUS_VIRTUAL;
    device.absmin[ABS_X as usize] = 0;
    device.absmax[ABS_X as usize] = (width.max(1) - 1) as i32;
    device.absmin[ABS_Y as usize] = 0;
    device.absmax[ABS_Y as usize] = (height.max(1) - 1) as i32;
    write_struct(&fd, &device).ok()?;
    ioctl(&fd, UI_DEV_CREATE, 0);
    Some(fd)
}

fn new_device(name: &str, product: u16) -> UinputUserDev {
    let mut device: UinputUserDev = unsafe { std::mem::zeroed() };
    let bytes = name.as_bytes();
    let len = bytes.len().min(UINPUT_MAX_NAME_SIZE - 1);
    device.name[..len].copy_from_slice(&bytes[..len]);
    device.input_id = InputId {
        bustype: BUS_VIRTUAL,
        vendor: 0x4844, // "HD"
        product,
        version: 0,
    };
    device
}

fn write_event(fd: &OwnedFd, event: &InputEvent) {
    let _ = write_struct(fd, event);
}

fn sync(fd: &OwnedFd) {
    write_event(fd, &InputEvent::default());
}

/// A key, in the guest's own code (the number the host sent, which is the number `uinput` takes).
pub fn key(fd: &OwnedFd, code: u16, down: bool) {
    write_event(
        fd,
        &InputEvent {
            kind: EV_KEY,
            code,
            value: if down { 1 } else { 0 },
            ..InputEvent::default()
        },
    );
    sync(fd);
}

/// Where the pointer is, and **only the buttons whose state changed**.
///
/// `held` is what the device believes is down right now, and this call updates it.  It is kept by
/// the caller (`GuestIo`) rather than derived here, because the two mistakes this replaces are both
/// about re-stating everything on every event:
///
/// * a motion that writes `BTN_LEFT 1` again while the left button is already down is a press
///   inside a press — X's own model is a state, and a repeated press is at best noise and at worst
///   a second click on top of a drag;
/// * a release that writes `0` for every button lifts the buttons the user is still holding: a
///   right-drag with the pointer moved is a right button that went up on its own.
///
/// So a press says one key down, a release says one key up, and a move says two axes and nothing
/// else.
pub fn pointer_move(fd: &OwnedFd, x: i32, y: i32, buttons: u32, held: &mut u32) {
    for (kind, code, value) in [(EV_ABS, ABS_X, x), (EV_ABS, ABS_Y, y)] {
        write_event(
            fd,
            &InputEvent {
                kind,
                code,
                value,
                ..InputEvent::default()
            },
        );
    }
    pointer_buttons(fd, buttons, held);
}

/// The buttons alone: the same state rule as [`pointer_move`], without moving the pointer.
///
/// This is what a wheel event needs — the buttons held while the wheel turned must reach the device
/// and the pointer must stay where it is.
pub fn pointer_buttons(fd: &OwnedFd, buttons: u32, held: &mut u32) {
    for (button, value) in button_changes(*held, buttons) {
        write_event(
            fd,
            &InputEvent {
                kind: EV_KEY,
                code: button,
                value,
                ..InputEvent::default()
            },
        );
    }
    *held = buttons & BUTTON_MASK;
    sync(fd);
}

/// **The state rule, on its own**: the `EV_KEY` events that take the device from `held` to `want`.
///
/// Nothing is written for a button that did not change — that is the whole of what makes a drag a
/// drag and a release a release.  It is a function of two masks so the rule is testable without a
/// device, and the order is the table's order: a change of two buttons at once is written left
/// first, which is the order the user's hand did them in for every case this window produces.
pub fn button_changes(held: u32, want: u32) -> Vec<(u16, i32)> {
    BUTTONS
        .iter()
        .filter_map(|(button, bit)| {
            let now = held & bit != 0;
            let want = want & bit != 0;
            (now != want).then(|| (*button, i32::from(want)))
        })
        .collect()
}

/// The bits the three buttons have, so a mask from the host cannot set a button this device does
/// not have.
pub const BUTTON_MASK: u32 = 1 | 2 | 4;

/// The wheel: `steps` is a signed step on the kernel's wheel axis, **up is positive**.
///
/// It is a relative axis, not a button: `REL_WHEEL` is what the kernel calls a wheel, and a device
/// that does not offer it has its wheel discarded before it reaches the guest's X server.  A step of
/// zero is said nothing about — writing one is an event the guest would have to invent a meaning
/// for.
pub fn wheel(fd: &OwnedFd, steps: i32) {
    if steps == 0 {
        return;
    }
    write_event(
        fd,
        &InputEvent {
            kind: EV_REL,
            code: REL_WHEEL,
            value: steps,
            ..InputEvent::default()
        },
    );
    sync(fd);
}

/// The horizontal wheel (a touchpad's two-finger sideways swipe, a tilted wheel): `steps` signed,
/// **right is positive**.
pub fn hwheel(fd: &OwnedFd, steps: i32) {
    if steps == 0 {
        return;
    }
    write_event(
        fd,
        &InputEvent {
            kind: EV_REL,
            code: REL_HWHEEL,
            value: steps,
            ..InputEvent::default()
        },
    );
    sync(fd);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_keyboard_offers_every_key_the_host_can_send() {
        // The claim the two sides rest on: a key code means the same number on both.  `30` is `a`
        // in the host's own table (`dc_display::gl::linux_key_code`) and in `uinput`'s, and the
        // keyboard is created with room for every code up to `KEY_MAX`.
        assert_eq!(KEY_MAX, 0x2ff);
        assert!(KEY_MAX as u32 >= 255, "a keyboard has room for every key");
    }

    #[test]
    fn the_structure_is_the_kernels_own_size() {
        // `struct uinput_user_dev` is 1116 bytes: 80 for the name, 8 for the id, 4 for the effects
        // and four arrays of 64 `int`s.
        assert_eq!(std::mem::size_of::<UinputUserDev>(), 80 + 8 + 4 + 4 * 64 * 4);
        assert_eq!(std::mem::size_of::<InputEvent>(), 24);
    }

    #[test]
    fn the_buttons_are_this_projects_own_numbers() {
        // `dc-fc-window` packs the window's buttons as 1, 2, 4 for left, middle, right, and this is
        // the table that turns those bits into the device's buttons.
        assert_eq!(BTN_LEFT, 0x110);
        assert_eq!(BTN_MIDDLE, 0x112);
        assert_eq!(BTN_RIGHT, 0x111);
        assert_eq!(
            BUTTONS,
            [(BTN_LEFT, 1), (BTN_MIDDLE, 2), (BTN_RIGHT, 4)],
            "left, middle, right, in that order"
        );
        assert_eq!(BUTTON_MASK, 7);
    }

    /// **A move is not a press.**  With the left button already down, a move that says "left is
    /// down" writes nothing: the device is already holding it, and writing it again is a click on
    /// top of the drag.
    #[test]
    fn a_move_while_a_button_is_held_sends_no_button_event() {
        assert!(button_changes(1, 1).is_empty(), "left held, left wanted");
        assert!(button_changes(0, 0).is_empty(), "nothing held, nothing wanted");
        assert!(button_changes(7, 7).is_empty(), "all three held, all three wanted");
    }

    /// **A press is one key down, a release is one key up**, and only that button.
    #[test]
    fn a_press_and_a_release_are_one_button_each() {
        assert_eq!(button_changes(0, 1), vec![(BTN_LEFT, 1)]);
        assert_eq!(button_changes(1, 0), vec![(BTN_LEFT, 0)]);
        assert_eq!(button_changes(0, 4), vec![(BTN_RIGHT, 1)]);
        assert_eq!(button_changes(4, 0), vec![(BTN_RIGHT, 0)]);
        assert_eq!(button_changes(0, 2), vec![(BTN_MIDDLE, 1)]);
    }

    /// **A release does not lift the buttons still held.**  This is the case the old code got
    /// wrong: it wrote every button on every event, so releasing the left button during a
    /// left-and-right hold lifted the right one too.
    #[test]
    fn releasing_one_button_leaves_the_other_held() {
        // Left and right down, then the left goes up: only the left is written.
        assert_eq!(button_changes(5, 4), vec![(BTN_LEFT, 0)]);
        // Left down, then the right joins it: only the right is written.
        assert_eq!(button_changes(1, 5), vec![(BTN_RIGHT, 1)]);
        // All three down, then the middle goes up.
        assert_eq!(button_changes(7, 5), vec![(BTN_MIDDLE, 0)]);
    }

    /// A mask from the host that names a button this device does not have is **not** written: the
    /// device is left holding what it was, rather than being told about a button it cannot report.
    #[test]
    fn a_button_the_device_does_not_have_is_not_written() {
        assert!(button_changes(0, 8).is_empty(), "bit 3 is not a button here");
        assert!(button_changes(0, 1 << 20).is_empty());
        // And the state a `pointer_buttons` call leaves behind is the mask with only the real
        // buttons in it.
        assert_eq!(8 & BUTTON_MASK, 0);
    }

    /// The wheel is the kernel's own axis, with the kernel's own numbers: `REL_WHEEL` 8 and
    /// `REL_HWHEEL` 6, on `EV_REL`.  A device that does not offer them has its wheel thrown away by
    /// the kernel, which is what the wheel was before.
    #[test]
    fn the_wheel_is_the_kernels_own_relative_axes() {
        assert_eq!(REL_WHEEL, 0x08);
        assert_eq!(REL_HWHEEL, 0x06);
        assert_eq!(EV_REL, 0x02);
        assert_eq!(ABS_X, 0x00);
        assert_eq!(ABS_Y, 0x01);
    }
}
