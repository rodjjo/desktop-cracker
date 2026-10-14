//! **The host's wheel, turned into the guest's wheel steps.**
//!
//! The design ("Display") says the window forwards the pointer's buttons; the wheel is the one of
//! them that is not a button, and it is the one the host's toolkit reports in two ways at once.
//! Measured on this host (GNOME/mutter 42.9 on Xorg, libinput, GTK 3.24) with a scratch probe that
//! injects a notch through a **real kernel device** (`/dev/uinput` → libinput → X → GDK), which is
//! the path a real mouse takes:
//!
//! * **one notch arrives as two scroll events**, both carrying the *same* X server timestamp:
//!   a `Smooth` one with a delta, and a discrete one (`Up`/`Down`/`Left`/`Right`) with no delta.
//!   A notch injected as `REL_WHEEL_HI_RES` alone (what a modern wheel sends) arrives the same way —
//!   libinput adds the discrete half when the high-resolution units add up to a notch.
//! * **the `Smooth` half's vertical sign is the content's, not the wheel's**: a notch **up** arrives
//!   as `delta.1 = -1` while its discrete half is `Up`.  Read as a wheel step it is the *opposite*
//!   step.  That is the operator's report of 2026-10-12 — "when I scroll, sometimes it add 1 and
//!   remove 1 right after, so it cancel the scroll movement or cause it to behave strange": the
//!   window was sending `REL_WHEEL -1` and `REL_WHEEL +1` for one notch.  (It had not been seen
//!   before because the earlier probe injected the wheel with `xdotool click 4/5`, which is XTEST:
//!   a synthetic button on the master pointer, and that produces **only** the discrete half.)
//! * the horizontal axis already agrees with the wheel: a notch right is `delta.0 = +1`.
//! * a **fraction** of a notch arrives as several `Smooth` events whose deltas add up to one, plus
//!   one discrete half (`30 + 30 + 30 + 30` units → `-0.5, -0.25, -0.25` and an `Up`).
//! * several notches injected back to back can share **one** timestamp, so a timestamp is a way to
//!   recognise the two halves of a notch and not a way to count notches.
//!
//! So the rule is: **the wheel is counted once per notch**.  A `Smooth` event contributes its
//! (wheel-direction) delta to a carried fraction, and only whole notches are forwarded; a discrete
//! event is a whole notch **unless** a `Smooth` event of the same server timestamp was already
//! counted, in which case it is the other half of that same notch.  A fraction that never reaches a
//! notch is carried, not rounded up into a notch the user never made.

use gtk::gdk;

/// How far a carried fraction may sit from a whole notch before it is treated as one.  The units a
/// high-resolution wheel sends are `1/120` of a notch, and a sum of them is not exactly `1.0`.
const WHOLE_NOTCH: f64 = 0.01;

/// What this window has been told about the wheel since the last notch it forwarded.
///
/// It is state because a notch is a *thing the user did*, and the host reports one as two events;
/// the alternative — answering each event on its own — is what produced the cancelling pair.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct Wheel {
    /// The part of a notch that has been seen but not worth a step yet, in notches (`up` and
    /// `right` are positive).
    carried: (f64, f64),
    /// The last event's server timestamp and **which half of a notch it was**: a discrete event with
    /// the timestamp of a `Smooth` one already counted is the same notch told a second way, and the
    /// other way round.
    last: Option<(u32, Half)>,
}

/// Which of the two ways the host reports a notch an event was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Half {
    Smooth,
    Discrete,
}

impl Wheel {
    /// The carried fraction, for a test or a reader that wants to know what is still owed.
    pub fn carried(&self) -> (f64, f64) {
        self.carried
    }

    /// Forget what was carried: the window lost the pointer, the run is ending, a new guest started.
    pub fn forget(&mut self) {
        self.carried = (0.0, 0.0);
        self.last = None;
    }
}

/// **One scroll event as the guest's wheel steps**: vertical first (`up` is positive), horizontal
/// second (`right` is positive).  Zero on both means this event is not a notch of its own.
///
/// `time` is the event's X server timestamp (`gdk::EventScroll::time`), which is how the two halves
/// of one notch are recognised.
pub fn steps(
    wheel: &mut Wheel,
    direction: gdk::ScrollDirection,
    delta: (f64, f64),
    time: u32,
) -> (i32, i32) {
    match direction {
        gdk::ScrollDirection::Up => discrete(wheel, (1, 0), time),
        gdk::ScrollDirection::Down => discrete(wheel, (-1, 0), time),
        gdk::ScrollDirection::Right => discrete(wheel, (0, 1), time),
        gdk::ScrollDirection::Left => discrete(wheel, (0, -1), time),
        gdk::ScrollDirection::Smooth => smooth(wheel, delta, time),
        // A direction this build's GDK does not name is not a wheel this project can name.
        gdk::ScrollDirection::__Unknown(_) => (0, 0),
        #[allow(unreachable_patterns)]
        _ => (0, 0),
    }
}

/// The discrete half: a whole notch, unless its `Smooth` half was already counted.
fn discrete(wheel: &mut Wheel, notch: (i32, i32), time: u32) -> (i32, i32) {
    if wheel.last == Some((time, Half::Smooth)) {
        return (0, 0);
    }
    wheel.last = Some((time, Half::Discrete));
    notch
}

/// The `Smooth` half: a delta, in the **content's** direction, which for the vertical axis is the
/// opposite of the wheel's (measured: a notch up is `delta.1 = -1`).  The horizontal axis agrees
/// with the wheel already.
///
/// Its server timestamp is recorded, because that is what a discrete event with the same one is
/// recognised as: the same notch, told a second way.
///
/// **A `Smooth` event that carries nothing claims nothing.**  Measured on the first notch of a
/// session: `Smooth delta=(0,0)` arrives before the `Up` of the same notch.  A rule that let it
/// stand for the notch would drop the `Up` and the notch would never reach the guest (measured
/// live: three notches up arriving as two `REL_WHEEL` steps).
fn smooth(wheel: &mut Wheel, delta: (f64, f64), time: u32) -> (i32, i32) {
    if wheel.last == Some((time, Half::Discrete)) {
        wheel.last = Some((time, Half::Smooth));
        return (0, 0);
    }
    if delta.0 == 0.0 && delta.1 == 0.0 {
        return (0, 0);
    }
    wheel.last = Some((time, Half::Smooth));
    wheel.carried.0 -= delta.1;
    wheel.carried.1 += delta.0;
    let whole = (whole(wheel.carried.0), whole(wheel.carried.1));
    wheel.carried.0 -= whole.0 as f64;
    wheel.carried.1 -= whole.1 as f64;
    whole
}

/// The whole notches a carried fraction is worth: everything but the residue, with the tolerance a
/// sum of `1/120`-unit fractions needs.
fn whole(carried: f64) -> i32 {
    if carried >= 0.0 {
        (carried + WHOLE_NOTCH).floor() as i32
    } else {
        (carried - WHOLE_NOTCH).ceil() as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The measurement this whole file exists for: **one notch is one step**, even though the host
    /// reports it as a `Smooth` event and a discrete one with the same timestamp.
    #[test]
    fn one_notch_up_is_one_step_and_not_a_step_and_its_opposite() {
        let mut wheel = Wheel::default();
        // Measured: `Smooth delta=(0.00, -1.00)` then `Up`, both at the same server timestamp.
        assert_eq!(
            steps(&mut wheel, gdk::ScrollDirection::Smooth, (0.0, -1.0), 100),
            (1, 0),
            "the smooth half of a notch up is a step up, not a step down"
        );
        assert_eq!(
            steps(&mut wheel, gdk::ScrollDirection::Up, (0.0, 0.0), 100),
            (0, 0),
            "the discrete half of the same notch must not be a second step"
        );
        assert_eq!(wheel.carried(), (0.0, 0.0));
    }

    /// The same, for a notch down: the pair used to be `+1` then `-1`, which is the report.
    #[test]
    fn one_notch_down_is_one_step_down() {
        let mut wheel = Wheel::default();
        assert_eq!(
            steps(&mut wheel, gdk::ScrollDirection::Smooth, (0.0, 1.0), 200),
            (-1, 0)
        );
        assert_eq!(
            steps(&mut wheel, gdk::ScrollDirection::Down, (0.0, 0.0), 200),
            (0, 0)
        );
    }

    /// The two halves can arrive the other way round, and the `Smooth` one can carry **nothing**
    /// (measured on the first notch of a session: `Smooth delta=(0,0)` then `Up` at the same
    /// timestamp).  An event that carries nothing is not the notch; the `Up` is.
    #[test]
    fn a_smooth_event_with_no_delta_is_not_the_notch() {
        let mut wheel = Wheel::default();
        assert_eq!(
            steps(&mut wheel, gdk::ScrollDirection::Smooth, (0.0, 0.0), 150),
            (0, 0)
        );
        assert_eq!(
            steps(&mut wheel, gdk::ScrollDirection::Up, (0.0, 0.0), 150),
            (1, 0)
        );
        assert_eq!(wheel.carried(), (0.0, 0.0));
    }

    /// The two halves in the other order — the discrete one first, a `Smooth` one carrying the
    /// notch after it — are still one notch.
    #[test]
    fn the_two_halves_in_the_other_order_are_still_one_notch() {
        let mut wheel = Wheel::default();
        assert_eq!(
            steps(&mut wheel, gdk::ScrollDirection::Up, (0.0, 0.0), 150),
            (1, 0)
        );
        assert_eq!(
            steps(&mut wheel, gdk::ScrollDirection::Smooth, (0.0, -1.0), 150),
            (0, 0)
        );
        assert_eq!(wheel.carried(), (0.0, 0.0));
    }

    /// A discrete event on its own — `xdotool click 4`, a synthetic button, no smooth half at all —
    /// is still a notch.
    #[test]
    fn a_discrete_notch_with_no_smooth_half_is_a_step() {
        let mut wheel = Wheel::default();
        assert_eq!(
            steps(&mut wheel, gdk::ScrollDirection::Up, (0.0, 0.0), 300),
            (1, 0)
        );
        assert_eq!(
            steps(&mut wheel, gdk::ScrollDirection::Down, (0.0, 0.0), 301),
            (-1, 0)
        );
        assert_eq!(
            steps(&mut wheel, gdk::ScrollDirection::Right, (0.0, 0.0), 302),
            (0, 1)
        );
        assert_eq!(
            steps(&mut wheel, gdk::ScrollDirection::Left, (0.0, 0.0), 303),
            (0, -1)
        );
    }

    /// Measured: five notches injected back to back share **one** timestamp.  The smooth half of
    /// each is a notch, and every discrete half is dropped — five notches, five steps.
    #[test]
    fn five_fast_notches_sharing_one_timestamp_are_five_steps() {
        let mut wheel = Wheel::default();
        let mut total = 0;
        for _ in 0..5 {
            total += steps(&mut wheel, gdk::ScrollDirection::Smooth, (0.0, -1.0), 400).0;
            total += steps(&mut wheel, gdk::ScrollDirection::Up, (0.0, 0.0), 400).0;
        }
        assert_eq!(
            total, 5,
            "five notches must not become five doubled or five cancelled"
        );
    }

    /// A fraction of a notch is carried until it is a notch: measured, `30 + 30 + 30 + 30` high-res
    /// units arrive as `-0.5, -0.25, -0.25` and one `Up`, and that is **one** step.
    #[test]
    fn a_fraction_is_carried_until_it_is_a_whole_notch() {
        let mut wheel = Wheel::default();
        assert_eq!(
            steps(&mut wheel, gdk::ScrollDirection::Smooth, (0.0, -0.5), 500),
            (0, 0)
        );
        assert_eq!(
            steps(&mut wheel, gdk::ScrollDirection::Smooth, (0.0, -0.25), 500),
            (0, 0)
        );
        assert_eq!(
            steps(&mut wheel, gdk::ScrollDirection::Smooth, (0.0, -0.25), 500),
            (1, 0)
        );
        assert_eq!(
            steps(&mut wheel, gdk::ScrollDirection::Up, (0.0, 0.0), 500),
            (0, 0)
        );
        assert_eq!(wheel.carried().0.abs(), 0.0);
    }

    /// A wheel that turns back before the notch is complete scrolls nothing.
    #[test]
    fn half_a_notch_up_then_half_a_notch_down_is_nothing() {
        let mut wheel = Wheel::default();
        assert_eq!(
            steps(&mut wheel, gdk::ScrollDirection::Smooth, (0.0, -0.5), 600),
            (0, 0)
        );
        assert_eq!(
            steps(&mut wheel, gdk::ScrollDirection::Smooth, (0.0, 0.5), 601),
            (0, 0)
        );
        assert_eq!(wheel.carried(), (0.0, 0.0));
    }

    /// The horizontal axis already agrees with the wheel (measured: a notch right is `+1`), so it is
    /// not flipped the way the vertical one is.
    #[test]
    fn the_horizontal_axis_keeps_its_own_sign() {
        let mut wheel = Wheel::default();
        assert_eq!(
            steps(&mut wheel, gdk::ScrollDirection::Smooth, (1.0, 0.0), 700),
            (0, 1)
        );
        assert_eq!(
            steps(&mut wheel, gdk::ScrollDirection::Smooth, (-1.0, 0.0), 701),
            (0, -1)
        );
    }

    /// A sum of `1/120`-unit fractions is not exactly `1.0`; the whole 120 of them are one notch.
    #[test]
    fn a_hundred_and_twenty_high_resolution_units_are_one_notch() {
        let mut wheel = Wheel::default();
        let unit = 1.0 / 120.0;
        let mut total = 0;
        for _ in 0..120 {
            total += steps(&mut wheel, gdk::ScrollDirection::Smooth, (0.0, -unit), 800).0;
        }
        assert_eq!(total, 1);
        assert!(wheel.carried().0.abs() < WHOLE_NOTCH);
    }

    /// `forget` is what the window calls when the pointer or the guest is gone: nothing is owed.
    #[test]
    fn forgetting_the_wheel_owes_nothing() {
        let mut wheel = Wheel::default();
        steps(&mut wheel, gdk::ScrollDirection::Smooth, (0.0, -0.5), 900);
        assert_ne!(wheel.carried().0, 0.0);
        wheel.forget();
        assert_eq!(wheel.carried(), (0.0, 0.0));
    }
}
