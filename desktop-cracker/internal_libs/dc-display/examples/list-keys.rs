//! Print the key numbering this project sends: one line per key, `keycode <TAB> kernel code <TAB>
//! keysym`.
//!
//! The window forwards a key as the **kernel's key code** (`dc_display::keymap`), which is the
//! number the guest's `uinput` keyboard takes.  This tool prints what a *particular* X server says,
//! so a check against a running guest compares the guest's own `/dev/input/event*` report with the
//! server's answer rather than with a copy of it written down somewhere else.
//!
//!     cargo run --example list-keys -p dc-display

use dc_display::xinput::KeyReader;

fn main() {
    let Some(reader) = KeyReader::connect() else {
        eprintln!("no display to ask (is DISPLAY set?)");
        std::process::exit(1);
    };
    let codes = reader.key_codes();
    println!("# X's keycode\tkernel key code\tkeysym (the check that was read)");
    for keycode in codes.keycodes() {
        let code = codes
            .code(keycode)
            .map(|code| code.to_string())
            .unwrap_or_else(|| "-".into());
        let symbol = codes
            .keysym_of(keycode)
            .map(|symbol| format!("{symbol:#06x}"))
            .unwrap_or_else(|| "-".into());
        println!("{keycode}\t{code}\t{symbol}");
    }
    let vetoed = codes.vetoed();
    if !vetoed.is_empty() {
        println!("# keys the server's mapping disagrees about (not forwarded): {vetoed:?}");
    }
}
