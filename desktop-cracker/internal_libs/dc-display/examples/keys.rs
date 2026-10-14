//! Print what the host's keyboard says, ten times a second — the reader, on its own.
//!
//! It is the tool for the question "is the key really down?": the window watches the same
//! `QueryKeymap`, and a difference between this and a real key press is a difference in the
//! *session* (a synthetic key, a nested server), not in the rule.
//!
//!     cargo run --example keys -p dc-display
//!
//! Hold a key while it runs.
fn main() {
    let Some(reader) = dc_display::xinput::KeyReader::connect() else {
        eprintln!("no display to ask (is DISPLAY set?)");
        std::process::exit(1);
    };
    for _ in 0..120 {
        if let Some(keys) = reader.keys() {
            println!(
                "numlock={} f9={} f10={} hotkey={:?}",
                keys.numlock,
                keys.f9,
                keys.f10,
                keys.hotkey()
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}
