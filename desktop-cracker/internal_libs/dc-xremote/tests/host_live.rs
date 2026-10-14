//! A live check against whatever display this machine has: it is a test of the
//! *host* more than of the code, so it skips itself when there is no display.

use std::path::Path;

#[test]
fn the_hosts_own_display_is_found_and_its_cookie_extracted() {
    let socket_dir = Path::new("/tmp/.X11-unix");
    let display = match dc_xremote::detect(socket_dir) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("skipping: {e}");
            return;
        }
    };
    println!(
        "host display: {} ({})",
        display.display,
        display.socket.display()
    );

    // The authority file is $XAUTHORITY when it is set (a display manager keeps
    // it under /run/user, and that file is the one with the cookie).
    let source = dc_xremote::authority_path();
    if !source.exists() {
        eprintln!(
            "skipping the cookie half: {} does not exist",
            source.display()
        );
        return;
    }
    // The host's own cookie is what we are after; if this display has none, the
    // server does not want one and there is nothing to extract.
    assert!(
        dc_xremote::has_cookie(&source, display.number),
        "{} has no cookie for {}",
        source.display(),
        display.display
    );

    let dir = tempfile::tempdir().unwrap();
    let guest_file = display.extract_authority(&source, dir.path()).unwrap();
    assert_eq!(guest_file, dir.path().join(dc_xremote::AUTHORITY_FILE));
    // the extracted file is a valid authority file for that display
    assert!(dc_xremote::has_cookie(&guest_file, display.number));

    // and xauth agrees — the strongest check available on the host
    match dc_xremote::xauth_list(&display.display, &guest_file) {
        Ok(text) => assert!(
            text.contains(dc_xremote::MIT_COOKIE),
            "xauth listed no cookie: {text:?}"
        ),
        Err(e) => panic!("xauth refused the file we wrote: {e}"),
    }

    let env = display.guest_environment("/run/desktop-cracker/Xauthority");
    assert!(env.contains(&format!("DISPLAY={}", display.display)));
}
