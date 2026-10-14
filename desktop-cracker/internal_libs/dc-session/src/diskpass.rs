//! The disk passphrase: asked for when the disk is opened, kept only in memory.
//!
//! The design is specific about this, and it is a *security* statement
//! rather than a convenience:
//!
//! > When we mount the disk, a password is asked for the user using a gui
//! > interface and the password is not stored at any place, kept only in memory
//! > in a secure way.
//!
//! and, separately, the disk's password is *not* the display unlock password:
//! they are two unrelated secrets, the second one is a salted hash in the
//! settings file and this one never leaves RAM.
//!
//! So this module owns four rules:
//!
//! 1. it is asked for **once**, on the UI thread and over the window (a dialog with no timeout: a
//!    person types at their own pace) — the plugin's client answers first when one is attached,
//!    which is how a test answers it exactly as a person would;
//! 2. it lives in a `Zeroizing` buffer, so it is overwritten when it is dropped: no copy is left
//!    in the process's heap;
//! 3. it is never written to a file, never put in an environment variable and never printed — the
//!    only place it goes is the run's **control share**, and the guest's own initramfs removes
//!    that file the moment it has opened the container with it;
//! 4. `Debug` hides it, so an accidental `{:?}` of this type cannot leak it into a log.

use std::io::Read;

use crate::prompt;

/// A passphrase that exists only while it is needed.
#[derive(Clone, PartialEq, Eq)]
pub struct DiskPassphrase(Option<zeroize::Zeroizing<Vec<u8>>>);
impl std::fmt::Debug for DiskPassphrase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(_) => f.write_str("DiskPassphrase(<set, hidden>)"),
            None => f.write_str("DiskPassphrase(<none>)"),
        }
    }
}
impl DiskPassphrase {
    pub fn none() -> DiskPassphrase {
        DiskPassphrase(None)
    }
    /// From something the user typed.
    pub fn new(secret: impl Into<Vec<u8>>) -> DiskPassphrase {
        let mut v = secret.into();
        // Trailing newline from a pipe/`read` is not part of the secret.
        while v.last() == Some(&b'\n') || v.last() == Some(&b'\r') {
            v.pop();
        }
        if v.is_empty() {
            DiskPassphrase(None)
        } else {
            DiskPassphrase(Some(zeroize::Zeroizing::new(v)))
        }
    }
    pub fn is_set(&self) -> bool {
        self.0.is_some()
    }
    /// The bytes, for the one place that needs them (handing them to the guest).
    pub fn expose(&self) -> Option<&[u8]> {
        self.0.as_ref().map(|z| z.as_slice())
    }
    /// Ask the user for the passphrase, as a desktop would in its window.
    pub fn ask(prompt_text: &str) -> anyhow::Result<DiskPassphrase> {
        Ok(match prompt::ask_password(prompt_text)? {
            Some(s) => DiskPassphrase::new(s),
            None => DiskPassphrase::none(),
        })
    }
    /// Read it from stdin: the headless/automation path, marked as such so it
    /// cannot be confused with an interactive ask.
    pub fn from_stdin() -> anyhow::Result<DiskPassphrase> {
        let mut buf = Vec::new();
        std::io::stdin()
            .take(4096)
            .read_to_end(&mut buf)
            .map(|_| ())
            .map_err(|e| anyhow::anyhow!("reading the disk passphrase from stdin: {e}"))?;
        Ok(DiskPassphrase::new(buf))
    }
}
/// Ask the user for the root disk's passphrase, with only the disk to name in the question.
///
/// It is the shape the **Firecracker** application uses: the question is the same one, and the
/// manager the other shape reports through is this project's own bookkeeping.
pub fn ask_about(disk: &std::path::Path) -> anyhow::Result<DiskPassphrase> {
    ask_over(disk, None)
}
/// The same question, asked **over a window** the caller owns.
///
/// `parent` is the window the dialog is transient for, so the question appears over the guest's
/// screen rather than behind it — which is the reason the application opens the window **before**
/// it asks anything, and the reason this takes an owner at all.
pub fn ask_over(
    disk: &std::path::Path,
    parent: Option<&dc_dialog::Parent>,
) -> anyhow::Result<DiskPassphrase> {
    let answer = match dc_dialog::password_question(dc_dialog::Question::new(
        dc_dialog::Kind::DiskPassword,
        "Root disk password:",
        &format!("The disk {} is encrypted.", disk.display()),
    )) {
        Some(answer) => Some(answer),
        None => dc_dialog::password_with_parent(parent, dc_common::APP_NAME, "Root disk password:"),
    };
    let Some(answer) = answer else {
        anyhow::bail!("the root disk's password was not given");
    };
    if answer.is_empty() {
        anyhow::bail!("the root disk's password was not given");
    }
    Ok(DiskPassphrase::new(answer))
}
/// **Ask the user for the passphrase a *new* disk is made with**, twice, over the application's own
/// window — and this is the only way a disk in this project is ever created.
///
/// It is a **question, not a setting**: the answer is used to build the LUKS container and is
/// dropped straight away (`Zeroizing`: overwritten when it is dropped, never written to any file,
/// never an environment variable, never a command line — Environment variables: ). Nothing
/// about it goes anywhere near the settings file, and there is no field for it in the settings
/// window: that window selects a disk, it does not hold its key.
///
/// It is asked **twice** for the same reason `--set-password` asks twice: the passphrase a disk is
/// created with is the only thing that will ever open it, and a typo in a hidden field is a disk
/// nobody can open.
///
/// The **plugin answers first** when a client is attached (a test answers exactly as a person does);
/// with no client it is the dialog, which has no timeout.
pub fn ask_new_disk_passphrase(
    disk: &std::path::Path,
    parent: Option<&dc_dialog::Parent>,
) -> anyhow::Result<DiskPassphrase> {
    let question = |title: &str, text: String| match dc_dialog::password_question(
        dc_dialog::Question::new(dc_dialog::Kind::DiskPassword, title, &text),
    ) {
        Some(answer) => Some(answer),
        None => dc_dialog::password_with_parent(parent, dc_common::APP_NAME, title),
    };
    let first = question(
        "Passphrase for the new disk:",
        format!(
            "The disk {} does not exist yet: it is made now, and this passphrase is what opens it.\n\
             It is not written anywhere — lose it and the disk cannot be opened again.",
            disk.display()
        ),
    )
    .filter(|answer| !answer.is_empty())
    .ok_or_else(|| anyhow::anyhow!("the new disk's passphrase was not given"))?;
    let again = question(
        "Again, to be sure:",
        "Type the same passphrase once more.".into(),
    )
    .filter(|answer| !answer.is_empty())
    .ok_or_else(|| anyhow::anyhow!("the new disk's passphrase was not given"))?;
    if first != again {
        anyhow::bail!("the two passphrases differ; no disk was made");
    }
    // The length is the most that is ever said about a passphrase (see `ask` above).
    let passphrase = DiskPassphrase::new(first);
    dc_common::milestone!(
        "the new disk will be made with a {}-byte passphrase; it is not kept anywhere",
        passphrase.expose().map(|b| b.len()).unwrap_or(0)
    );
    Ok(passphrase)
}

/// Ask the user for the root disk's passphrase.
///
/// The shape of the question is the project's rule: a **dialog**, no timeout, kept only in
/// memory.  **The guest is what opens the disk**, and this answer is what it opens it with, so:
///
/// * the passphrase goes to the guest's own initramfs through the run's **control share**, and
///   the guest removes that file the moment it has opened the container with it
///   (`DESK-ROOT a password was provided for this start (the share's copy is removed now)`);
/// * a wrong password is the guest's own sentence (`DESK-ROOT wrong-password the password did not
///   open the container`) a second or two into the boot, and the run ends with it;
/// * there is no retry and no fallback: the application finishes, and the user starts it again
///   and types the right one.
///
/// It is called **on the UI thread** — the thread running the GTK main loop — because that is
/// where a GTK dialog belongs; a question asked anywhere else is a window nothing will take
/// away.  The header check is done by the caller, which reads it before this point (and is what
/// tells "a wrong password" from "no password will ever open this disk").
///
/// This function is therefore only the question; the *proof* is the run itself (see `run.rs`,
/// where a hypervisor that refuses the disk ends the application).
pub fn ask(
    disk: &std::path::Path,
    app: &dc_common::manager::Manager,
    parent: Option<&dc_dialog::Parent>,
) -> anyhow::Result<DiskPassphrase> {
    app.record(
        Some(dc_common::manager::Phase::WaitingForUser),
        "asking the user for the root disk's password",
    );
    // **The plugin first**: a client that answers the question answers it exactly as a person
    // would, and a plugin with no client answers "no answer" — which is what puts the dialog on
    // screen, and gives a person as long as they like to type.
    let answer = match dc_dialog::password_question(dc_dialog::Question::new(
        dc_dialog::Kind::DiskPassword,
        "Root disk password:",
        &format!("The disk {} is encrypted.", disk.display()),
    )) {
        Some(answer) => Some(answer),
        // **The dialog belongs to the display window**, when there is one: a question that is
        // transient for it cannot end up behind the guest's screen.
        None => dc_dialog::password_with_parent(parent, dc_common::APP_NAME, "Root disk password:"),
    };
    let Some(answer) = answer else {
        anyhow::bail!("the root disk's password was not given");
    };
    if answer.is_empty() {
        anyhow::bail!("the root disk's password was not given");
    }
    // The **length** is the most that may ever be said about a passphrase: it tells "the
    // question and the answer agree" from "something truncated it", and gives nothing away.
    let passphrase = DiskPassphrase::new(answer);
    dc_common::milestone!(
        "the disk's password was given ({} byte(s)); the guest will open the disk with it",
        passphrase.expose().map(|b| b.len()).unwrap_or(0)
    );
    Ok(passphrase)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_trailing_newline_is_not_part_of_the_secret() {
        let p = DiskPassphrase::new("hunter2\n");
        assert_eq!(p.expose(), Some(&b"hunter2"[..]));
        let p = DiskPassphrase::new("hunter2\r\n");
        assert_eq!(p.expose(), Some(&b"hunter2"[..]));
        // ...but an inner one is
        let p = DiskPassphrase::new("a\nb");
        assert_eq!(p.expose(), Some(&b"a\nb"[..]));
    }
    #[test]
    fn an_empty_passphrase_is_no_passphrase() {
        assert!(!DiskPassphrase::new("").is_set());
        assert!(!DiskPassphrase::none().is_set());
        assert!(DiskPassphrase::new("x").is_set());
    }
    #[test]
    fn debug_never_reveals_the_secret() {
        let p = DiskPassphrase::new("top-secret");
        let shown = format!("{p:?}");
        assert!(!shown.contains("top-secret"), "{shown}");
        assert!(shown.contains("hidden"), "{shown}");
        // and the same for a struct that contains it
        #[derive(Debug)]
        #[allow(dead_code)]
        struct Holder {
            pass: DiskPassphrase,
        }
        let h = Holder {
            pass: DiskPassphrase::new("top-secret"),
        };
        assert!(!format!("{h:?}").contains("top-secret"));
    }
    #[test]
    fn the_buffer_is_zeroed_when_its_guard_goes_away() {
        // The property the type is built for: the buffer that holds the secret
        // is overwritten, so a later read of the process's memory does not find
        // it.  (Reading *freed* memory is undefined behaviour, so this checks
        // the guard itself rather than the allocator's leftovers.)
        use zeroize::Zeroize;
        let mut guard = zeroize::Zeroizing::new(b"zero-me-please".to_vec());
        assert_eq!(&guard[..], b"zero-me-please");
        let ptr = guard.as_ptr();
        let len = guard.len();
        guard.zeroize();
        let after = unsafe { std::slice::from_raw_parts(ptr, len) }; // still ours
        assert!(
            after.iter().all(|b| *b == 0),
            "the passphrase buffer still holds data: {after:?}"
        );
    }
    /// **A disk that is being made is asked for its passphrase twice, and a refusal is a refusal.**
    /// This is the one path with no display and no plugin, so it is the terminal question — which is
    /// the shape a caller gets when the application has no window to ask over.
    ///
    /// The interesting half is what a *refusal* is: a passphrase is not optional (a disk made with
    /// none is a disk nobody can open), so the first "no answer" ends it, and the two answers have to
    /// agree — the second question exists because a typo in a hidden field is a disk nobody can open.
    #[test]
    fn a_new_disk_is_never_made_without_one_agreeing_passphrase() {
        // The kind of question this asks is the disk's own, which is what a client answers with a
        // password rather than a yes/no (`dc_dialog::Kind::DiskPassword`).
        assert_eq!(dc_dialog::Kind::DiskPassword.as_str(), "disk-password");
        let missing = std::path::Path::new("/srv/disks/root.raw");
        // No display, no plugin: the terminal is the frontend, and with no terminal either the
        // question answers "nothing" — which is a refusal, and it is the refusal a caller sees.
        let refused = ask_new_disk_passphrase(missing, None);
        assert!(refused.is_err(), "{refused:?}");
        assert!(
            format!("{}", refused.unwrap_err()).contains("not given"),
            "a refusal says so"
        );
    }

    #[test]
    fn the_type_holds_its_secret_in_a_zeroizing_guard() {
        let p = DiskPassphrase::new("secret");
        // The inner guard is a `Zeroizing`, which is what makes the drop safe.
        let z: &zeroize::Zeroizing<Vec<u8>> = p.0.as_ref().unwrap();
        assert_eq!(&z[..], b"secret");
    }
}
