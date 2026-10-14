//! The small dialogs the application puts in front of the user.
//!
//! Two of them are the project's rules: the window must not open without
//! the unlock password, and a hidden window must not come back without it.
//!
//! They are **GTK3 windows of our own**, the same toolkit the display window and the settings
//! window use, and they are asked on **the thread that runs the GTK main loop** — the display
//! thread.  That is not a detail: GTK belongs to the thread that ran `gtk::init()`, and a dialog
//! that is created somewhere else and destroyed after its `run()` returns leaves a window on the
//! screen that nothing will ever take away (measured: the disk's password dialog stayed visible
//! and unresponsive while the guest booted behind it).
//!
//! So there is exactly one rule here: **ask where the loop is**.  A caller that is on that thread
//! (the display loop, the settings window's own callbacks) calls these functions directly; a
//! caller that is not (the disk's password, asked before the window exists but on the same thread
//! all the same) uses the same functions, and the terminal prompt is what a session with no
//! display server gets.
//!
//! Everything here answers rather than fails: a dialog that cannot be shown is
//! `None`/`false`, which the caller reads as "the user did not say yes".

pub mod prompt;

/// Why a dialog could not be shown.
#[derive(Debug, thiserror::Error)]
pub enum DialogError {
    /// No way to ask: no display server and no terminal.
    #[error("no way to put a dialog on this session (no display server, no terminal)")]
    NoTool,
    /// The dialog tool failed.
    #[error("{tool} failed: {message}")]
    Failed {
        /// The tool that failed.
        tool: String,
        /// What it said.
        message: String,
    },
}

/// The **kind** a question has, as the plugin's protocol names it
///: `disk-password`, `unlock-password`, `confirm`.
///
/// The dialog does not ask which one it is — the caller knows, because it knows what it is about
/// to do with the answer — so it is passed in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    DiskPassword,
    UnlockPassword,
    Confirm,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::DiskPassword => "disk-password",
            Kind::UnlockPassword => "unlock-password",
            Kind::Confirm => "confirm",
        }
    }
}

/// A question, as a plugin receives it: what it is, and the two lines the dialog would show.
#[derive(Debug, Clone, Copy)]
pub struct Question<'a> {
    pub kind: Kind,
    pub prompt: &'a str,
    /// The long form of the question, when there is one (an empty string otherwise).
    pub detail: &'a str,
}

impl<'a> Question<'a> {
    pub fn new(kind: Kind, prompt: &'a str, detail: &'a str) -> Question<'a> {
        Question {
            kind,
            prompt,
            detail,
        }
    }
}

/// The GTK window a question belongs to, when the caller knows it.
///
/// It is the display window itself, so a question appears **over the guest's screen** instead of
/// behind it.  The type and the rule that publishes it live in `dc-ui`, which is the one place
/// every window the application puts up takes its placement from.
pub type Parent = dc_ui::Parent;

/// The plugin answer for a question, if a client gave one.
enum PluginAnswer {
    Password(String),
    Confirm(bool),
}

/// **Ask through the plugin, or not at all.**  A plugin that cannot answer says "no answer", and
/// the caller then does what it always does — which is why this returns an `Option` rather than
/// a default: "no answer" and "the answer was no" are different things.
fn from_plugin(question: Question<'_>) -> Option<PluginAnswer> {
    dc_plugin::ask(question.kind.as_str(), question.prompt, question.detail).map(|answer| {
        match answer {
            dc_plugin::Answered::Password(password) => PluginAnswer::Password(password),
            dc_plugin::Answered::Confirm(yes) => PluginAnswer::Confirm(yes),
        }
    })
}

/// How a question reaches the user, if at all.
///
/// Asked of the session itself: **our own GTK dialog** when there is a display server to put it
/// on, the terminal prompt otherwise, and nothing when there is neither — a question nobody can
/// be asked is answered by the caller's own default rather than by hanging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frontend {
    /// A GTK dialog of our own.
    Graphical,
    /// A prompt on the terminal the application was started from.
    Terminal,
    /// No dialogs: every question answers "no".
    None,
}

/// Decide the frontend once per process.
///
/// **A graphical dialog is the default**, because that is what a desktop application does and
/// what this project asks for ("a password is asked for the user using a gui interface"). The
/// terminal is the fallback for a session with no display, and `none` answers every question with
/// the caller's own default (a service, a test that must never wait).
///
/// The one thing this costs: a dialog takes the pointer and the keyboard, so it must **never** be
/// put up while the user is typing into the guest — which is why the disk's password is settled
/// *before* the guest is started (the question is asked, the answer is proved, and only then does
/// the window show a guest).
pub fn frontend() -> Frontend {
    if std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some() {
        Frontend::Graphical
    } else if std::io::IsTerminal::is_terminal(&std::io::stdin())
        || std::path::Path::new("/dev/tty").exists()
    {
        Frontend::Terminal
    } else {
        Frontend::None
    }
}

// ---------------------------------------------------------------- messages

/// Tell the user something.  **It does not wait**: a message that blocks the caller also blocks
/// whatever the caller was drawing, and the window is the guest's screen — a still picture there
/// is indistinguishable from a hang.
///
/// With GTK it is put on screen by the loop itself (`glib::idle_add_local`) and closes with its
/// own OK; without GTK it is a sentence on the console.
pub fn message_with_parent(
    parent: Option<&Parent>,
    title: &str,
    text: &str,
) -> Result<(), DialogError> {
    message_inner(parent, title, text)
}

pub fn message(title: &str, text: &str) -> Result<(), DialogError> {
    message_inner(None, title, text)
}

fn message_inner(parent: Option<&Parent>, title: &str, text: &str) -> Result<(), DialogError> {
    // The parent is the display window, and the scheduled work finds it again on the UI thread
    // (`parent_window`): passing it through would be handing a GTK object to another thread.
    match frontend() {
        Frontend::Graphical => graphical_message(parent, title, text),
        Frontend::Terminal => {
            println!("\n=== {title} ===\n{text}\n");
            Ok(())
        }
        Frontend::None => {
            println!("{title}: {text}");
            Ok(())
        }
    }
}

/// A message the user is told, in a GTK dialog, **scheduled on the main loop**: a message that
/// blocked its caller would also block whatever it was drawing (the window is the guest's
/// screen, and a still picture there is indistinguishable from a hang).
fn graphical_message(parent: Option<&Parent>, title: &str, text: &str) -> Result<(), DialogError> {
    use gtk::prelude::*;
    let (shown_title, shown_text) = (title.to_string(), text.to_string());
    let (title, text) = (shown_title.clone(), shown_text.clone());
    let _ = parent; // the display window is found again on the UI thread (see below)
                    // **On the UI thread's own tick**, never in this call: a caller that is the run's own thread
                    // would otherwise reach into glib from a thread it does not own (measured: a panic about the
                    // main context being acquired by another thread).  See `display_loop::schedule_once`.
                    //
                    // The parent is asked for **there** and not carried: a GTK object cannot leave the thread
                    // that owns it, so the closure names nothing of GTK's.
    let run = move || {
        let parent = dc_display::display_loop::parent_window();
        let dialog = gtk::MessageDialog::new(
            parent.as_ref(),
            gtk::DialogFlags::MODAL,
            gtk::MessageType::Info,
            gtk::ButtonsType::Ok,
            &text,
        );
        dialog.set_title(&title);
        dialog.set_position(gtk::WindowPosition::Center);
        dialog.connect_response(|dialog, _| unsafe { dialog.destroy() });
        // **Centered and put in front before it is shown** (`dc-ui`): the session's window
        // manager may ignore GTK's own request, the title bar's height is not known before the
        // window exists, and the guest's own window is a full-screen one of ours — a message the
        // user cannot see is a message that was not delivered.
        dc_ui::bring_to_front(&dialog);
        dialog.show_all();
    };
    if !dc_display::display_loop::schedule_once(run) {
        // No UI thread is running (a headless run): the message is a sentence on the console,
        // which is what a session with no window gets.
        println!("{shown_title}: {shown_text}");
    }
    Ok(())
}

// ---------------------------------------------------------------- questions

/// What the user chose in a question that has more than two answers.
///
/// The close question has three — *Close*, *Hide* and *Cancel* (the operator, 2026-10-09: "we do
/// not need two question when we close the window we need one dialog with three buttons") — and a
/// two-answer `bool` cannot say which.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    /// The **Close** button: end the application.
    Close,
    /// The **Hide** button: take the window off the screen and keep the guest running.
    Hide,
    /// The **Cancel** button: nothing happens at all.
    Cancel,
}

impl Choice {
    /// The choice a response means.  It is one function so the mapping is pinned by a test and
    /// not re-derived at each call site: anything that is not one of the two named buttons (the
    /// window's own close, `Esc`, a click on the title bar's X) is a **Cancel** — the answer that
    /// does nothing, which is the only safe reading of "the question was dismissed".
    pub fn from_response(response: &str) -> Choice {
        if response == CHOOSE_CLOSE {
            Choice::Close
        } else if response == CHOOSE_HIDE {
            Choice::Hide
        } else {
            Choice::Cancel
        }
    }
}

/// Ask a three-answer question in **one** dialog: the first button, the second, and Cancel.
///
/// It used to be two questions in a row (close? / hide instead?), which is a bad question: the
/// user answers the first and gets a second they did not ask for, and the pair has no answer that
/// means "I did not mean to press that".  One dialog with three buttons says all three things at
/// once, and the *Cancel* answer is what the window's own close button and `Esc` mean.
///
/// A dialog that cannot be shown answers **Cancel**: nothing happens, which is the safe answer for
/// everything this is used for.
pub fn choose_with_parent(parent: Option<&Parent>, title: &str, text: &str) -> Choice {
    choose_inner(parent, title, text)
}

pub fn choose(title: &str, text: &str) -> Choice {
    choose_inner(None, title, text)
}

/// The same question, **asked through the plugin**: `Some(choice)` when a plugin answered it,
/// `None` when the caller should put up its own dialog.  A yes/no answer the plugin did give is
/// read as the first button (yes) or the last (no), which is what a client that only knows
/// `confirm` means.
pub fn choose_question(question: Question<'_>) -> Option<Choice> {
    match from_plugin(question)? {
        // The protocol's `confirm` answer is a **yes/no**, and this question has three answers:
        // yes is the first button (*Close*) and no is the last one (*Cancel*).  A client that
        // wants to *Hide* answers "no answer" and the dialog is put up for the person, which is
        // the honest thing — the protocol has no way to say which of two non-yes answers was
        // meant, and inventing one would be a protocol change with a hook to match it.
        PluginAnswer::Confirm(true) => Some(Choice::Close),
        PluginAnswer::Confirm(false) => Some(Choice::Cancel),
        PluginAnswer::Password(_) => None,
    }
}

fn choose_inner(parent: Option<&Parent>, title: &str, text: &str) -> Choice {
    match frontend() {
        Frontend::Graphical => graphical_choose(parent, title, text),
        Frontend::Terminal => {
            println!("\n=== {title} ===\n{text}");
            println!("  1) {CHOOSE_CLOSE}\n  2) {CHOOSE_HIDE}\n  3) {CHOOSE_CANCEL}");
            match prompt::ask_line("Which one? [3] ") {
                Ok(Some(answer)) => match answer.trim() {
                    "1" | "close" | "c" => Choice::Close,
                    "2" | "hide" | "h" => Choice::Hide,
                    _ => Choice::Cancel,
                },
                _ => Choice::Cancel,
            }
        }
        Frontend::None => Choice::Cancel,
    }
}

/// The first button is the default: a question about closing the application is answered by
/// somebody who meant to press it, and `Esc` (or the dialog's own X) is the Cancel.
fn graphical_choose(parent: Option<&Parent>, title: &str, text: &str) -> Choice {
    use gtk::prelude::*;
    if !gtk::is_initialized() {
        return Choice::Cancel;
    }
    let dialog = gtk::MessageDialog::new(
        parent,
        gtk::DialogFlags::MODAL,
        gtk::MessageType::Question,
        gtk::ButtonsType::None,
        text,
    );
    dialog.set_title(title);
    dialog.set_position(gtk::WindowPosition::Center);
    // **One row, three buttons, in the order the question reads**: Close, Hide, Cancel.  GTK
    // gives the first button the default response and the last a `Cancel`-ish one; the names are
    // the caller's words, so the answer is matched by name rather than by position.
    // **The three labels are fixed here**, and the answer is read back by them: the caller
    // passes the question, not the buttons, so the two can never disagree.
    dialog.add_button(CHOOSE_CLOSE, gtk::ResponseType::Ok);
    dialog.add_button(CHOOSE_HIDE, gtk::ResponseType::Other(CHOOSE_HIDE_ID));
    dialog.add_button(CHOOSE_CANCEL, gtk::ResponseType::Cancel);
    dialog.set_default_response(gtk::ResponseType::Ok);
    dc_ui::bring_to_front(&dialog);
    // **The keyboard is the question's while it is up** (`dc_ui::hold_keyboard_for_guest`): the
    // display window holds the keyboard for the guest, and a button or an entry cannot be used
    // while that grab is held.  The grab comes back when the answer is in.
    let answer =
        dc_ui::hold_keyboard_for_guest(|| Choice::from_response(&response_name(dialog.run())));
    unsafe { dialog.destroy() };
    answer
}

/// The three buttons' own labels, in one place: the dialog adds them and the response is read
/// back by them, so the two cannot drift apart.
///
/// **`Keep hidden`, not `Hide`** (the operator, 2026-10-13: "the button Hide has the text 'Keep
/// hidden' and does as it says"): by the time this question is up the window is **already** off the
/// screen — the close button hid it before the question was asked — so this button does not hide
/// anything, it promises to keep it that way and to keep the guest running.
const CHOOSE_CLOSE: &str = "Close";
const CHOOSE_HIDE: &str = "Keep hidden";
const CHOOSE_CANCEL: &str = "Cancel";
/// The id the **Keep hidden** button answers with (a `GtkResponseType` of its own, since `Close`
/// and `Cancel` already have one).
const CHOOSE_HIDE_ID: u16 = 1;

impl Choice {
    /// The three labels this dialog's buttons carry.
    pub const LABELS: (&'static str, &'static str, &'static str) =
        (CHOOSE_CLOSE, CHOOSE_HIDE, CHOOSE_CANCEL);
}

/// A response as the label it came from.  The three buttons have three distinct labels, and the
/// window's own close (`delete-event`) has none — which is the **Cancel** answer.
fn response_name(response: gtk::ResponseType) -> String {
    match response {
        gtk::ResponseType::Ok => CHOOSE_CLOSE.to_string(),
        gtk::ResponseType::Other(id) if id == CHOOSE_HIDE_ID => CHOOSE_HIDE.to_string(),
        _ => String::new(),
    }
}

// ---------------------------------------------------------------- confirmation

/// Ask a yes/no question.  A dialog that cannot be shown answers **no**: the safe answer for
/// everything this is used for.
pub fn confirm_with_parent(
    parent: Option<&Parent>,
    title: &str,
    text: &str,
    yes: &str,
    no: &str,
) -> bool {
    confirm_inner(parent, title, text, yes, no)
}

pub fn confirm(title: &str, text: &str, yes: &str, no: &str) -> bool {
    confirm_inner(None, title, text, yes, no)
}

/// The same question, **asked through the plugin**: `Some(answer)` when a plugin answered it,
/// `None` when the caller should put up its own dialog.
pub fn confirm_question(question: Question<'_>) -> Option<bool> {
    match from_plugin(question)? {
        PluginAnswer::Confirm(yes) => Some(yes),
        // A password answer to a yes/no question is not an answer to this question.
        PluginAnswer::Password(_) => None,
    }
}

fn confirm_inner(parent: Option<&Parent>, title: &str, text: &str, yes: &str, no: &str) -> bool {
    match frontend() {
        Frontend::Graphical => graphical_confirm(parent, title, text, yes, no),
        Frontend::Terminal => {
            println!("\n=== {title} ===\n{text}");
            match prompt::ask_line(&format!("{yes}? [y/N] ")) {
                Ok(Some(answer)) => {
                    let answer = answer.trim().to_ascii_lowercase();
                    answer == "y" || answer == "yes"
                }
                _ => false,
            }
        }
        Frontend::None => false,
    }
}

/// A yes/no question in a GTK dialog.  A dialog that cannot be shown answers **no**, which is the
/// safe answer for everything this is used for.
fn graphical_confirm(
    parent: Option<&Parent>,
    title: &str,
    text: &str,
    yes: &str,
    no: &str,
) -> bool {
    use gtk::prelude::*;
    if !gtk::is_initialized() {
        return false;
    }
    let dialog = gtk::MessageDialog::new(
        parent,
        gtk::DialogFlags::MODAL,
        gtk::MessageType::Question,
        gtk::ButtonsType::None,
        text,
    );
    dialog.set_title(title);
    dialog.set_position(gtk::WindowPosition::Center);
    dialog.add_button(yes, gtk::ResponseType::Ok);
    dialog.add_button(no, gtk::ResponseType::Cancel);
    // **In front before it is shown** (`dc-ui`): GTK's own request is a hint, a session whose
    // window manager ignores it puts the question in the corner, and the guest's window is a
    // full-screen window of ours that would otherwise be over the question.
    dc_ui::bring_to_front(&dialog);
    // **The keyboard is the question's while it is up** (`dc_ui::hold_keyboard_for_guest`).
    let answer = dc_ui::hold_keyboard_for_guest(|| dialog.run());
    unsafe { dialog.destroy() };
    answer == gtk::ResponseType::Ok
}

/// Ask for a **password**, with the characters hidden, in a dialog that belongs to `parent`.
///
/// `None` is a cancelled dialog and never a retry: the caller treats it as a refusal.
pub fn password_with_parent(parent: Option<&Parent>, title: &str, text: &str) -> Option<String> {
    password_inner(parent, title, text)
}

/// The same question, **asked through the plugin**: `Some(password)` when a plugin answered it
/// (an empty one is a refusal, exactly as an empty dialog answer is), `None` when the caller
/// should put up its own dialog.
pub fn password_question(question: Question<'_>) -> Option<String> {
    match from_plugin(question)? {
        PluginAnswer::Password(password) if !password.is_empty() => Some(password),
        // An empty password is a refusal, and a yes/no answer is not an answer to this question:
        // both fall back to the dialog.
        _ => None,
    }
}

fn password_inner(parent: Option<&Parent>, title: &str, text: &str) -> Option<String> {
    match frontend() {
        Frontend::Graphical => graphical_password(parent, title, text),
        Frontend::Terminal => prompt::ask_password(text).ok().flatten(),
        Frontend::None => None,
    }
}

/// A password question in a GTK dialog, with the entry's characters hidden.
///
/// It **runs here and returns**: the caller is the thread that runs the GTK main loop, which is
/// what makes `run()`/`destroy()` safe (see the module's note).
fn graphical_password(parent: Option<&Parent>, title: &str, text: &str) -> Option<String> {
    use gtk::prelude::*;
    if !gtk::is_initialized() {
        return None;
    }
    let dialog = gtk::MessageDialog::new(
        parent,
        gtk::DialogFlags::MODAL,
        gtk::MessageType::Question,
        gtk::ButtonsType::None,
        text,
    );
    dialog.set_title(title);
    dialog.set_position(gtk::WindowPosition::Center);
    dialog.add_button("OK", gtk::ResponseType::Ok);
    dialog.add_button("Cancel", gtk::ResponseType::Cancel);
    dialog.set_default_response(gtk::ResponseType::Ok);
    let entry = gtk::Entry::new();
    entry.set_visibility(false);
    entry.set_activates_default(true);
    dialog.content_area().add(&entry);
    entry.show();
    // **In front before it is shown** (`dc-ui`), after the entry is in: the preferred size the
    // rule measures is the dialog the user is about to see, entry and buttons included.
    dc_ui::bring_to_front(&dialog);
    dialog.show_all();
    // **And the caret is in the field the user came to type in** (the operator: a question "should
    // ... gain focus on the password editor"): the dialog takes the keyboard when it is mapped,
    // and this is what makes the first keystroke a character of the password instead of a search
    // in the guest behind it.  It is called after `show_all` because a widget that is not visible
    // cannot hold the focus.
    entry.grab_focus();
    // **The keyboard is the entry's while the question is up**: the display window's grab is let
    // go first, or the characters the person types are the guest's and not the password.
    let answer = dc_ui::hold_keyboard_for_guest(|| dialog.run());
    let typed = entry.text().to_string();
    unsafe { dialog.destroy() };
    if answer != gtk::ResponseType::Ok {
        return None; // cancel
    }
    // An **empty** answer is a refusal, not a password: a caller that passed one on would ask the
    // guest to try an empty password.
    if typed.is_empty() {
        None
    } else {
        Some(typed)
    }
}
