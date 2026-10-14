//! **The disk manager's window** — `desk-disk` with no arguments.
//!
//! Managing a disk is four things: **make** one, **resize** one, **change its passphrase**, and
//! **say what is on it**.  The disk this window makes is a **data disk** — an encrypted container
//! with an empty filesystem for the guest to mount — because the userland belongs to the **root**
//! disk and to nothing else (the operator, 2026-10-13; the root disk is `make rootdisk`, which is
//! `desk-disk rootdisk`).  All four are the project's
//! own disk jobs (`dc-fc-disk`: a microVM of its own, no root, no loop device, no `dm-crypt` on the
//! host), and this module is the one place they are put in front of a person as a window instead of
//! a command line.
//!
//! The shape is the application's settings window, and deliberately so:
//!
//! * **one thread**, running `gtk::main` (GTK is single-threaded, and a job is minutes long);
//! * **the dialog is the operation**, which is the operator's own rule (2026-10-13): a job runs on a
//!   thread of its own behind a **modal progress dialog**, whose log is **cleared for each new job**
//!   and which ends with one sentence saying whether it worked.  A job being minutes long is exactly
//!   why the dialog cannot be dismissed while it runs;
//! * **the passphrase is never a setting**: it is typed in the window, handed to the job and
//!   dropped with it — no file, no command line, no environment.  Every passphrase field carries a
//!   **Show** check, so what was typed can be looked at;
//! * **the size is a number**: a disk is a raw file whose length is its size (`truncate` and
//!   `ftruncate`; Firecracker attaches raw images), so "how big" is a file length in MiB;
//! * **no tab scrolls**: the window has room for every field of every tab.

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;

use gtk::prelude::*;

use dc_disk_manager::{DiskJob, Job};

/// The smallest disk this project will make: the guest's userland is ~1.8 GiB, and a disk has to
/// carry it plus room to work in.  A size below it is refused with a sentence rather than made and
/// filled to the brim — which is the failure `desk-disk create` reports as "is the disk big
/// enough for it?".
const MIN_DISK_MIB: u64 = 2048;

/// **The size a new disk is offered at** (MiB): the tool's own default, and what the field starts
/// with.
const DEFAULT_DISK_MIB: u64 = 20 * 1024;

/// **Is a job in flight?**  Set when one is sent, cleared when its end is applied.  It is what makes
/// the window refuse a second job (`send`), which is the window's own half of "one job at a time" —
/// the other half is the `flock` the job thread takes (`crate::job_lock`).
static IN_FLIGHT: AtomicBool = AtomicBool::new(false);

/// What the window tells a job thread to do.
enum Order {
    Make {
        path: PathBuf,
        mib: u64,
        passphrase: String,
    },
    Resize {
        path: PathBuf,
        mib: Option<u64>,
        passphrase: Option<String>,
    },
    Change {
        path: PathBuf,
        current: String,
        new: String,
    },
    Info {
        path: PathBuf,
    },
}

impl Order {
    /// What this job is: the progress dialog's title and the window's first line about it.
    fn title(&self) -> &'static str {
        match self {
            Order::Make { .. } => "Making the disk",
            Order::Resize { .. } => "Resizing the disk",
            Order::Change { .. } => "Changing the passphrase",
            Order::Info { .. } => "Reading the disk",
        }
    }
}

/// What a job thread reports back, as it goes.
#[derive(Debug)]
enum Report {
    /// **The job started**: clear the log (a new job must not be read with the last one's lines
    /// still there: the operator, 2026-10-13) and open the progress dialog.
    Started(&'static str),
    /// One line of what the job is doing: into the log and into the dialog.
    Line(String),
    /// The job is over: whether it worked, and the sentence that says what happened.  This is what
    /// the dialog ends with, and what lets it be closed.
    Finished { ok: bool, said: String },
}

/// **The modal progress dialog**, while a job runs.
struct Progress {
    dialog: gtk::Dialog,
    /// The one sentence that changes: what is happening, then whether it worked.
    said: gtk::Label,
    /// Everything the job has printed, as it arrives.
    details: gtk::TextView,
    /// **Only the end closes it**: while the job runs the dialog cannot be dismissed — the operation
    /// blocks the window, and a dismissed progress bar is a person wondering whether it still runs.
    closable: Arc<AtomicBool>,
}

/// **The window.**  It owns the widgets: every job runs on its own thread and reports back through a
/// channel this thread drains, so the window itself never blocks on a job.
pub struct DiskWindow {
    window: gtk::Window,
    log: gtk::TextView,
    status: gtk::Label,
    /// **The dialog while a job runs.**  `Rc<RefCell<..>>`, not `Arc<Mutex<..>>`: a GTK object lives
    /// on the thread that made it and never crosses one — the job thread sends *reports*, and this
    /// thread applies them.
    progress: Rc<RefCell<Option<Progress>>>,
}

impl DiskWindow {
    /// Build the window, and run it.  Returns when the window is closed.
    pub fn run() -> i32 {
        if gtk::init().is_err() {
            eprintln!("desk-disk: no display server for the disk manager's window");
            return 1;
        }
        // **One channel for reports**, with a sending end in the widgets that check what was typed
        // and in the job thread, and one place that reads it: the GLib timeout that applies each
        // report to the widgets, on this thread (the only thread that may touch one).
        let (orders_tx, orders_rx) = channel::<Order>();
        let (report_tx, report_rx) = channel::<Report>();
        let window = DiskWindow::build(orders_tx, report_tx.clone());
        // The orders are carried out by a thread of their own, one at a time, so a job that is
        // minutes long never freezes the window it was started from.
        DiskWindow::serve(orders_rx, report_rx, report_tx, &window);
        window.window.show_all();
        dc_ui::bring_to_front(&window.window);
        gtk::main();
        0
    }

    /// Build every widget once: the notebook, its four tabs, the log and the status line.
    fn build(orders: Sender<Order>, reports: Sender<Report>) -> DiskWindow {
        let window = gtk::Window::new(gtk::WindowType::Toplevel);
        window.set_title(&format!("{} — disks", dc_common::APP_NAME));
        window.set_default_size(820, 660);
        window.set_border_width(12);

        let outer = gtk::Box::new(gtk::Orientation::Vertical, 10);
        window.add(&outer);
        let tabs = gtk::Notebook::new();
        outer.add(&tabs);

        // ---------------------------------------------------------------- make a disk
        {
            let body = tab_body();
            tabs.append_page(&body, Some(&tab_label("Make a disk")));
            body.add(&heading("A new data disk, for the guest to mount and fill"));
            let column = form();
            let grid = grid();
            column.add(&grid);

            let path = gtk::Entry::new();
            path.set_text(&default_new_disk().display().to_string());
            path.set_hexpand(true);
            field(&grid, 0, "_Disk file", &path);
            let browse = gtk::Button::with_label("Choose…");
            grid.attach(&browse, 2, 0, 1, 1);
            choose_file(&browse, &window, &path, "Where to make the disk", true);

            let size = gtk::SpinButton::with_range(MIN_DISK_MIB as f64, 4_194_304.0, 256.0);
            size.set_value(DEFAULT_DISK_MIB as f64);
            field(&grid, 1, "Size (Mi_B)", &size);

            let pass = password_field(&grid, 2, "_Passphrase");
            let confirm = password_field(&grid, 3, "A_gain");

            let note = gtk::Label::new(Some(
                "An **additional disk** for a guest: an encrypted container with an empty ext4 \
                 filesystem, which the guest mounts (the panel's own mount plugin, or \
                 `desk-disk-mount`) and fills.  **Nothing is copied into it** — the guest's \
                 own system belongs to the **root** disk, which `make rootdisk` makes — its \
                 passphrase is asked for twice and kept nowhere, and it is made inside a microVM \
                 of its own (a minute or two).",
            ));
            note.set_xalign(0.0);
            note.set_line_wrap(true);
            column.add(&note);

            let button = action_button("Make the disk (data)");
            {
                let orders = orders.clone();
                let reports = reports.clone();
                button.connect_clicked(move |_| {
                    let path = PathBuf::from(path.text().to_string());
                    let mib = size.value() as u64;
                    let one = pass.text();
                    let two = confirm.text();
                    if path.as_os_str().is_empty() {
                        refuse(&reports, "name the disk file first");
                        return;
                    }
                    if let Err(said) = accepted_size(mib) {
                        refuse(&reports, &said);
                        return;
                    }
                    if one.is_empty() {
                        refuse(
                            &reports,
                            "the disk needs a passphrase: it is what opens it at boot",
                        );
                        return;
                    }
                    if one != two {
                        refuse(&reports, "the two passphrases differ; nothing was made");
                        return;
                    }
                    if send(
                        &orders,
                        &reports,
                        Order::Make {
                            path,
                            mib,
                            passphrase: one,
                        },
                    )
                    .is_err()
                    {
                        return;
                    }
                    pass.set_text("");
                    confirm.set_text("");
                });
            }
            column.add(&button);
            body.add(&column);
        }

        // ---------------------------------------------------------------- resize
        {
            let body = tab_body();
            tabs.append_page(&body, Some(&tab_label("Resize")));
            body.add(&heading("A bigger disk"));
            let column = form();
            let grid = grid();
            column.add(&grid);

            let path = gtk::Entry::new();
            path.set_hexpand(true);
            field(&grid, 0, "Disk _file", &path);
            let browse = gtk::Button::with_label("Choose…");
            grid.attach(&browse, 2, 0, 1, 1);
            choose_file(&browse, &window, &path, "Choose a disk to resize", false);

            let size = gtk::SpinButton::with_range(0.0, 4_194_304.0, 256.0);
            size.set_value(0.0);
            field(&grid, 1, "New size (Mi_B, 0 = as it is)", &size);

            let pass = password_field(&grid, 2, "_Passphrase");

            let note = gtk::Label::new(Some(
                "Growing is one `ftruncate` and then the filesystem inside the container is grown to \
                 fill it (the job does that part).  **Shrinking is not done**: a filesystem that \
                 does not fit is a filesystem that loses data, and nothing here destroys data.  \
                 The passphrase opens the container; it is not changed by this.",
            ));
            note.set_xalign(0.0);
            note.set_line_wrap(true);
            column.add(&note);

            let button = action_button("Resize the disk");
            {
                let orders = orders.clone();
                let reports = reports.clone();
                button.connect_clicked(move |_| {
                    let path = PathBuf::from(path.text().to_string());
                    let mib = size.value() as u64;
                    let passphrase = pass.text();
                    if path.as_os_str().is_empty() {
                        refuse(&reports, "name the disk file first");
                        return;
                    }
                    let sent = send(
                        &orders,
                        &reports,
                        Order::Resize {
                            path,
                            mib: (mib > 0).then_some(mib),
                            passphrase: (!passphrase.is_empty()).then_some(passphrase),
                        },
                    );
                    if sent.is_ok() {
                        pass.set_text("");
                    }
                });
            }
            column.add(&button);
            body.add(&column);
        }

        // ---------------------------------------------------------------- change the passphrase
        {
            let body = tab_body();
            tabs.append_page(&body, Some(&tab_label("Passphrase")));
            body.add(&heading("Change a disk's passphrase"));
            let column = form();
            let grid = grid();
            column.add(&grid);

            let path = gtk::Entry::new();
            path.set_hexpand(true);
            field(&grid, 0, "Disk _file", &path);
            let browse = gtk::Button::with_label("Choose…");
            grid.attach(&browse, 2, 0, 1, 1);
            choose_file(&browse, &window, &path, "Choose a disk", false);

            let current_field = password_field(&grid, 1, "_Current passphrase");
            let new_field = password_field(&grid, 2, "_New passphrase");
            let again_field = password_field(&grid, 3, "A_gain");

            let note = gtk::Label::new(Some(
                "Both passphrases are asked for here and kept nowhere: the old one opens the \
                 container, the new one replaces it, and the guest asks for the new one at the next \
                 boot.",
            ));
            note.set_xalign(0.0);
            note.set_line_wrap(true);
            column.add(&note);

            let button = action_button("Change the passphrase");
            {
                let orders = orders.clone();
                let reports = reports.clone();
                button.connect_clicked(move |_| {
                    let path = PathBuf::from(path.text().to_string());
                    let current = current_field.text();
                    let new_pass = new_field.text();
                    let again_text = again_field.text();
                    if path.as_os_str().is_empty() {
                        refuse(&reports, "name the disk file first");
                        return;
                    }
                    if current.is_empty() {
                        refuse(
                            &reports,
                            "the current passphrase is what opens the disk: it is needed",
                        );
                        return;
                    }
                    if new_pass.is_empty() {
                        refuse(&reports, "the new passphrase is empty");
                        return;
                    }
                    if new_pass != again_text {
                        refuse(
                            &reports,
                            "the two new passphrases differ; nothing was changed",
                        );
                        return;
                    }
                    let sent = send(
                        &orders,
                        &reports,
                        Order::Change {
                            path,
                            current,
                            new: new_pass,
                        },
                    );
                    if sent.is_ok() {
                        current_field.set_text("");
                        new_field.set_text("");
                        again_field.set_text("");
                    }
                });
            }
            column.add(&button);
            body.add(&column);
        }

        // ---------------------------------------------------------------- what is on it
        {
            let body = tab_body();
            tabs.append_page(&body, Some(&tab_label("What is on it")));
            body.add(&heading("What a disk holds"));
            let column = form();
            let grid = grid();
            column.add(&grid);

            let path = gtk::Entry::new();
            path.set_hexpand(true);
            field(&grid, 0, "Disk _file", &path);
            let browse = gtk::Button::with_label("Choose…");
            grid.attach(&browse, 2, 0, 1, 1);
            choose_file(&browse, &window, &path, "Choose a disk to look at", false);

            let note = gtk::Label::new(Some(
                "Reads the file's length, whether it is a LUKS container, and — through a job of its \
                 own — what the guest sees inside it.  Nothing is written and no passphrase is \
                 needed: it is a question, not a change.",
            ));
            note.set_xalign(0.0);
            note.set_line_wrap(true);
            column.add(&note);

            let button = action_button("Look at the disk");
            {
                let orders = orders.clone();
                let reports = reports.clone();
                button.connect_clicked(move |_| {
                    let path = PathBuf::from(path.text().to_string());
                    if path.as_os_str().is_empty() {
                        refuse(&reports, "name the disk file first");
                        return;
                    }
                    let _ = send(&orders, &reports, Order::Info { path });
                });
            }
            column.add(&button);
            body.add(&column);
        }

        // ---------------------------------------------------------------- the log and the status
        outer.add(&heading("What the job says"));
        let log = gtk::TextView::new();
        log.set_editable(false);
        log.set_monospace(true);
        log.set_wrap_mode(gtk::WrapMode::WordChar);
        let scroll = gtk::ScrolledWindow::new(gtk::Adjustment::NONE, gtk::Adjustment::NONE);
        scroll.set_policy(gtk::PolicyType::Automatic, gtk::PolicyType::Automatic);
        scroll.set_min_content_height(110);
        scroll.add(&log);
        outer.add(&scroll);

        let status = gtk::Label::new(Some("ready"));
        status.set_xalign(0.0);
        status.set_line_wrap(true);
        outer.add(&status);

        let actions = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        actions.set_halign(gtk::Align::End);
        let quit = gtk::Button::with_label("Close");
        let window_for_quit = window.clone();
        quit.connect_clicked(move |_| unsafe { window_for_quit.destroy() });
        actions.add(&quit);
        outer.add(&actions);

        let window_for_close = window.clone();
        window.connect_delete_event(move |_, _| {
            unsafe { window_for_close.destroy() };
            gtk::main_quit();
            false.into()
        });

        DiskWindow {
            window,
            log,
            status,
            progress: Rc::new(RefCell::new(None)),
        }
    }

    /// **Drain the reports on the UI thread** (a GLib timeout of its own — the only thread that may
    /// touch a widget is the one running `gtk::main`), and run the orders one at a time on a thread
    /// of their own.
    fn serve(
        orders: Receiver<Order>,
        reports: Receiver<Report>,
        sender: Sender<Report>,
        window: &DiskWindow,
    ) {
        // **The job thread**: one order at a time, in the order they were given, so two jobs never
        // run over one disk or over the one directory their sockets live in.
        std::thread::spawn(move || {
            while let Ok(order) = orders.recv() {
                let _ = sender.send(Report::Started(order.title()));
                let said = carry_out(order, &sender);
                let _ = sender.send(said);
            }
        });
        // And the window's own end of it: every report, applied to the widgets here.
        let log = window.log.clone();
        let status = window.status.clone();
        let progress = window.progress.clone();
        let parent = window.window.clone();
        gtk::glib::timeout_add_local(std::time::Duration::from_millis(100), move || {
            while let Ok(report) = reports.try_recv() {
                match report {
                    Report::Started(title) => {
                        // **A new job, a clean log**: the last job's lines are not this job's.
                        clear(&log);
                        status.set_text(&format!("{title}…"));
                        open_progress(&parent, &progress, title);
                    }
                    Report::Line(line) => {
                        append(&log, &line);
                        if let Some(progress) = progress.borrow().as_ref() {
                            append(&progress.details, &line);
                        }
                    }
                    Report::Finished { ok, said } => {
                        append(&log, &format!("— {said}"));
                        status.set_text(&if ok {
                            format!("done: {said}")
                        } else {
                            format!("failed: {said}")
                        });
                        if let Some(progress) = progress.borrow().as_ref() {
                            // **The end, in the dialog itself**: what was done, and whether it
                            // worked — and only now can the dialog be closed.
                            progress.said.set_markup(&if ok {
                                format!("<b>Completed successfully</b>\n{said}")
                            } else {
                                format!("<b>Failed</b>\n{said}")
                            });
                            progress.closable.store(true, Ordering::Relaxed);
                        }
                        IN_FLIGHT.store(false, Ordering::Relaxed);
                    }
                }
            }
            gtk::glib::ControlFlow::Continue
        });
    }
}

/// **The modal progress dialog**: what is happening, everything the job has printed, and one button
/// that does nothing until the job is over.
fn open_progress(parent: &gtk::Window, slot: &Rc<RefCell<Option<Progress>>>, title: &str) {
    let dialog = gtk::Dialog::with_buttons(
        Some(title),
        Some(parent),
        gtk::DialogFlags::MODAL | gtk::DialogFlags::DESTROY_WITH_PARENT,
        &[],
    );
    dialog.set_default_size(560, 380);
    dialog.add_button("Close", gtk::ResponseType::Close);

    let said = gtk::Label::new(Some("working…"));
    said.set_xalign(0.0);
    said.set_line_wrap(true);
    dialog.content_area().add(&said);

    let details = gtk::TextView::new();
    details.set_editable(false);
    details.set_monospace(true);
    details.set_wrap_mode(gtk::WrapMode::WordChar);
    let scroll = gtk::ScrolledWindow::new(gtk::Adjustment::NONE, gtk::Adjustment::NONE);
    scroll.set_policy(gtk::PolicyType::Automatic, gtk::PolicyType::Automatic);
    scroll.set_vexpand(true);
    scroll.add(&details);
    dialog.content_area().add(&scroll);

    // **The Close button is inert while the job runs**: a modal progress dialog a person can dismiss
    // is a job nobody can see the end of.  It works the moment the job says it is over.
    let closable = Arc::new(AtomicBool::new(false));
    let closable_for_close = closable.clone();
    let dialog_for_close = dialog.clone();
    dialog.connect_response(move |_, _| {
        if closable_for_close.load(Ordering::Relaxed) {
            unsafe { dialog_for_close.destroy() };
        }
    });
    let closable_for_delete = closable.clone();
    let dialog_for_delete = dialog.clone();
    dialog.connect_delete_event(move |_, _| {
        if closable_for_delete.load(Ordering::Relaxed) {
            unsafe { dialog_for_delete.destroy() };
            return gtk::glib::Propagation::Proceed;
        }
        gtk::glib::Propagation::Stop
    });

    dc_ui::bring_to_front(&dialog);
    dialog.show_all();
    // **One dialog per job**, destroyed when it is closed (and the slot cleared with it): the next
    // job opens its own, with its own log — a reused dialog would be a dialog carrying the last
    // job's lines, which is exactly what "clear it for a new job" is against.
    let slot_for_close = slot.clone();
    let dialog_for_forget = dialog.clone();
    dialog.connect_response(move |_, _| {
        if let Some(progress) = slot_for_close.borrow().as_ref() {
            if progress.dialog == dialog_for_forget {
                *slot_for_close.borrow_mut() = None;
            }
        }
    });
    *slot.borrow_mut() = Some(Progress {
        dialog,
        said,
        details,
        closable,
    });
}

/// **Carry one order out**, on the job thread: build the job, run it in its own microVM, and send
/// every line it printed as it arrives.
///
/// The passphrases live in this function's own `String`s for as long as the job needs them and go out
/// of scope with it (`DiskJob` zeroizes its own copy when it is dropped) — nowhere else.
fn carry_out(order: Order, reports: &Sender<Report>) -> Report {
    let run = match dc_fc_disk::tool_run() {
        Ok(run) => run,
        Err(e) => return failed(format!("{e}")),
    };
    // **One job at a time for the whole machine**: the same lock `desk-disk` takes, so the
    // window and the command line refuse each other instead of writing one disk from two places.
    let _lock = match crate::job_lock(&run.run_dir) {
        Ok(lock) => lock,
        Err(e) => return failed(format!("{e}")),
    };
    let (job, what) = match order {
        Order::Make {
            path,
            mib,
            passphrase,
        } => {
            if let Err(said) = make_room(&path, mib) {
                return failed(said);
            }
            // **Nothing is copied into it**: an additional disk is the user's own data, and the
            // userland belongs to the root disk (`desk-disk rootdisk`, `make rootdisk`).
            let job = DiskJob::new(Job::CreateLuks, &path).with_password(passphrase);
            (
                job,
                format!("made the data disk {} ({mib} MiB, empty)", path.display()),
            )
        }
        Order::Resize {
            path,
            mib,
            passphrase,
        } => {
            if let Some(mib) = mib {
                if let Err(e) = dc_fc_disk::image::resize_raw(&path, mib) {
                    return failed(format!("{e}"));
                }
                let _ = reports.send(Report::Line(format!(
                    "the file is {mib} MiB now; the filesystem inside it is grown by the job"
                )));
            }
            let mut job = DiskJob::new(Job::Resize, &path);
            if let Some(passphrase) = passphrase {
                job = job.with_password(passphrase);
            }
            (job, format!("resized {}", path.display()))
        }
        Order::Change { path, current, new } => (
            DiskJob::new(Job::ChangePassword, &path)
                .with_password(current)
                .with_new_password(new),
            format!("the passphrase of {} was changed", path.display()),
        ),
        Order::Info { path } => {
            if let Ok((size, luks)) = dc_fc_disk::image::inspect(&path) {
                let _ = reports.send(Report::Line(format!(
                    "the file is {} MiB, {}",
                    size / (1024 * 1024),
                    if luks {
                        "a LUKS container"
                    } else {
                        "not a LUKS container"
                    }
                )));
            }
            (
                DiskJob::new(Job::Info, &path),
                format!("read {}", path.display()),
            )
        }
    };
    match run.run(&job) {
        Ok(result) => {
            for line in &result.lines {
                let _ = reports.send(Report::Line(line.clone()));
            }
            if result.ok {
                Report::Finished {
                    ok: true,
                    said: format!("{what} — the job took {:.1}s", result.took.as_secs_f64()),
                }
            } else {
                failed(format!(
                    "the job did not succeed ({} line(s) above)",
                    result.lines.len()
                ))
            }
        }
        Err(e) => failed(format!("{e}")),
    }
}

/// A job that did not work, with the sentence a person reads.
fn failed(said: String) -> Report {
    Report::Finished { ok: false, said }
}

/// **The file a new disk is written to**: the folder the settings name (`disk_folder`, which is
/// what the application looks in), or the package's own `disks/` when there is no settings file yet
/// — so the disk this window makes is where the application expects to find one.
fn default_new_disk() -> PathBuf {
    dc_session_paths::disk_folder().join("new.raw")
}

/// Make room for a disk: the file is created and **sized** here (one `truncate`), refused when
/// anything is already at that path — a disk is the user's data and `create` never overwrites one.
fn make_room(path: &std::path::Path, mib: u64) -> Result<(), String> {
    if path.exists() {
        return Err(format!(
            "{} is already there; a disk is never overwritten",
            path.display()
        ));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    }
    dc_fc_disk::image::create_raw(path, mib).map_err(|e| format!("{e}"))
}

/// The settings' own `disk_folder`, for the default path — read from the same file the application
/// reads, and the package's own folder when there is no settings file yet.
mod dc_session_paths {
    /// The folder the disks live in: **what the settings say** (`disk_folder`, read from
    /// `dc_settings::config_path`), and `<package>/disks` when there is no settings file yet — a
    /// fresh installation's own folder.
    pub fn disk_folder() -> std::path::PathBuf {
        let config = dc_settings::config_path();
        if let Ok(settings) = dc_settings::Settings::load_from(&config, false) {
            if !settings.disk_folder.as_os_str().is_empty() {
                return settings.disk_folder;
            }
        }
        dc_common::package_dir()
            .map(|package| dc_common::media::disk_folder_for(&package))
            .unwrap_or_else(|| std::path::PathBuf::from("."))
    }
}

/// **Is this a size a new disk may have?** this project's rule, in one place so the window and its test
/// apply the same one: a disk carries the guest's own userland, so anything smaller than
/// [`MIN_DISK_MIB`] is refused with a sentence rather than made and filled to the brim.
pub fn accepted_size(mib: u64) -> Result<(), String> {
    if mib < MIN_DISK_MIB {
        return Err(format!(
            "{mib} MiB is too small for a disk with a system in it; at least {MIN_DISK_MIB} MiB"
        ));
    }
    Ok(())
}

/// **Send an order**, unless one is already in flight: a second job would queue behind the first and
/// then run *after* it, over a disk the person has stopped looking at.  The refusal is said in the
/// window (`refuse`), and the progress dialog is opened by the job thread's own `Started`.
fn send(orders: &Sender<Order>, reports: &Sender<Report>, order: Order) -> Result<(), ()> {
    if IN_FLIGHT.load(Ordering::Relaxed) {
        refuse(
            reports,
            "a job is already running; wait for its dialog to say it is done",
        );
        return Err(());
    }
    IN_FLIGHT.store(true, Ordering::Relaxed);
    if orders.send(order).is_err() {
        IN_FLIGHT.store(false, Ordering::Relaxed);
        refuse(reports, "the window's own channel is gone");
        return Err(());
    }
    Ok(())
}

/// Something was checked and refused (or a job ended): the window is told in the same channel a job's
/// end travels on, and no job is in flight any more.
fn refuse(reports: &Sender<Report>, said: &str) {
    IN_FLIGHT.store(false, Ordering::Relaxed);
    let _ = reports.send(Report::Finished {
        ok: false,
        said: said.to_string(),
    });
}

/// Clear a log area: **a new job starts with nothing to read** (the operator, 2026-10-13), so the
/// last job's lines are never read as this one's.
fn clear(log: &gtk::TextView) {
    if let Some(buffer) = log.buffer() {
        buffer.set_text("");
    }
}

/// Add one line to a log area, and scroll to it: what a person watches while a job runs.
fn append(log: &gtk::TextView, line: &str) {
    let Some(buffer) = log.buffer() else {
        return;
    };
    let mut end = buffer.end_iter();
    buffer.insert(&mut end, &format!("{line}\n"));
    let at = buffer.end_iter();
    if let Some(mark) = buffer.create_mark(None, &at, false) {
        log.scroll_mark_onscreen(&mark);
    }
}

// ---------------------------------------------------------------------------- the small widgets

fn tab_body() -> gtk::Box {
    let body = gtk::Box::new(gtk::Orientation::Vertical, 12);
    body.set_border_width(12);
    body
}

fn tab_label(text: &str) -> gtk::Label {
    gtk::Label::new(Some(text))
}

/// **The form itself**, in the middle of the tab: the fields are one column of a readable width
/// (~520 px), which is what makes a label and its entry line up with every other label and entry —
/// the same rule the settings window follows, and the reason its grid is a grid.
fn form() -> gtk::Box {
    let column = gtk::Box::new(gtk::Orientation::Vertical, 12);
    column.set_halign(gtk::Align::Center);
    column.set_size_request(520, -1);
    column
}

fn grid() -> gtk::Grid {
    let grid = gtk::Grid::new();
    grid.set_row_spacing(6);
    grid.set_column_spacing(12);
    grid
}

fn heading(text: &str) -> gtk::Label {
    let label = gtk::Label::new(Some(text));
    label.set_xalign(0.0);
    label.set_markup(&format!("<b>{text}</b>"));
    label
}

fn field<W: IsA<gtk::Widget>>(grid: &gtk::Grid, row: i32, label: &str, widget: &W) {
    let l = gtk::Label::new(Some(label));
    l.set_xalign(1.0);
    if label.contains('_') {
        l.set_use_underline(true);
        l.set_mnemonic_widget(Some(widget));
    }
    grid.attach(&l, 0, row, 1, 1);
    widget.set_hexpand(true);
    grid.attach(widget, 1, row, 1, 1);
}

/// **A job's own button**, under the fields of its tab: the same width as the fields, not the width
/// of the window — a form is a form, and a button spanning the whole window is not one.
fn action_button(label: &str) -> gtk::Button {
    let button = gtk::Button::with_label(label);
    button.set_halign(gtk::Align::End);
    button
}

/// **A passphrase field, and the check that shows it** (the operator, 2026-10-13: *"need to allow to
/// see/hide the password on the inputs"*): the entry is masked, and the check beside it reveals what
/// was typed — which is how a person checks a passphrase they are about to make a disk with without
/// typing it twice and hoping.
fn password_field(grid: &gtk::Grid, row: i32, label: &str) -> Secret {
    let entry = gtk::Entry::new();
    entry.set_visibility(false);
    entry.set_hexpand(true);
    field(grid, row, label, &entry);

    let show = gtk::CheckButton::with_label("Show");
    show.set_tooltip_text(Some("show what was typed, in this field"));
    let reveal = entry.clone();
    show.connect_toggled(move |button| reveal.set_visibility(button.is_active()));
    grid.attach(&show, 2, row, 1, 1);
    Secret { entry }
}

/// A passphrase field, as the widgets around it see it: `text()` is the secret, and it is emptied
/// once a job has it (the window keeps no passphrase after that).
#[derive(Clone)]
struct Secret {
    entry: gtk::Entry,
}

impl Secret {
    fn text(&self) -> String {
        self.entry.text().to_string()
    }

    fn set_text(&self, text: &str) {
        self.entry.set_text(text);
    }
}

/// A file chooser for a path field: **Save** for a disk that is being made, **Open** for one that
/// already exists.
fn choose_file(
    button: &gtk::Button,
    parent: &gtk::Window,
    entry: &gtk::Entry,
    title: &str,
    save: bool,
) {
    let entry = entry.clone();
    let parent = parent.clone();
    let title = title.to_string();
    button.connect_clicked(move |_| {
        let action = if save {
            gtk::FileChooserAction::Save
        } else {
            gtk::FileChooserAction::Open
        };
        let chooser = gtk::FileChooserDialog::new(Some(&title), Some(&parent), action);
        chooser.add_button("Cancel", gtk::ResponseType::Cancel);
        chooser.add_button(
            if save { "Choose" } else { "Open" },
            gtk::ResponseType::Accept,
        );
        chooser.set_current_folder(entry.text().as_str());
        if chooser.run() == gtk::ResponseType::Accept {
            if let Some(path) = chooser.filename() {
                entry.set_text(&path.display().to_string());
            }
        }
        unsafe { chooser.destroy() };
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The size rule**, pinned where the window applies it: a disk with the guest's system in it
    /// cannot be smaller than the userland, and the window refuses a smaller one before it starts a
    /// job — "is the disk big enough for it?" is a question to answer *before* minutes of work, not
    /// after.
    #[test]
    fn a_new_disk_is_at_least_big_enough_for_the_userland() {
        // The size the window offers by default, and the smallest it accepts.
        assert_eq!(DEFAULT_DISK_MIB, 20 * 1024);
        assert!(
            accepted_size(DEFAULT_DISK_MIB).is_ok(),
            "the default has to be a size the window takes"
        );
        // The floor carries the guest's own userland (the image this project builds is a little
        // under 2 GiB), with room to work in.
        let userland_mib = 1_800;
        assert!(
            MIN_DISK_MIB > userland_mib,
            "a disk smaller than the userland cannot carry it"
        );
        assert!(
            accepted_size(MIN_DISK_MIB - 1).is_err(),
            "a disk below the minimum is refused before a job starts"
        );
    }

    /// **A disk is never overwritten**: the window's own check is the tool's rule, applied before a
    /// job is started rather than half-way through one.
    #[test]
    fn a_disk_that_is_already_there_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("disk.raw");
        std::fs::write(&path, b"the user's disk").unwrap();
        let refused = make_room(&path, 4096);
        assert!(refused.is_err(), "{refused:?}");
        assert_eq!(std::fs::read(&path).unwrap(), b"the user's disk");
        // And a new one is created at the size asked for.
        let fresh = dir.path().join("fresh.raw");
        make_room(&fresh, 4096).unwrap();
        assert_eq!(std::fs::metadata(&fresh).unwrap().len(), 4096 * 1024 * 1024);
    }

    /// **One job at a time**: a second order while one is in flight is refused with the reason, and
    /// the first is the only one the job thread ever sees.
    #[test]
    fn a_second_job_is_refused_while_one_runs() {
        let (orders, received) = channel::<Order>();
        let (reports, said) = channel::<Report>();
        assert!(send(
            &orders,
            &reports,
            Order::Info {
                path: PathBuf::from("/a/disk.raw"),
            },
        )
        .is_ok());
        assert!(
            send(
                &orders,
                &reports,
                Order::Info {
                    path: PathBuf::from("/b/disk.raw"),
                },
            )
            .is_err(),
            "a second job is refused while one is in flight"
        );
        match said.try_recv() {
            Ok(Report::Finished { ok: false, said }) => {
                assert!(said.contains("already running"), "{said}")
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert!(received.try_recv().is_ok());
        assert!(
            received.try_recv().is_err(),
            "only the first order reached the job thread"
        );
        // The end of a job is what clears the flag: the next one is taken again.
        refuse(&reports, "done");
        assert!(send(
            &orders,
            &reports,
            Order::Info {
                path: PathBuf::from("/c/disk.raw"),
            },
        )
        .is_ok());
    }

    /// **A job says what it is before it works**: the title is what clears the log and opens the
    /// progress dialog, so every order has one — and it is a sentence, not the order's variant name.
    #[test]
    fn every_job_announces_itself_before_it_works() {
        let orders = [
            Order::Make {
                path: PathBuf::from("/a/disk.raw"),
                mib: DEFAULT_DISK_MIB,
                passphrase: "x".into(),
            },
            Order::Resize {
                path: PathBuf::from("/a/disk.raw"),
                mib: None,
                passphrase: None,
            },
            Order::Change {
                path: PathBuf::from("/a/disk.raw"),
                current: "x".into(),
                new: "y".into(),
            },
            Order::Info {
                path: PathBuf::from("/a/disk.raw"),
            },
        ];
        assert_eq!(orders[0].title(), "Making the disk");
        assert_eq!(orders[1].title(), "Resizing the disk");
        assert_eq!(orders[2].title(), "Changing the passphrase");
        assert_eq!(orders[3].title(), "Reading the disk");
    }

    /// The default path is the package's own disk folder — the same place the application looks and
    /// the settings name (`<package>/disks`, Settings: ).
    #[test]
    fn a_new_disk_lands_in_the_packages_own_disk_folder() {
        let path = default_new_disk();
        assert!(path.ends_with("disks/new.raw"), "{path:?}");
        assert!(!path.starts_with("/tmp"), "{path:?}");
    }
}
