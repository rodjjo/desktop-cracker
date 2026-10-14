//! The settings window: what the user edits, validated and saved the same way a
//! hand-edited file is.
//!
//! It is opened by the `numlock + F10` key (Display: "hide the window and show the
//! settings window"), and by the flow for a user who has no unlock password yet.
//!
//! The window is a **view over a draft**: `SettingsDraft` holds the whole
//! behaviour (add and remove shared folders with their tag and mode, choose the
//! root-folder, decide how much memory and how many vCPUs the guest gets, change
//! the unlock password), and it is validated by `dc-settings` and applied through
//! the tray.  Everything the window *does* is therefore testable without a
//! display; with `feature = "gui"` (which `make build` turns on) the GTK3 window
//! is the view, and without it the window reports that this build has none —
//! which is not fatal, because the settings file is the source of truth either
//! way.

pub use gui::SettingsWindow;

use dc_settings::{AdditionalDisk, Settings, ShareMode, SharedFolder};

/// The editable copy of the settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingsDraft {
    pub shared_folders: Vec<SharedFolder>,
    /// The additional disks: each one is attached to the microVM as a
    /// block device of its own and mounted by the user inside the guest.
    pub disks: Vec<AdditionalDisk>,
    pub root_disk: std::path::PathBuf,
    pub disk_folder: std::path::PathBuf,
    pub memory_mb: u32,
    pub vcpus: u32,
    pub display_width: u32,
    pub display_height: u32,
    pub balloon_automatic: bool,
    pub remote_x: bool,
    /// **`--host-network`**, as the settings hold it.
    pub host_network: bool,
    /// **The forward to the guest's sshd** (`ssh_port`): what the person typed in the window — a
    /// port, `0`, or nothing at all.  It is a *string* here and a port in the settings, because the
    /// window's answer has to survive being half-typed: `""` and `"0"` are both "off", and anything
    /// else is only a port when [`parse_ssh_port`] says so.
    pub ssh_port: String,
    /// **Was Save pressed?**  A window dismissed with Cancel (or its own close button) hands back
    /// the values it was given, so a caller that saved unconditionally would write a file that is
    /// exactly what it had — except for the one thing a draft cannot carry: a *change* the file
    /// gained while the window was open (a hand edit, another run).  `false` is "nothing was
    /// decided", and the caller writes nothing at all.
    pub saved: bool,
    /// A new password the user typed (`None` leaves the stored one alone, and
    /// `Some("")` clears it).
    pub new_password: Option<String>,
}

impl SettingsDraft {
    /// The draft for the settings on disk.
    pub fn from_settings(s: &Settings) -> SettingsDraft {
        SettingsDraft {
            shared_folders: s.shared_folders.clone(),
            disks: s.disks.clone(),
            root_disk: s.root_disk.clone(),
            disk_folder: s.disk_folder.clone(),
            memory_mb: s.memory_mb,
            vcpus: s.vcpus,
            display_width: s.display_width,
            display_height: s.display_height,
            balloon_automatic: s.balloon_automatic,
            remote_x: s.remote_x,
            host_network: s.host_network,
            ssh_port: s.ssh_port.map(|p| p.to_string()).unwrap_or_default(),
            saved: false,
            new_password: None,
        }
    }

    /// Add a shared folder, with a tag that does not collide with the ones
    /// already there (the guest mounts by tag, so two shares cannot share one).
    pub fn add_folder(&mut self, path: impl Into<std::path::PathBuf>, mode: ShareMode) -> &str {
        let mut folder = SharedFolder::new(path, mode);
        let base = folder.tag.clone();
        let mut n = 2;
        while self.shared_folders.iter().any(|f| f.tag == folder.tag) {
            folder.tag = format!("{base}-{n}");
            n += 1;
        }
        self.shared_folders.push(folder);
        self.shared_folders
            .last()
            .map(|f| f.tag.as_str())
            .unwrap_or_default()
    }

    pub fn remove_folder(&mut self, tag: &str) -> bool {
        let before = self.shared_folders.len();
        self.shared_folders.retain(|f| f.tag != tag);
        self.shared_folders.len() != before
    }

    pub fn set_folder_mode(&mut self, tag: &str, mode: ShareMode) -> bool {
        match self.shared_folders.iter_mut().find(|f| f.tag == tag) {
            Some(f) => {
                f.mode = mode;
                true
            }
            None => false,
        }
    }

    /// Add an **additional disk**, with a name that does not collide with the ones already
    /// there — the name is how the guest tells the disks apart (`desk-disk-mount open
    /// NAME`), so two of them cannot share one.
    pub fn add_disk(&mut self, path: impl Into<std::path::PathBuf>, mode: ShareMode) -> &str {
        let mut disk = AdditionalDisk::new(path, mode);
        let base = disk.tag.clone();
        let mut n = 2;
        while self.disks.iter().any(|d| d.tag == disk.tag) {
            disk.tag = format!("{base}-{n}");
            n += 1;
        }
        self.disks.push(disk);
        self.disks
            .last()
            .map(|d| d.tag.as_str())
            .unwrap_or_default()
    }

    pub fn remove_disk(&mut self, tag: &str) -> bool {
        let before = self.disks.len();
        self.disks.retain(|d| d.tag != tag);
        self.disks.len() != before
    }

    pub fn set_disk_mode(&mut self, tag: &str, mode: ShareMode) -> bool {
        match self.disks.iter_mut().find(|d| d.tag == tag) {
            Some(d) => {
                d.mode = mode;
                true
            }
            None => false,
        }
    }

    /// **Whether the root disk has to be made.**  A path with no disk behind it is a package that
    /// has not been used yet; an existing disk is the user's and is never touched (`create` does
    /// not overwrite).
    ///
    /// The window says so and nothing more: **the passphrase of a disk is never a setting**.  It is
    /// asked for in a question of its own when the disk is made (`dc_session::diskpass`), and it
    /// exists in memory for as long as the disk takes to build.
    pub fn root_disk_is_missing(&self) -> bool {
        !self.root_disk.as_os_str().is_empty() && !self.root_disk.exists()
    }

    /// **Was this draft saved?**  See [`SettingsDraft::saved`]: only Save sets it.
    pub fn was_saved(&self) -> bool {
        self.saved
    }

    /// The settings this draft describes.  The password is applied here, so the
    /// caller never has to remember to do it.
    pub fn to_settings(&self, current: &Settings) -> Result<Settings, dc_settings::SettingsError> {
        let mut s = current.clone();
        s.shared_folders = self.shared_folders.clone();
        s.disks = self.disks.clone();
        s.root_disk = self.root_disk.clone();
        s.disk_folder = self.disk_folder.clone();
        s.memory_mb = self.memory_mb;
        s.vcpus = self.vcpus;
        s.display_width = self.display_width;
        s.display_height = self.display_height;
        s.balloon_automatic = self.balloon_automatic;
        s.remote_x = self.remote_x;
        s.host_network = self.host_network;
        // **The port is validated here, where the person typed it**: `to_settings` is what the window
        // calls when Save is clicked, so a value it cannot use is refused the same way a memory size
        // outside the range is, and nothing is written.
        s.ssh_port = match parse_ssh_port(&self.ssh_port) {
            Ok(port) => port,
            Err(said) => return Err(dc_settings::SettingsError::Invalid(said)),
        };
        if let Some(password) = &self.new_password {
            s.set_password(if password.is_empty() {
                None
            } else {
                Some(password.as_str())
            })?;
        }
        s.validate()?;
        Ok(s)
    }

    /// A summary for the log and for the window's own status line.
    pub fn summary(&self) -> String {
        // Every disk this project makes is an encrypted one, so the summary says
        // where it is and nothing else.
        format!(
            "{} MiB, {} vCPU(s), root disk {}, {} shared folder(s), {} additional disk(s), \
             encrypted",
            self.memory_mb,
            self.vcpus,
            self.root_disk.display(),
            self.shared_folders.len(),
            self.disks.len(),
        )
    }
}

/// **The forward's port, as a field in the window.** this project's rule, and the only place it is
/// applied for the window: an empty field and `0` are the **same answer** — nothing is forwarded —
/// and any other number has to be one this process may bind ([`dc_settings::SSH_PORT_RANGE`]).
///
/// The sentence it returns is what the window shows, so it says the whole rule and not just "invalid".
pub fn parse_ssh_port(text: &str) -> Result<Option<u16>, String> {
    let text = text.trim();
    if text.is_empty() || text == "0" {
        return Ok(None);
    }
    let port: u16 = text.parse().map_err(|_| {
        format!("the ssh port {text:?} is not a port number; leave it empty for no forward")
    })?;
    if !dc_settings::SSH_PORT_RANGE.contains(&port) {
        return Err(format!(
            "the ssh port {port} is below {}; this application may not bind a privileged port, and \
             a host usually has its own service there.  Leave it empty for no forward",
            dc_settings::SSH_PORT_RANGE.start()
        ));
    }
    Ok(Some(port))
}

/// The settings window of a build with no GUI toolkit: it reports why it cannot
/// open, and the draft is still there for a caller that wants to edit the file
/// (`--show-settings` prints its path).
#[cfg(not(feature = "gui"))]
pub mod gui {
    use super::*;

    pub struct SettingsWindow {
        draft: std::sync::Mutex<SettingsDraft>,
    }

    impl SettingsWindow {
        pub fn new(current: Settings) -> SettingsWindow {
            SettingsWindow {
                draft: std::sync::Mutex::new(SettingsDraft::from_settings(&current)),
            }
        }

        pub fn draft(&self) -> SettingsDraft {
            self.draft.lock().unwrap().clone()
        }

        pub fn open(&self) -> Result<(), String> {
            Err(
                "this build has no GUI: build with the `gui` feature (which `make build` \
                 uses), or edit the settings file (`--show-settings` prints its path)"
                    .into(),
            )
        }
    }
}

/// The GTK3 settings window (the `gui` feature).
#[cfg(feature = "gui")]
pub mod gui {
    use super::*;
    use gtk::prelude::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// The window, as GTK sees it.  The widgets only *show* the draft and read
    /// it back on Save: the validation, the tags and the password all live in
    /// `SettingsDraft`.
    pub struct SettingsWindow {
        draft: Rc<RefCell<SettingsDraft>>,
    }

    impl SettingsWindow {
        pub fn new(current: Settings) -> SettingsWindow {
            SettingsWindow {
                draft: Rc::new(RefCell::new(SettingsDraft::from_settings(&current))),
            }
        }

        pub fn draft(&self) -> SettingsDraft {
            self.draft.borrow().clone()
        }

        /// Build and show the window.  Needs a display server.
        ///
        /// The layout is a **grid**, so every field's label lines up with every
        /// other's: a settings window is read top to bottom, and a column of
        /// labels with a column of values beside it is what makes that possible.
        /// Each section is a heading, its fields, and (for the shares) a list the
        /// user adds to and removes from.
        pub fn open(&self) -> Result<(), String> {
            if gtk::init().is_err() {
                return Err("no display server for the settings window".into());
            }
            let draft = self.draft.borrow().clone();

            let window = gtk::Window::new(gtk::WindowType::Toplevel);
            window.set_title(&format!("{} — settings", dc_common::APP_NAME));
            // **The window has a size a screen has.**  It was one long column of every subject,
            // which on a 1080-pixel screen was taller than the screen itself — the buttons at the
            // bottom were off it, and the settings could not be saved at all (the operator,
            // 2026-10-13).  So the subjects are **tabs**, the buttons are outside them, and every
            // tab scrolls rather than growing the window.
            window.set_default_size(760, 620);
            window.set_border_width(12);

            let outer = gtk::Box::new(gtk::Orientation::Vertical, 10);
            window.add(&outer);
            let tabs = gtk::Notebook::new();
            tabs.set_scrollable(true);
            outer.add(&tabs);

            // ------------------------------------------------------- the machine
            //
            // **The first tab is the machine and its root disk**, which is what a user meets on the
            // first run: the disk's path and, when there is no disk behind it, the passphrase it is
            // made with.  A window that opens for a missing disk opens on this tab.
            let machine_box = tab_body();
            tabs.append_page(&scrollable_page(&machine_box), Some(&tab_label("Machine")));
            machine_box.add(&heading("The microVM"));
            let grid = gtk::Grid::new();
            grid.set_row_spacing(6);
            grid.set_column_spacing(12);
            machine_box.add(&grid);

            let memory = gtk::SpinButton::with_range(128.0, 262_144.0, 256.0);
            memory.set_value(draft.memory_mb as f64);
            field(&grid, 0, "_Guest RAM (MiB)", &memory);

            // Up to 64 is what the settings file allows; the *default* is the host's cores
            // capped at twelve (see `dc_common::default_vcpus`), because giving the guest
            // every core of a many-core host makes its boot slower, not faster.
            let vcpus = gtk::SpinButton::with_range(1.0, 64.0, 1.0);
            vcpus.set_value(draft.vcpus as f64);
            field(&grid, 1, "v_CPUs", &vcpus);

            let note = gtk::Label::new(Some(
                "A process inside the guest may want a lot of memory; the balloon \
                 gives it back when it is idle.",
            ));
            note.set_xalign(0.0);
            note.set_line_wrap(true);
            grid.attach(&note, 1, 2, 1, 1);

            // ------------------------------------------------------ the root disk
            machine_box.add(&heading("Root disk"));
            let disk_grid = gtk::Grid::new();
            disk_grid.set_row_spacing(6);
            disk_grid.set_column_spacing(12);
            machine_box.add(&disk_grid);

            let disk = gtk::Entry::new();
            disk.set_text(&draft.root_disk.display().to_string());
            disk.set_hexpand(true);
            field(&disk_grid, 0, "Root disk _path", &disk);
            let browse = gtk::Button::with_label("Choose…");
            disk_grid.attach(&browse, 2, 0, 1, 1);
            {
                let disk = disk.clone();
                let window = window.clone();
                browse.connect_clicked(move |_| {
                    let chooser = gtk::FileChooserDialog::new(
                        Some("Choose the root disk"),
                        Some(&window),
                        gtk::FileChooserAction::Save,
                    );
                    chooser.add_button("Cancel", gtk::ResponseType::Cancel);
                    chooser.add_button("Choose", gtk::ResponseType::Accept);
                    if chooser.run() == gtk::ResponseType::Accept {
                        if let Some(path) = chooser.filename() {
                            disk.set_text(&path.display().to_string());
                        }
                    }
                    unsafe { chooser.destroy() };
                });
            }
            let disk_note = gtk::Label::new(Some(
                "**This root disk is the one the guest boots from**, and the userland this package \
                 carries is copied into it when it is made — that is what makes a guest come up on \
                 it.  **This window selects the disk; it does not hold its key**: the passphrase it \
                 is made with is asked for in a question of its own, twice, and kept in memory only, \
                 because no passphrase of any disk is ever a setting.  An existing disk is your own: \
                 nothing here overwrites one, and `desk-disk` is the tool that resizes or rekeys \
                 it.",
            ));
            disk_note.set_xalign(0.0);
            disk_note.set_line_wrap(true);
            disk_grid.attach(&disk_note, 1, 1, 2, 1);

            // --------------------------------------------------- shared folders
            let shares_tab = tab_body();
            tabs.append_page(
                &scrollable_page(&shares_tab),
                Some(&tab_label("Shared folders")),
            );
            let shares_frame = gtk::Frame::new(None);
            shares_frame.set_shadow_type(gtk::ShadowType::In);
            let shares_box = gtk::Box::new(gtk::Orientation::Vertical, 6);
            shares_box.set_border_width(8);
            shares_frame.add(&shares_box);
            shares_tab.add(&shares_frame);

            let list = gtk::ListBox::new();
            list.set_selection_mode(gtk::SelectionMode::None);
            shares_box.add(&list);
            for (i, folder) in draft.shared_folders.iter().enumerate() {
                let _ = i;
                list.add(&share_row(folder));
            }
            if draft.shared_folders.is_empty() {
                let empty = gtk::Label::new(Some(
                    "No shared folder: the guest has nothing of this host's mounted.",
                ));
                empty.set_xalign(0.0);
                shares_box.add(&empty);
            }

            let buttons = gtk::Box::new(gtk::Orientation::Horizontal, 6);
            let add_folder = gtk::Button::with_label("Add folder…");
            let remove_folder = gtk::Button::with_label("Remove the last one");
            buttons.add(&add_folder);
            buttons.add(&remove_folder);
            shares_box.add(&buttons);
            {
                // Adding asks for the folder and its access mode, which is what
                // the settings file stores: a path, a tag and RW/RO.
                let list = list.clone();
                let draft_rc = self.draft.clone();
                let window = window.clone();
                add_folder.connect_clicked(move |_| {
                    let chooser = gtk::FileChooserDialog::new(
                        Some("Choose a folder to share"),
                        Some(&window),
                        gtk::FileChooserAction::SelectFolder,
                    );
                    chooser.add_button("Cancel", gtk::ResponseType::Cancel);
                    chooser.add_button("Share", gtk::ResponseType::Accept);
                    if chooser.run() != gtk::ResponseType::Accept {
                        unsafe { chooser.destroy() };
                        return;
                    }
                    let Some(path) = chooser.filename() else {
                        unsafe { chooser.destroy() };
                        return;
                    };
                    unsafe { chooser.destroy() };
                    let folder = {
                        let mut d = draft_rc.borrow_mut();
                        let tag = d.add_folder(path.clone(), ShareMode::Ro).to_string();
                        d.shared_folders
                            .iter()
                            .find(|f| f.tag == tag)
                            .cloned()
                            .unwrap_or_else(|| d.shared_folders.last().cloned().unwrap())
                    };
                    list.add(&share_row(&folder));
                    list.show_all();
                });
            }
            {
                let list = list.clone();
                let draft_rc = self.draft.clone();
                remove_folder.connect_clicked(move |_| {
                    let last = {
                        let mut d = draft_rc.borrow_mut();
                        d.shared_folders.pop()
                    };
                    if last.is_some() {
                        if let Some(row) = list.children().last() {
                            list.remove(row);
                        }
                    }
                });
            }

            // ------------------------------------------------ additional disks
            let disks_tab = tab_body();
            tabs.append_page(
                &scrollable_page(&disks_tab),
                Some(&tab_label("Additional disks")),
            );
            let disks_frame = gtk::Frame::new(None);
            disks_frame.set_shadow_type(gtk::ShadowType::In);
            let disks_box = gtk::Box::new(gtk::Orientation::Vertical, 6);
            disks_box.set_border_width(8);
            disks_frame.add(&disks_box);
            disks_tab.add(&disks_frame);

            let disk_list = gtk::ListBox::new();
            disk_list.set_selection_mode(gtk::SelectionMode::None);
            disks_box.add(&disk_list);
            for disk in draft.disks.iter() {
                disk_list.add(&disk_row(disk));
            }
            if draft.disks.is_empty() {
                let empty = gtk::Label::new(Some(
                    "No additional disk: the guest has only its root disk.",
                ));
                empty.set_xalign(0.0);
                disks_box.add(&empty);
            }
            let disk_note = gtk::Label::new(Some(
                "Each disk is attached to the microVM as a block device of its own (/dev/vdb, \
                 /dev/vdc, …) and nothing else: it is not mounted for you, and whether it is \
                 an encrypted container or a plain filesystem makes no difference here. \
                 Inside the guest, `desk-disk-mount` lists them and mounts one (`open \
                 NAME`), asking for its password when it is a LUKS container.",
            ));
            disk_note.set_xalign(0.0);
            disk_note.set_line_wrap(true);
            disks_box.add(&disk_note);

            let disk_buttons = gtk::Box::new(gtk::Orientation::Horizontal, 6);
            let add_disk = gtk::Button::with_label("Add disk…");
            let remove_disk = gtk::Button::with_label("Remove the last one");
            disk_buttons.add(&add_disk);
            disk_buttons.add(&remove_disk);
            disks_box.add(&disk_buttons);
            {
                // Adding a disk asks the user for a file: the settings store its path, its
                // access mode and its name (`AdditionalDisk`).
                let list = disk_list.clone();
                let draft_rc = self.draft.clone();
                let window = window.clone();
                add_disk.connect_clicked(move |_| {
                    let chooser = gtk::FileChooserDialog::new(
                        Some("Choose a disk image to attach"),
                        Some(&window),
                        gtk::FileChooserAction::Open,
                    );
                    chooser.add_button("Cancel", gtk::ResponseType::Cancel);
                    chooser.add_button("Attach", gtk::ResponseType::Accept);
                    if chooser.run() != gtk::ResponseType::Accept {
                        unsafe { chooser.destroy() };
                        return;
                    }
                    let Some(path) = chooser.filename() else {
                        unsafe { chooser.destroy() };
                        return;
                    };
                    unsafe { chooser.destroy() };
                    let disk = {
                        let mut d = draft_rc.borrow_mut();
                        let tag = d.add_disk(path.clone(), ShareMode::Rw).to_string();
                        d.disks
                            .iter()
                            .find(|x| x.tag == tag)
                            .cloned()
                            .unwrap_or_else(|| d.disks.last().cloned().unwrap())
                    };
                    list.add(&disk_row(&disk));
                    list.show_all();
                });
            }
            {
                let list = disk_list.clone();
                let draft_rc = self.draft.clone();
                remove_disk.connect_clicked(move |_| {
                    let last = {
                        let mut d = draft_rc.borrow_mut();
                        d.disks.pop()
                    };
                    if last.is_some() {
                        if let Some(row) = list.children().last() {
                            list.remove(row);
                        }
                    }
                });
            }

            // -------------------------------------- the password and the network
            //
            // One tab, because they are the same kind of thing: what the *user* controls about the
            // session and about what the guest may reach — not what the machine is made of.
            let session_tab = tab_body();
            tabs.append_page(
                &scrollable_page(&session_tab),
                Some(&tab_label("Password & network")),
            );
            session_tab.add(&heading("Unlock password"));
            let pass_grid = gtk::Grid::new();
            pass_grid.set_row_spacing(6);
            pass_grid.set_column_spacing(12);
            session_tab.add(&pass_grid);
            let password = gtk::Entry::new();
            password.set_visibility(false);
            password.set_placeholder_text(Some("leave empty to keep the current one"));
            password.set_hexpand(true);
            field(&pass_grid, 0, "_New password", &password);
            let pass_note = gtk::Label::new(Some(
                "It is asked for — with the current one — when you save a change, and it \
                 is needed to show the window again after it is hidden to the tray. \
                 Changing it takes effect the next time the application starts.",
            ));
            pass_note.set_xalign(0.0);
            pass_note.set_line_wrap(true);
            pass_grid.attach(&pass_note, 1, 1, 1, 1);

            // ------------------------------------------------- the guest's network
            session_tab.add(&heading("The guest's network"));
            let network_grid = gtk::Grid::new();
            network_grid.set_row_spacing(6);
            network_grid.set_column_spacing(12);
            session_tab.add(&network_grid);
            let host_network = gtk::CheckButton::with_label("Let the guest reach this computer");
            host_network.set_active(draft.host_network);
            field(&network_grid, 0, "_Host network", &host_network);
            let network_note = gtk::Label::new(Some(
                "Off: the host's own services are not the guest's to reach.  On: the name \
                 `parenthost` resolves to the guest's gateway, and a connection to that address \
                 is carried to this computer's 127.0.0.1.  `--host-network` says the same thing \
                 for one run.",
            ));
            network_note.set_xalign(0.0);
            network_note.set_line_wrap(true);
            network_grid.attach(&network_note, 1, 1, 1, 1);

            // **The door the other way**: the host reaching *into* the guest (`ssh_port`).  It is a
            // field and not a switch because it names a port, and the empty field is a real answer —
            // it means "no forward", which is what the run has without it.
            let ssh = gtk::Entry::new();
            ssh.set_text(&draft.ssh_port);
            ssh.set_placeholder_text(Some("empty: no forward"));
            ssh.set_width_chars(8);
            ssh.set_max_width_chars(8);
            field(&network_grid, 2, "_SSH port", &ssh);
            let ssh_note = gtk::Label::new(Some(
                "The host's own 127.0.0.1 port carried to the guest's sshd (port 22 inside, \
                 user `deskuser`): `ssh -p 2223 deskuser@127.0.0.1`. Leave it empty — or 0 — \
                 for no forward at all, which is what the guest's sshd has without one.  A port \
                 below 1024 is refused: this application may not bind a privileged port.  \
                 `--ssh-port` says the same thing for one run.",
            ));
            ssh_note.set_xalign(0.0);
            ssh_note.set_line_wrap(true);
            network_grid.attach(&ssh_note, 1, 3, 1, 1);

            // ------------------------------------------------------- the buttons
            // **The buttons are outside the tabs**, so they are on screen whichever tab is open and
            // whatever a tab's list has grown to.
            let actions = gtk::Box::new(gtk::Orientation::Horizontal, 8);
            actions.set_halign(gtk::Align::End);
            let cancel = gtk::Button::with_label("Cancel");
            let save = gtk::Button::with_label("Save");
            // **Return saves**, which is what a window with two buttons answers everywhere else:
            // `Save` is the window's default widget, so Enter in any entry of it saves the settings
            // instead of doing nothing.  Closing the window with its own button is still a cancel.
            save.set_can_default(true);
            window.set_default(Some(&save));
            actions.add(&cancel);
            actions.add(&save);
            outer.add(&actions);

            // **`destroy()` and then out of the GTK loop.**  `gtk::main()` returns only when
            // it is told to (`gtk::main_quit`), and a window that is merely destroyed leaves
            // the loop running: the thread stayed inside `open()` for the life of the
            // application, so the `Save` that was clicked was never read back and the
            // settings could never be opened a second time (measured — the operator's
            // report, both halves of it).
            let w = window.clone();
            cancel.connect_clicked(move |_| {
                unsafe { w.destroy() };
                gtk::main_quit();
            });

            let w = window.clone();
            let draft_rc = self.draft.clone();
            save.connect_clicked(move |_| {
                // Read the widgets back into the draft; the caller applies it.  **The disk's
                // passphrase is not among them**: it is a question, asked below when the disk is
                // made, and it never becomes a setting.
                let mut d = draft_rc.borrow_mut();
                d.memory_mb = memory.value() as u32;
                d.vcpus = vcpus.value() as u32;
                let text = disk.text().to_string();
                if !text.is_empty() {
                    d.root_disk = std::path::PathBuf::from(text);
                }
                let secret = password.text().to_string();
                d.new_password = if secret.is_empty() {
                    None
                } else {
                    Some(secret)
                };
                d.host_network = host_network.is_active();
                d.ssh_port = ssh.text().to_string();
                d.saved = true;
                // **The disk this path has not got yet.**  The question that follows is the
                // caller's (`dc_session` owns the disk's questions and the disk path itself), so
                // this window closes first and the question is asked over the window the run has;
                // the run makes the disk and continues from it.
                unsafe { w.destroy() };
                // And out of the GTK loop, so the caller reads the draft back and saves it.
                gtk::main_quit();
            });

            // Closing the window with its own close button is a **cancel**, and it too has to
            // leave the loop.
            let w = window.clone();
            window.connect_delete_event(move |_, _| {
                gtk::main_quit();
                unsafe { w.destroy() };
                // Let the default handler run as well (the window is already destroyed).
                false.into()
            });

            // **Centered and in front before it is shown** (`dc-ui`): the settings window is one
            // of the application's windows, every one of them arrives in the middle of the screen,
            // and the guest's own window is a full-screen one of ours — a settings window behind
            // it is a settings window the user cannot see.
            dc_ui::bring_to_front(&window);
            window.show_all();
            // **The keyboard is the settings window's while it is open**
            // (`dc_ui::hold_keyboard_for_guest`): the display window holds the keyboard for the
            // guest, and an entry or a spin button in this window cannot be used while that grab is
            // held.  `gtk::main()` runs the display loop's own tick while it runs, which is why the
            // question is counted (`dc_ui::question_is_up`) rather than only released here.
            dc_ui::hold_keyboard_for_guest(gtk::main);
            Ok(())
        }
    }

    /// One shared folder, as a row the user can read and remove.
    fn share_row(folder: &SharedFolder) -> gtk::Box {
        let row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let path = gtk::Label::new(Some(&folder.path.display().to_string()));
        path.set_xalign(0.0);
        path.set_ellipsize(gtk::pango::EllipsizeMode::Middle);
        path.set_hexpand(true);
        row.add(&path);

        let tag = gtk::Label::new(Some(&format!("tag {}", folder.tag)));
        tag.set_xalign(0.0);
        row.add(&tag);

        let mode = gtk::ComboBoxText::new();
        mode.append(Some("ro"), "Read-only");
        mode.append(Some("rw"), "Read-write");
        mode.set_active_id(Some(if folder.mode.is_read_only() {
            "ro"
        } else {
            "rw"
        }));
        row.add(&mode);
        row
    }

    /// A row of the additional-disks list: the image, the name the guest will see and the
    /// access mode it is attached with.
    fn disk_row(disk: &AdditionalDisk) -> gtk::Box {
        let row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let path = gtk::Label::new(Some(&disk.path.display().to_string()));
        path.set_xalign(0.0);
        path.set_ellipsize(gtk::pango::EllipsizeMode::Middle);
        path.set_hexpand(true);
        row.add(&path);

        let tag = gtk::Label::new(Some(&format!("name {}", disk.tag)));
        tag.set_xalign(0.0);
        row.add(&tag);

        let mode = gtk::ComboBoxText::new();
        mode.append(Some("ro"), "Read-only");
        mode.append(Some("rw"), "Read-write");
        mode.set_active_id(Some(if disk.mode.is_read_only() { "ro" } else { "rw" }));
        row.add(&mode);
        row
    }

    /// One tab's body: a vertical box with a margin, holding that subject's fields.
    fn tab_body() -> gtk::Box {
        let body = gtk::Box::new(gtk::Orientation::Vertical, 14);
        body.set_border_width(12);
        body
    }

    /// A tab's label, which is the tab's name.
    fn tab_label(text: &str) -> gtk::Label {
        gtk::Label::new(Some(text))
    }

    /// **A tab that scrolls instead of growing the window.**  A settings window taller than the
    /// screen is a settings window whose Save button cannot be reached, so a tab is allowed to be at
    /// most `MAX_TAB_HEIGHT` tall and the rest of it is scrolled to.  The width is the window's: a
    /// settings window that scrolled sideways would hide fields.
    fn scrollable_page(body: &gtk::Box) -> gtk::ScrolledWindow {
        let scroll = gtk::ScrolledWindow::new(gtk::Adjustment::NONE, gtk::Adjustment::NONE);
        scroll.set_policy(gtk::PolicyType::Never, gtk::PolicyType::Automatic);
        // The window follows the tab's own height up to the limit, and not the other way round: a
        // short tab makes a short window.
        scroll.set_propagate_natural_height(true);
        scroll.set_max_content_height(MAX_TAB_HEIGHT);
        scroll.add(body);
        scroll
    }

    /// How tall one tab may make the window (pixels), before it starts scrolling.
    const MAX_TAB_HEIGHT: i32 = 480;

    /// A section heading: what the fields under it are about.
    fn heading(text: &str) -> gtk::Label {
        let label = gtk::Label::new(Some(text));
        label.set_xalign(0.0);
        label.set_markup(&format!("<b>{text}</b>"));
        label
    }

    /// A labelled field, in the grid: the label in column 0, the widget in
    /// column 1 — which is what lines every field up with every other.
    ///
    /// The label carries a **mnemonic** (`_Path` is `Alt+P`), and the mnemonic points at the widget
    /// it names: a settings window is a thing a person fills in, and reaching a field from the
    /// keyboard is what makes the rest of it reachable too.
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
}
#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> Settings {
        Settings::default()
    }

    /// **A package that has never been used**: the settings' own path has no disk behind it, and
    /// that is what the window offers to make.  An existing disk is the user's — nothing offers to
    /// write over it (which is also what `dc-fc-disk::create_root_disk` refuses).
    #[test]
    fn a_missing_root_disk_is_the_one_that_gets_made() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = SettingsDraft::from_settings(&settings());
        d.root_disk = dir.path().join("root.raw");
        assert!(d.root_disk_is_missing());
        assert!(dc_fc_disk::creatable(&d.root_disk));

        std::fs::write(&d.root_disk, b"a disk the user already has").unwrap();
        assert!(!d.root_disk_is_missing());
        assert!(!dc_fc_disk::creatable(&d.root_disk));
        assert!(
            !dc_fc_disk::creatable(&d.root_disk),
            "a disk that is there is the user's: nothing offers to make one"
        );
        // And the window's own path is never a job's target: `create_root_disk` refuses a file that
        // is already there, whatever a caller believed.
        assert!(dc_fc_disk::create_root_disk(&d.root_disk, 1, "hunter2").is_err());
        assert_eq!(
            std::fs::read(&d.root_disk).unwrap(),
            b"a disk the user already has"
        );
    }

    /// **The ssh forward's port, as the window holds it**: an empty field and `0` are the same
    /// answer (nothing is forwarded), a port this process may bind is kept, and a privileged one is
    /// refused with a sentence — the same rule `dc-settings` applies to the file, applied where the
    /// person typed it.
    #[test]
    fn the_ssh_port_field_is_off_when_empty_or_zero_and_refuses_a_privileged_one() {
        assert_eq!(parse_ssh_port("").unwrap(), None, "empty is off");
        assert_eq!(parse_ssh_port("   ").unwrap(), None, "and so is whitespace");
        assert_eq!(parse_ssh_port("0").unwrap(), None, "and so is 0");
        assert_eq!(
            parse_ssh_port(" 2223 ").unwrap(),
            Some(2223),
            "a port is a port"
        );
        assert_eq!(
            parse_ssh_port("65535").unwrap(),
            Some(65535),
            "the last one"
        );
        for bad in ["22", "80", "1023", "65536", "-1", "abc", "22a"] {
            let refused = parse_ssh_port(bad);
            assert!(refused.is_err(), "{bad:?} was accepted as a port");
            assert!(
                refused.unwrap_err().contains("empty"),
                "{bad:?} should say what to do instead"
            );
        }
    }

    /// And the field reaches the settings, as the number and not as the text: a saved window's
    /// `ssh_port` is a port, `None` when the field is empty, and the round trip through the file
    /// keeps it.
    #[test]
    fn the_ssh_port_the_window_saves_is_the_settings_own() {
        let s = settings();
        let mut d = SettingsDraft::from_settings(&s);
        d.ssh_port = "2223".into();
        assert_eq!(d.to_settings(&s).unwrap().ssh_port, Some(2223));
        d.ssh_port = String::new();
        assert_eq!(d.to_settings(&s).unwrap().ssh_port, None);
        d.ssh_port = "0".into();
        assert_eq!(
            d.to_settings(&s).unwrap().ssh_port,
            None,
            "0 is the same answer"
        );
        d.ssh_port = "22".into();
        assert!(d.to_settings(&s).is_err(), "a privileged port is not saved");
        // And back: the settings' port is what the field shows.
        let mut on = s.clone();
        on.ssh_port = Some(2222);
        assert_eq!(SettingsDraft::from_settings(&on).ssh_port, "2222");
        assert_eq!(SettingsDraft::from_settings(&s).ssh_port, "");

        // **The file is the record**, not the draft: what a person saves is what a run reads.
        // (A `tempfile` directory of this test's own, never the system's temp directory.)
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yml");
        let mut d = SettingsDraft::from_settings(&s);
        d.ssh_port = "2223".into();
        let saved = d.to_settings(&s).unwrap();
        saved.save_to(&path).unwrap();
        let read_back = dc_settings::Settings::load_from(&path, false).unwrap();
        assert_eq!(read_back.ssh_port, Some(2223));
        assert!(std::fs::read_to_string(&path)
            .unwrap()
            .contains("ssh_port: 2223"));
    }

    /// **A disk's passphrase is not a setting**: the draft a window hands back carries the path and
    /// nothing secret, so what reaches the settings file cannot be a key even by accident.
    #[test]
    fn the_settings_a_window_saves_hold_no_passphrase() {
        let s = settings();
        let mut d = SettingsDraft::from_settings(&s);
        d.root_disk = std::path::PathBuf::from("/srv/disks/root.raw");
        d.new_password = Some("an-unlock-password".into());
        let written = d.to_settings(&s).unwrap();
        let text = serde_yaml::to_string(&written).unwrap();
        assert!(text.contains("/srv/disks/root.raw"), "{text}");
        // The unlock password is the one secret this file may hold, and only as a salted hash.
        assert!(text.contains("pbkdf2-sha256$"), "{text}");
        assert!(!text.contains("an-unlock-password"), "{text}");
        assert!(!text.contains("hunter2"), "{text}");
        assert!(!text.contains("disk_passphrase"), "{text}");
    }

    #[test]
    fn a_draft_round_trips_the_settings_it_came_from() {
        let s = settings();
        let d = SettingsDraft::from_settings(&s);
        assert_eq!(d.to_settings(&s).unwrap().memory_mb, s.memory_mb);
        assert_eq!(d.shared_folders, s.shared_folders);
        assert!(d.summary().contains("MiB"));
    }

    #[test]
    fn adding_folders_gives_each_one_a_distinct_tag() {
        let mut d = SettingsDraft::from_settings(&settings());
        let first = d.add_folder("/tmp/same", ShareMode::Rw).to_string();
        let second = d.add_folder("/tmp/same", ShareMode::Ro).to_string();
        assert_ne!(first, second, "two shares must not share a mount tag");
        let third = d.add_folder("/tmp/same", ShareMode::Rw).to_string();
        assert_ne!(second, third);
        assert_eq!(d.shared_folders.len(), 3);
    }

    #[test]
    fn removing_and_switching_a_folder() {
        let mut d = SettingsDraft::from_settings(&settings());
        let tag = d.add_folder("/tmp/x", ShareMode::Rw).to_string();
        assert!(d.set_folder_mode(&tag, ShareMode::Ro));
        assert!(d.shared_folders[0].mode.is_read_only());
        assert!(d.remove_folder(&tag));
        assert!(d.shared_folders.is_empty());
        assert!(
            !d.remove_folder(&tag),
            "removing twice is not an error, just false"
        );
        assert!(!d.set_folder_mode("nope", ShareMode::Ro));
    }

    #[test]
    fn the_memory_the_guest_gets_is_what_the_window_edits() {
        // A process inside the guest can want a lot of memory, so the machine's
        // RAM is a setting the user owns.
        let s = settings();
        let mut d = SettingsDraft::from_settings(&s);
        d.memory_mb = 8192;
        d.vcpus = 8;
        let out = d.to_settings(&s).unwrap();
        assert_eq!(out.memory_mb, 8192);
        assert_eq!(out.vcpus, 8);
    }

    #[test]
    fn the_password_change_is_part_of_the_same_save() {
        let mut s = settings();
        s.set_password(Some("old")).unwrap();
        let mut d = SettingsDraft::from_settings(&s);
        // unchanged by default
        let out = d.to_settings(&s).unwrap();
        assert!(out.verify_password("old"));

        // a new one
        d.new_password = Some("new".into());
        let out = d.to_settings(&s).unwrap();
        assert!(out.verify_password("new"));
        assert!(!out.verify_password("old"));

        // and clearing it
        d.new_password = Some(String::new());
        let out = d.to_settings(&s).unwrap();
        assert!(!out.has_password());
    }

    #[test]
    fn an_impossible_draft_is_refused_before_anything_is_written() {
        let s = settings();
        let mut d = SettingsDraft::from_settings(&s);
        d.memory_mb = 16; // below the kernel's boot floor
        assert!(d.to_settings(&s).is_err());
        d.memory_mb = 1024;
        d.vcpus = 0;
        assert!(d.to_settings(&s).is_err());
    }

    #[test]
    fn the_root_disk_is_editable() {
        let s = settings();
        let mut d = SettingsDraft::from_settings(&s);
        d.root_disk = "/srv/desktop-cracker/root.raw".into();
        assert_eq!(
            d.to_settings(&s).unwrap().root_disk,
            std::path::PathBuf::from("/srv/desktop-cracker/root.raw")
        );
    }

    /// **The additional disks are a list the user adds to and removes from**, exactly as the
    /// shared folders are — and each one carries the name the guest will see.
    #[test]
    fn additional_disks_are_added_and_removed_by_name() {
        let s = settings();
        let mut d = SettingsDraft::from_settings(&s);
        assert!(d.disks.is_empty());

        // A name is derived from the image and made unique, because it is how the guest tells
        // the disks apart (`desk-disk-mount open NAME`).
        let first = d.add_disk("/srv/data.raw", ShareMode::Rw).to_string();
        let second = d.add_disk("/srv/other/data.raw", ShareMode::Rw).to_string();
        assert_eq!(first, "data");
        assert_eq!(second, "data-2", "the second 'data' gets a name of its own");

        assert!(d.set_disk_mode("data", ShareMode::Ro));
        assert!(!d.set_disk_mode("nope", ShareMode::Ro));

        let out = d.to_settings(&s).unwrap();
        assert_eq!(out.disks.len(), 2);
        assert_eq!(out.disks[0].tag, "data");
        assert!(out.disks[0].mode.is_read_only());
        assert_eq!(out.disks[1].tag, "data-2");

        assert!(d.remove_disk("data"));
        assert!(!d.remove_disk("data"));
        assert_eq!(d.to_settings(&s).unwrap().disks.len(), 1);
        // The window's own summary says how many there are, which is what the log prints.
        assert!(
            d.summary().contains("1 additional disk(s)"),
            "{}",
            d.summary()
        );
    }
}
