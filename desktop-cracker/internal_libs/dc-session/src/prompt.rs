//! The application's questions to the user, on the terminal.
//!
//! The asking itself is `dc-dialog`'s (it is the same question the graphical dialog
//! asks, with the terminal as the fallback); this module is the name the application
//! uses for it, so a call site reads the same as before.

#[allow(unused_imports)]
pub use dc_dialog::prompt::{ask_line, ask_password, ask_password_twice};
