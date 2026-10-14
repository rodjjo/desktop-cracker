//! **The media a run needs, and where it is looked for.**
//!
//! The search itself is the project's one search — `dc_common::media` — shared by the application
//! and by the disk tool, so a run from the repository, from a `make dist` package or from an
//! installed prefix finds the same files the same way. What is added here is the
//! part only the application has: the switches that override it.

use std::path::PathBuf;

use dc_cli::Cli;

/// The guest kernel: `--kernel`, then the project's own search.
pub fn kernel(cli: &Cli) -> PathBuf {
    cli.kernel.clone().unwrap_or_else(dc_common::media::kernel)
}

/// The guest's initramfs: `--initramfs`, then the project's own search.
pub fn initramfs(cli: &Cli) -> Option<PathBuf> {
    cli.initramfs.clone().or_else(dc_common::media::initramfs)
}

/// Firecracker: `DESK_FIRECRACKER` (the one environment variable this application has, and it
/// carries a **path**, never a credential), then the project's own search.
pub fn firecracker() -> PathBuf {
    dc_common::media::firecracker()
}
