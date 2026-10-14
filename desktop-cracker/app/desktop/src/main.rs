//! **`desktop-cracker`**: the application, and the microVM it runs.
//!
//! The machine is a **Firecracker** microVM, defined over its own API (`fc_run`), and every device
//! its guest has is a **channel this process serves** over vsock.  A hypervisor of this kind has no
//! display device, no sound card, no 9P, no input device, no disk encryption and no ACPI, so each of
//! those is this project's own work rather than a device definition:
//!
//! | what the guest gets | how |
//! |---|---|
//! | the machine | Firecracker's API (`fc_run::start`) |
//! | the screen | the display channel (53000) and `dc-fc-window` |
//! | the keyboard and the pointer | the same channel's frames, written to `uinput` in the guest |
//! | the network | the network channel (59000): the guest's own `tun0`, no tap, no sudo |
//! | the shared folders | the shares' service (54000) and the guest's FUSE mount |
//! | the sound | the sound channel (55000) and the guest's `snd-aloop` card |
//! | the encrypted root disk | the control share (56000), opened **by the guest** |
//! | the screen's own framebuffer | the guest's kernel module (`guest-kernel/`, `/dev/fb0`) |
//! | ending the run | the shutdown channel (57000): the guest reboots, Firecracker exits |
//! | remote X | the host's own X server, on port 1026, over Firecracker's unix socket |
//!
//! The run's own order: settings → plugin → the window and the disk's question → the machine → the
//! guest's landmark → run → clean shutdown.

use anyhow::Result;

mod media;
mod plugin;
mod run;

fn main() {
    if let Err(e) = try_main() {
        eprintln!("desktop-cracker: {e:#}");
        std::process::exit(1);
    }
}

fn try_main() -> Result<()> {
    let cli = dc_cli::parse_env().map_err(|e| anyhow::anyhow!("{e}"))?;
    if cli.help {
        print!("{}", dc_cli::USAGE);
        return Ok(());
    }
    if cli.version {
        println!("desktop-cracker {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    run::run(cli)
}
