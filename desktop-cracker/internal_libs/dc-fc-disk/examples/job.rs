//! **A disk job, by hand**: what `desk-disk create`/`info`/`resize`/`change-pass` will
//! drive, run against a real Firecracker and the project's own guest.
//!
//! ```text
//! cd desktop-cracker
//! cargo run --release --example job -- \
//!     --firecracker ../temp/fc-study/bin/firecracker \
//!     --kernel      download/kernel \
//!     --initramfs   ../download/initramfs.gz \
//!     --image       ../temp/migtest/disk.raw --size-mb 1024 create
//! ```
//!
//! The guest is the project's **own** initramfs: its init reads the job off the kernel
//! command line (`desk.diskjob=…`) and runs `guest-tools diskmgr`, which is exactly what
//! the machine this project started with does.  What differs is only how the pieces are attached (`dc-fc-disk`'s own
//! documentation has that table).

use std::path::PathBuf;
use std::time::Duration;

use dc_disk_manager::{DiskJob, Job};
use dc_fc_disk::{image, DiskRun};

const USAGE: &str = "job --firecracker PATH --kernel PATH --initramfs PATH --image PATH \
                     [--seed-image PATH] [--password P] [--new-password P] [--size-mb N] \
                     [--timeout SECONDS] create|info|resize|change-pass";

fn main() {
    let mut args = std::env::args().skip(1);
    let mut firecracker = PathBuf::new();
    let mut kernel = PathBuf::new();
    let mut initramfs = PathBuf::new();
    let mut image = PathBuf::new();
    let mut seed_image = None;
    let mut password = None;
    let mut new_password = None;
    let mut size_mb = None;
    let mut timeout = 600u64;
    let mut command = String::new();
    while let Some(arg) = args.next() {
        let mut value = || args.next().unwrap_or_default();
        match arg.as_str() {
            "--firecracker" => firecracker = value().into(),
            "--kernel" => kernel = value().into(),
            "--initramfs" => initramfs = value().into(),
            "--image" => image = value().into(),
            "--seed-image" => seed_image = Some(PathBuf::from(value())),
            "--password" => password = Some(value()),
            "--new-password" => new_password = Some(value()),
            "--size-mb" => size_mb = value().parse().ok(),
            "--timeout" => timeout = value().parse().unwrap_or(600),
            other => command = other.to_string(),
        }
    }
    if command.is_empty() || image.as_os_str().is_empty() {
        eprintln!("{USAGE}");
        std::process::exit(2);
    }

    // The image is made and grown on the **host**: a raw file's size is its size, and no image
    // tool is involved.
    if let Some(mb) = size_mb {
        if !image.exists() {
            image::create_raw(&image, mb).expect("making the image");
            println!("made {} ({} MiB)", image.display(), mb);
        } else {
            image::resize_raw(&image, mb).expect("growing the image");
            println!("grew {} to {} MiB", image.display(), mb);
        }
    }

    let job = match command.as_str() {
        "create" => DiskJob::new(Job::CreateLuks, &image)
            .with_password(password.clone().unwrap_or_default()),
        "info" => DiskJob::new(Job::Info, &image),
        "resize" => {
            let mut job = DiskJob::new(Job::Resize, &image);
            if let Some(p) = &password {
                job = job.with_password(p.clone());
            }
            job
        }
        "change-pass" => DiskJob::new(Job::ChangePassword, &image)
            .with_password(password.clone().unwrap_or_default())
            .with_new_password(new_password.clone().unwrap_or_default()),
        other => {
            eprintln!("unknown command {other:?}\n{USAGE}");
            std::process::exit(2);
        }
    };
    let job = match seed_image {
        Some(seed) => job.with_seed_image(seed),
        None => job,
    };

    let run = DiskRun {
        kernel,
        initramfs,
        firecracker,
        run_dir: std::env::temp_dir().join(format!("desk-disk-{}", std::process::id())),
        timeout: Duration::from_secs(timeout),
        ..DiskRun::default()
    };

    match run.run(&job) {
        Ok(result) => {
            for line in &result.lines {
                println!("{line}");
            }
            println!(
                "{}: {} in {:.1}s",
                command,
                if result.ok { "OK" } else { "FAILED" },
                result.took.as_secs_f64()
            );
            if !result.ok {
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("job: {e}");
            std::process::exit(1);
        }
    }
}
