//! **The framebuffer's control node**: the module's own numbers (`guest-kernel/desk_fb.h`) and
//! the mapping the guest reads its screen through.
//!
//! The module publishes the geometry the run decided, and `/dev/desk_fb-fb` is what the agent
//! opens: `HFB_GET_INFO` says how big the screen is, and `mmap` gives the pixels — the same mapping
//! Xorg's fbdev driver draws into, which is why the agent compares memory instead of asking for
//! damage.

use std::os::fd::OwnedFd;

/// `/dev/desk_fb-fb`: the control node the module creates.
pub const CONTROL: &str = "/dev/desk_fb-fb";

/// What the screen is, as the module publishes it.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Info {
    pub width: u32,
    pub height: u32,
    pub bpp: u32,
    pub stride: u32,
    pub size: u32,
}

/// `_IOR('H', 0x01, struct desk_fb_info)` — the module's own request number.
pub const HFB_GET_INFO: libc::c_ulong = ior(0x01, std::mem::size_of::<Info>());
/// `_IOR('H', 0x02, struct desk_fb_damage)`.
pub const HFB_GET_DAMAGE: libc::c_ulong = ior(0x02, 12);
/// `_IO('H', 0x03)`.
pub const HFB_WAIT: libc::c_ulong = 0x4803;
/// `_IO('H', 0x04)`.
pub const HFB_FORGET: libc::c_ulong = 0x4804;

/// The kernel's own `_IOR` (`linux/ioctl.h`): direction, size and type packed into a number.
const fn ior(number: u32, size: usize) -> libc::c_ulong {
    ((2u32 << 30) | ((size as u32) << 16) | ((b'H' as u32) << 8) | number) as libc::c_ulong
}

/// The framebuffer's control node, opened and mapped.
pub struct Framebuffer {
    pub fd: OwnedFd,
    pub info: Info,
}

impl Framebuffer {
    /// Open the control node and ask it what the screen is.
    pub fn open() -> std::io::Result<Framebuffer> {
        let file = std::fs::OpenOptions::new().read(true).write(true).open(CONTROL)?;
        let fd: OwnedFd = file.into();
        let mut info = Info::default();
        // SAFETY: the fd is the module's control node and `info` is the structure it fills.
        let rc = unsafe { libc::ioctl(std::os::fd::AsRawFd::as_raw_fd(&fd), HFB_GET_INFO as _, &mut info) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Framebuffer { fd, info })
    }

    /// **The pixels**: the module's own memory, mapped read-only.  Xorg writes into it, and this
    /// mapping sees those writes — that is the whole reason the guest is what says what changed.
    ///
    /// # Safety
    ///
    /// The mapping is `info.size` bytes and stays valid as long as the `Framebuffer` (and this
    /// returned slice's user) does not outlive it.
    pub fn map(&self) -> std::io::Result<&[u8]> {
        // SAFETY: the offset is zero, the length is the module's own, and the read-only protection
        // is what the agent needs (Xorg is the writer).
        let at = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                self.info.size as usize,
                libc::PROT_READ,
                libc::MAP_SHARED,
                std::os::fd::AsRawFd::as_raw_fd(&self.fd),
                0,
            )
        };
        if at == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: the mapping is `size` bytes, and it outlives this borrow.
        Ok(unsafe { std::slice::from_raw_parts(at as *const u8, self.info.size as usize) })
    }

    /// Wait for the kernel's own drawing (a console, `fbcon`) to change something, up to the
    /// caller's timeout.  The guest's usual path is the mapping and its own comparison; this is
    /// what a client that watches only the control node blocks on.
    pub fn wait_for_drawing(&self, timeout_ms: i64) -> bool {
        // SAFETY: the fd is the control node, and the argument is the module's own timeout.
        unsafe { libc::ioctl(std::os::fd::AsRawFd::as_raw_fd(&self.fd), HFB_WAIT as _, timeout_ms) == 0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_request_numbers_are_the_kernel_s_own() {
        // `_IOR('H', 1, struct desk_fb_info)` with the structure being five `__u32`s.
        assert_eq!(HFB_GET_INFO, 0x8014_4801);
        assert_eq!(HFB_GET_DAMAGE, 0x800c_4802);
        assert_eq!(HFB_WAIT, 0x4803);
        assert_eq!(HFB_FORGET, 0x4804);
    }

    #[test]
    fn the_control_node_is_the_modules_own_path() {
        assert_eq!(CONTROL, "/dev/desk_fb-fb");
    }
}
