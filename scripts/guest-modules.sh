#!/bin/bash
# The **extra modules** this project's guest loads, on top of the list
# `tools/guest-image/build.sh` copies.
#
# Why this is a file of its own rather than an edit to that script: `tools/guest-image/build.sh`
# is the project's own, and it is what every guest image this project boots is made from. So
# that list stays exactly as it is, and this file says what this guest needs beyond it — which
# is nothing about the project's devices and everything about the two things Firecracker does
# not give us:
#
# * **a display**: the guest's framebuffer is this project's own (built from
#     `desktop-cracker/guest-kernel/`) and the fbdev helpers it draws through; nothing else: a second fbdev
#     driver in the guest would take `/dev/fb0` and Xorg would draw into a screen nobody watches;
#   * **a sound card**: `snd-aloop`, the kernel's loopback card, which is the guest's half of
# the audio service. `virtio_snd` (the card a hardware VM would give it) is not in the
#     list for this kernel either — there is no virtio-snd device here to drive it.
#
# The project's own list already covers what stays the same: `dm-crypt` and `essiv` for
# the encrypted root disk, the vsock stack, `9p` (which this path does not use but which costs
# nothing), the overlay filesystem and the input driver.
#
# Each entry is `<path under kernel/>: <what it is for>`; the path is what the module's file
# is called inside `download/modules/<release>/kernel/`.
DESK_EXTRA_MODULES=(
    "drivers/video/fbdev/core/sysfillrect.ko: fbdev's generic rectangle fills"
    "drivers/video/fbdev/core/syscopyarea.ko: fbdev's generic rectangle copies"
    "drivers/video/fbdev/core/sysimgblt.ko: fbdev's generic image blits"
    "drivers/video/fbdev/core/fb_sys_fops.ko: fbdev's read/write helpers"
    "drivers/video/fbdev/core/cfbfillrect.ko: fbdev's packed-pixel fills"
    "drivers/video/fbdev/core/cfbcopyarea.ko: fbdev's packed-pixel copies"
    "drivers/video/fbdev/core/cfbimgblt.ko: fbdev's packed-pixel blits"
    "sound/drivers/snd-aloop.ko: the guest's sound card — the audio service's other end"
    # **This project's own framebuffer**, built by this tree's kernel build
    # (`desktop-cracker/guest-kernel/`, put into the kernel's tree by `scripts/kernel-build.sh`).  It is what
    # gives the guest a `/dev/fb0` at all: Firecracker has no display device, and the guest's
    # own `xf86-video-fbdev` is what draws into this one.
    "drivers/video/desk_fb/desk_fb.ko: the guest's screen — /dev/fb0 and its control node"
)
