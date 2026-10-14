#!/bin/bash
# The options this project's guest needs **beyond Firecracker's own configuration**.
#
# Why these are asked for by name rather than edited into a copy of the config: the
# configuration the Firecracker project validates is the *baseline*, and the only honest way
# to depart from it is a short, readable list of departures — each with the reason it is
# there.  Everything else stays exactly as Firecracker ships it, so the day its configuration
# changes this script keeps working and the list of differences stays one screen long.
#
# It is **sourced** by `kernel-build.sh`, which is what turns this list into a `.config`
# (`scripts/config`), resolves it (`make olddefconfig`) and then verifies that every option
# really came out as asked (`make olddefconfig` can refuse one whose dependencies are not
# there — and a `=y` that silently became "not set" is a guest feature that fails in the
# guest, at run time, far from here).
#
# The four groups, and what each one is for:
#
# storage the encrypted root disk, opened **inside the guest** (the only shape with
# no host privilege): Firecracker's
#               configuration leaves the device-mapper out entirely, and a guest without
#               `dm-crypt` cannot open the project's own disk.
# network the guest's own **TUN**. Firecracker's only network device is a tap on
#               the host, which needs a capability this project does not ask for; the TUN is
#               made inside the guest, where nothing outside it is privileged.
#   modules     **modules at all**.  Firecracker's guest configuration is built with
# `# CONFIG_MODULES is not set`, and this guest loads what it needs at run
#               time: the framebuffer (below), the sound card, and the agent's own tools.
#               A guest with no module support is a guest whose kernel must carry every
# driver it will ever want — which is why the display's own driver and
#               this list both need this on.
# display the framebuffer Xorg's own `xf86-video-fbdev` uses: `FB` and the helpers
# this project's own driver draws through (`guest-kernel/desk_fb.c`, built
#               by this same build and the only fbdev driver the guest loads — a second one
#               would take `/dev/fb0`, which is exactly what happened while the module was
#               being written, measured 2026-10-10).  `FUSE_FS` (already on in Firecracker's
# config) is what the shared folders are built on.
# input/audio the keyboard and the mouse as `uinput` devices and the sound card as
# `snd-aloop` — both are the "put it back on the guest's side" half of
#               services the host answers over vsock.

# The names, in one array.  `kernel-build.sh` turns each one into `scripts/config --enable`
# (`=y`), or `--module` (`=m`) when the name is prefixed with `m:` — a driver the guest loads
# at run time.  A name prefixed with `*:` is an **internal helper symbol** (no prompt of its
# own: it is `select`ed by the driver that needs it), and the build asks for it and accepts
# either `=y` or `=m`, because which one it takes is the driver's business, not this list's.
DESK_KERNEL_OPTIONS=(
    # --- storage: the encrypted root disk, opened in the guest
    CONFIG_MD
    CONFIG_BLK_DEV_DM
    CONFIG_DM_CRYPT
    # --- network: the guest's own TUN (no tap, no capability)
    CONFIG_TUN
    # --- modules at all
    CONFIG_MODULES
    CONFIG_MODULE_UNLOAD
    # --- the display: what Xorg's fbdev driver needs to have a screen at all
    CONFIG_FB
    *:CONFIG_FB_SYS_FILLRECT
    *:CONFIG_FB_SYS_COPYAREA
    *:CONFIG_FB_SYS_IMAGEBLIT
    *:CONFIG_FB_SYS_FOPS
    # **This project's own framebuffer** (`desktop-cracker/guest-kernel/`): the guest's screen, as a
    # real `/dev/fb0` that the guest's own `xf86-video-fbdev` drives.  Firecracker has no
    # display device, so the framebuffer comes from the guest's own kernel — which is why the
    # guest kernel is this project's build and not Firecracker's stock one.  The option is
    # declared in this tree's own `guest-kernel/Kconfig`, which `kernel-build.sh` puts into the
    # kernel source beside the module.
    m:CONFIG_DESK_FB
    # --- input and audio: the guest half of two vsock services
    CONFIG_INPUT_UINPUT
    CONFIG_SOUND
    CONFIG_SND
    m:CONFIG_SND_ALOOP
)
