#!/bin/bash
# make install-deps — report what this host is missing so the microVM can run.
#
# It *reports*; it never installs and never calls sudo.  The exact command for
# this distribution is printed instead, so the choice stays with the user.
set -uo pipefail

missing_tools=()
missing_libs=()
ok=0

need_tool() {
    if command -v "$1" >/dev/null 2>&1; then
        printf '  ok      %-22s %s\n' "$1" "$(command -v "$1")"
        ok=$((ok + 1))
    else
        printf '  MISSING %-22s %s\n' "$1" "$2"
        missing_tools+=("$1")
    fi
}

echo "== tools"
need_tool gcc "builds the guest's tools, the guest's display library and the kernel module"
need_tool firecracker       "the microVM runs on Firecracker (a released binary)"
need_tool make              "this Makefile"
need_tool cargo             "builds the Rust application"
need_tool rustc             "builds the Rust application"
need_tool gcc               "builds the tiny static guest tools"
need_tool cpio              "builds the guest initramfs"
need_tool gzip              "compresses the guest initramfs"
need_tool curl              "downloads the base image and the hypervisor"
need_tool busybox           "the guest init in the smoke/tools image"
need_tool mke2fs            "optional: building the guest root disk"

echo
echo "== libraries (development headers)"
need_lib libpulse-simple "the guest's audio, through the host's sound server"
need_lib gl        "OpenGL itself"
need_lib gtk+-3.0  "the window and every dialog: a GTK3 window with a gtk::GLArea"
echo
echo "== KVM"
if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    echo "  ok      /dev/kvm is readable and writable — accel=kvm available"
    ok=$((ok + 1))
else
    echo "  MISSING /dev/kvm is not writable by $(id -un) (groups: $(id -Gn))"
    echo "          add yourself to the 'kvm' group:  sudo usermod -aG kvm $(id -un)   (then log out and in)"
fi

echo "== network (the guest's own TUN, over a channel: no helper, no sudo)"
echo
if [ ${#missing_tools[@]} -eq 0 ] && [ ${#missing_libs[@]} -eq 0 ]; then
    echo "install-deps: nothing missing ($ok checks passed)."
    exit 0
fi

echo "install-deps: $((${#missing_tools[@]} + ${#missing_libs[@]})) item(s) missing."
if command -v apt-get >/dev/null 2>&1; then
    pkgs=()
    for t in "${missing_tools[@]}"; do
        case "$t" in
        cargo | rustc) pkgs+=(cargo rustc) ;;
        # Firecracker is a released binary, not a package: the line above says where it comes from
        firecracker) ;;
        firecracker) ;;   # a released binary: the message above says where it comes from
        busybox) pkgs+=(busybox-static) ;;
        mke2fs) pkgs+=(e2fsprogs) ;;
        cpio | gzip | curl | gcc | make) pkgs+=("$t") ;;
        esac
    done
    for l in "${missing_libs[@]}"; do
        case "$l" in
        libpulse-simple) pkgs+=(libpulse-dev) ;;
        gl) pkgs+=(libgl-dev) ;;
        gtk+-3.0) pkgs+=(libgtk-3-dev) ;;
        esac
    done
    # de-duplicate, keep order
    # An empty list still prints one blank line, so "non-empty" is "has a non-blank line".
    printf '%s\n' "${pkgs[@]}" | awk 'NF && !seen[$0]++' > /tmp/.dc-deps.$$
    if [ -s /tmp/.dc-deps.$$ ]; then
        echo "  sudo apt-get install -y $(tr '\n' ' ' < /tmp/.dc-deps.$$)"
    else
        echo "  nothing here can be installed by apt: see the lines above"
    fi
    rm -f /tmp/.dc-deps.$$
else
    echo "  install the equivalents of: ${missing_tools[*]} ${missing_libs[*]}"
fi
exit 1
