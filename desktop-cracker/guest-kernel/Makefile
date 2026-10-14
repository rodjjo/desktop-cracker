# This project's own framebuffer, as the kernel's own build system wants it: this directory is
# copied into the kernel tree by `scripts/build-kernel.sh` (as `drivers/video/desk_fb/`),
# and the kernel's `Makefile` is what builds it — no second build system, no out-of-tree
# `make -C`, and the module that ships is built by the same `make modules` as every other.
obj-$(CONFIG_DESK_FB) += desk_fb.o
