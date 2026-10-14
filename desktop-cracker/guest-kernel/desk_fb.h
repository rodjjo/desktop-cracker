/* SPDX-License-Identifier: GPL-2.0 */
/*
 * The control node of this project's own framebuffer.
 *
 * Shared between the module and the guest's agent, which is the only program that talks to it:
 * the module publishes it, the agent includes it, and neither has to guess at a number.
 */
#ifndef _DESK_FB_H
#define _DESK_FB_H

#include <linux/ioctl.h>
#include <linux/types.h>

/* The module's own name, and therefore its two device nodes: `/dev/fb0` for the screen and
 * `/dev/<name>-fb` for the control node.  It is here, once, because both ends need it — the
 * module creates the node, the agent opens it, and a name written twice is a name that drifts. */
#define DESK_NAME "desk_fb"
#define DESK_FB_CONTROL "/dev/" DESK_NAME "-fb"

/* What the screen is: the geometry the run decided before the guest booted, and the numbers a
 * program needs to read the pixels (the mapping's stride and size). */
struct desk_fb_info {
	__u32 width;
	__u32 height;
	__u32 bpp;
	__u32 stride;
	__u32 size;
};

/* What changed: the rows of the screen the **kernel's own** drawing touched since the last
 * query.  The pixels themselves are read through the mapping — damage is a hint about where to
 * look, and a client that compares the mapping itself (which is what the agent does, because
 * Xorg writes to the mapping) needs none of this to be correct, only to be quick. */
struct desk_fb_damage {
	__u32 first_row;
	__u32 last_row;
	__u32 rows_total;
};

#define HFB_GET_INFO _IOR('H', 0x01, struct desk_fb_info)
#define HFB_GET_DAMAGE _IOR('H', 0x02, struct desk_fb_damage)
/* Wait for the kernel's own drawing to change something; the argument is a timeout in
 * milliseconds (0 or less: the module's own 100 ms). */
#define HFB_WAIT _IO('H', 0x03)
/* Forget what this client has been told: the next query reports the whole screen. */
#define HFB_FORGET _IO('H', 0x04)

#endif /* _DESK_FB_H */
