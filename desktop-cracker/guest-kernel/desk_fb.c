// SPDX-License-Identifier: GPL-2.0
/*
 * desk_fb — this project's own **framebuffer**: the guest's screen, backed by guest memory.
 *
 * Firecracker exposes no display device, so the guest's screen cannot come from hardware: it
 * comes from the guest's own memory, published as a real framebuffer that the guest's Xorg
 * already knows how to drive through `xf86-video-fbdev`.  That is the whole of this module —
 * and keeping it that small is the point:
 *
 *   * `/dev/fb0` **is** the framebuffer.  It is registered with `fbdev`, its drawing
 *     operations are the kernel's own `sys_*` blitters (there is not a line of drawing code
 *     here), and its format is the one the project's display uses: 32 bits per pixel, `XRGB8888`;
 * * `/dev/desk_fb-fb` is the **control node** the guest's agent talks to: it asks for the
 *     geometry the run decided, and it `mmap`s the pixels themselves — one mapping, read
 *     directly, with no copy between the module and the agent.
 *
 * **The damage is measured by whoever has the mapping**, and on purpose: Xorg's fbdev driver
 * does its drawing in its own buffer and then writes the changed rectangles into the mapping,
 * which the kernel cannot intercept — so every design ends in "compare the memory".  Comparing
 * it on the agent's side costs one `mmap` and a loop the agent already has to run; doing it in
 * the kernel would cost a system call per poll and the same reads, and would be code with a bug
 * surface for no gain.  What the module *does* mark is the drawing the kernel itself makes
 * through `fb_ops` (a text console, a kernel message, `fbcon`), because those pass through
 * functions that are ours: a change reported there is remembered in the module's own damage
 * record, so a client that only watches the control node still sees it.
 */

#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/fb.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/wait.h>

#include "desk_fb.h"

/* The screen's default is the project's own window size (`dc-display`'s 1280x800); the run
 * replaces it with the geometry the display service decided before the guest booted. */
static int width = 1280;
static int height = 800;
static int bpp = 32;
module_param(width, int, 0444);
module_param(height, int, 0444);
module_param(bpp, int, 0444);
MODULE_PARM_DESC(width, "screen width in pixels");
MODULE_PARM_DESC(height, "screen height in pixels");
MODULE_PARM_DESC(bpp, "bits per pixel (32: XRGB8888)");

struct desk_fb {
	struct fb_info *info;
	/* The pixels, and the numbers the control node answers with: kept here as well as in
	 * `fb_info` because the control node is what the agent reads, and it should not have to
	 * know how `fb_info` lays its fields out. */
	u8 *screen;
	u32 stride;
	u32 size;
	u32 width;
	u32 height;
	u32 bpp;
	/* The damage the **kernel's own** drawing made (`fb_ops`), remembered in rows: what a
	 * client that watches the control node — rather than the mapping — needs to be told. */
	struct mutex lock;
	bool dirty;
	u32 dirty_first;
	u32 dirty_last;
	wait_queue_head_t wait;
	u32 generation;
};

static struct desk_fb *deskfb;
static dev_t control_dev;
static struct cdev control_cdev;
static struct class *control_class;
static struct device *control_device;

/* --- the mapping, shared by both nodes --- */

/*
 * **Map the screen.**  This is the one place the two nodes agree, and it is the reason the
 * module has a mapping function at all: fbdev's default path hands `smem_start` to
 * `vm_iomap_memory`, which treats it as an **I/O address** and maps it uncached/decrypted — right
 * for a PCI card's BAR, wrong for pages the kernel allocated.  An X server that writes scanlines
 * into such a mapping corrupts its own page tables (measured 2026-10-10: `Xorg: Corrupted page
 * table`, `Bad pagetable: 000f`, and the X server dies), so the driver maps its own pages one by
 * one with `vmalloc_to_pfn`, which is exactly what the kernel's own `fb_deferred_io_mmap` does.
 */
static int map_the_screen(struct vm_area_struct *vma)
{
	struct desk_fb *hfb = deskfb;
	unsigned long size = vma->vm_end - vma->vm_start;
	unsigned long offset = vma->vm_pgoff << PAGE_SHIFT;
	unsigned long at;

	if (!hfb)
		return -ENODEV;
	if (offset + size > PAGE_ALIGN(hfb->size))
		return -EINVAL;

	vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);
	for (at = 0; at < size; at += PAGE_SIZE) {
		unsigned long pfn = vmalloc_to_pfn(hfb->screen + offset + at);

		if (remap_pfn_range(vma, vma->vm_start + at, pfn, PAGE_SIZE, vma->vm_page_prot))
			return -EAGAIN;
	}
	return 0;
}

/* --- the drawing the kernel does: ours only so it can be noticed --- */

static void mark_dirty(struct desk_fb *hfb, u32 first, u32 last)
{
	mutex_lock(&hfb->lock);
	if (!hfb->dirty) {
		hfb->dirty = true;
		hfb->dirty_first = first;
		hfb->dirty_last = last;
	} else {
		hfb->dirty_first = min(hfb->dirty_first, first);
		hfb->dirty_last = max(hfb->dirty_last, last);
	}
	hfb->generation++;
	mutex_unlock(&hfb->lock);
	wake_up_interruptible(&hfb->wait);
}

/* Rows 0..n of the rectangle a fill, copy or blit touched, from its `struct fb_*` argument. */
static void hfb_fillrect(struct fb_info *info, const struct fb_fillrect *rect)
{
	sys_fillrect(info, rect);
	if (rect->height)
		mark_dirty(deskfb, rect->dy, rect->dy + rect->height - 1);
}

static void hfb_copyarea(struct fb_info *info, const struct fb_copyarea *area)
{
	sys_copyarea(info, area);
	if (area->height)
		mark_dirty(deskfb, area->dy, area->dy + area->height - 1);
}

static void hfb_imageblit(struct fb_info *info, const struct fb_image *image)
{
	sys_imageblit(info, image);
	if (image->height)
		mark_dirty(deskfb, image->dy, image->dy + image->height - 1);
}

static int hfb_setcolreg(unsigned regno, unsigned red, unsigned green, unsigned blue,
			 unsigned transp, struct fb_info *info)
{
	if (regno >= 256)
		return -EINVAL;
	if (info->var.bits_per_pixel == 32) {
		/* An XRGB8888 screen's palette: a "colour" is the pixel value itself. */
		((u32 *)info->pseudo_palette)[regno] = ((transp & 0xff00) << 16) |
						       ((red & 0xff00) << 8) |
						       (green & 0xff00) |
						       ((blue & 0xff00) >> 8);
	}
	return 0;
}

/* **The framebuffer's own mapping**, which is the one that matters and the one fbdev does *not*
 * do correctly for memory that is not a device: the default path hands `smem_start` to
 * `vm_iomap_memory`, which treats it as an **I/O address** and maps it through
 * `pgprot_decrypted`/`pgprot_noncached` — that is right for a PCI card's BAR and wrong for pages
 * the kernel allocated, and an X server that writes scanlines into such a mapping corrupts its
 * own page tables (measured 2026-10-10: Xorg's driver `memcpy`s a shadow line in and the guest's
 * kernel reports `Xorg: Corrupted page table`, `Bad pagetable: 000f`, and the X server dies).
 * Mapping the driver's own pages one by one with `vmalloc_to_pfn` is what the kernel's own
 * `fb_deferred_io_mmap` does for the same reason. */
static int desk_fb_ops_mmap(struct fb_info *info, struct vm_area_struct *vma)
{
	(void)info;
	return map_the_screen(vma);
}

static const struct fb_ops desk_fb_ops = {
	.owner = THIS_MODULE,
	/* `/dev/fb0` is mapped by us: see `map_the_screen` for why the default would corrupt the
	 * guest's own page tables. */
	.fb_mmap = desk_fb_ops_mmap,
	/* The kernel's helpers, not ours: a framebuffer of system memory draws through these,
	 * and the only reason they are wrapped at all is the damage record. */
	.fb_fillrect = hfb_fillrect,
	.fb_copyarea = hfb_copyarea,
	.fb_imageblit = hfb_imageblit,
	.fb_read = fb_sys_read,
	.fb_write = fb_sys_write,
	.fb_setcolreg = hfb_setcolreg,
};

/* --- the control node --- */

static long desk_fb_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct desk_fb *hfb = deskfb;
	void __user *user = (void __user *)arg;

	if (!hfb)
		return -ENODEV;

	switch (cmd) {
	case HFB_GET_INFO: {
		struct desk_fb_info info;

		info.width = hfb->width;
		info.height = hfb->height;
		info.bpp = hfb->bpp;
		info.stride = hfb->stride;
		info.size = hfb->size;
		if (copy_to_user(user, &info, sizeof(info)))
			return -EFAULT;
		return 0;
	}
	case HFB_GET_DAMAGE: {
		struct desk_fb_damage damage;

		mutex_lock(&hfb->lock);
		/* A client that has never been told anything is told everything: it has just
		 * started, and a screen it has not seen is a screen it has to draw. */
		if (!hfb->dirty) {
			mutex_unlock(&hfb->lock);
			return -ENODATA;
		}
		damage.first_row = hfb->dirty_first;
		damage.last_row = hfb->dirty_last;
		damage.rows_total = hfb->height;
		hfb->dirty = false;
		mutex_unlock(&hfb->lock);
		if (copy_to_user(user, &damage, sizeof(damage)))
			return -EFAULT;
		return 0;
	}
	case HFB_WAIT: {
		/* Wait for the kernel's own drawing to change something, up to the caller's
		 * timeout.  (The agent's usual path is the mapping and its own comparison —
		 * this is what a client that watches only this node blocks on.) */
		long timeout_ms = (long)arg;
		u32 generation = READ_ONCE(hfb->generation);

		if (timeout_ms <= 0)
			timeout_ms = 100;
		wait_event_interruptible_timeout(hfb->wait, READ_ONCE(hfb->generation) != generation,
						 msecs_to_jiffies(timeout_ms));
		return 0;
	}
	default:
		return -ENOTTY;
	}
}

/* The mapping: **the agent's own way to the pixels.**  It maps the module's buffer (the same
 * memory that is `/dev/fb0`), so the agent reads what the guest draws without a call per
 * rectangle and without a copy. */
static int desk_fb_mmap(struct file *file, struct vm_area_struct *vma)
{
	(void)file;
	return map_the_screen(vma);
}

static int desk_fb_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int desk_fb_release(struct inode *inode, struct file *file)
{
	return 0;
}

static const struct file_operations desk_fb_fops = {
	.owner = THIS_MODULE,
	.open = desk_fb_open,
	.release = desk_fb_release,
	.unlocked_ioctl = desk_fb_ioctl,
	.mmap = desk_fb_mmap,
	.llseek = no_llseek,
};

/* --- registering the framebuffer --- */

static int __init desk_fb_init(void)
{
	struct fb_info *info;
	struct desk_fb *hfb;
	int ret;

	if (bpp != 32) {
		pr_err(DESK_NAME ": only 32 bits per pixel (XRGB8888) is implemented\n");
		return -EINVAL;
	}
	if (width <= 0 || height <= 0) {
		pr_err(DESK_NAME ": %dx%d is not a screen\n", width, height);
		return -EINVAL;
	}

	hfb = kzalloc(sizeof(*hfb), GFP_KERNEL);
	if (!hfb)
		return -ENOMEM;

	hfb->width = width;
	hfb->height = height;
	hfb->bpp = bpp;
	hfb->stride = width * (bpp / 8);
	hfb->size = hfb->stride * height;
	hfb->screen = vzalloc(hfb->size);
	if (!hfb->screen) {
		ret = -ENOMEM;
		goto err_free;
	}
	mutex_init(&hfb->lock);
	init_waitqueue_head(&hfb->wait);

	info = framebuffer_alloc(sizeof(u32) * 256, NULL);
	if (!info) {
		ret = -ENOMEM;
		goto err_free;
	}
	info->screen_base = (char __iomem *)hfb->screen;
	info->screen_size = hfb->size;
	info->fbops = &desk_fb_ops;
	info->fix.smem_start = (unsigned long)hfb->screen;
	info->fix.smem_len = hfb->size;
	strscpy(info->fix.id, "desk", sizeof(info->fix.id));
	info->fix.type = FB_TYPE_PACKED_PIXELS;
	info->fix.visual = FB_VISUAL_TRUECOLOR;
	info->fix.line_length = hfb->stride;
	info->fix.accel = FB_ACCEL_NONE;

	info->var.xres = width;
	info->var.yres = height;
	info->var.xres_virtual = width;
	info->var.yres_virtual = height;
	info->var.bits_per_pixel = bpp;
	info->var.red.offset = 16;
	info->var.red.length = 8;
	info->var.green.offset = 8;
	info->var.green.length = 8;
	info->var.blue.offset = 0;
	info->var.blue.length = 8;
	info->var.transp.offset = 24;
	info->var.transp.length = 8;
	info->var.activate = FB_ACTIVATE_NOW;
	info->var.vmode = FB_VMODE_NONINTERLACED;
	info->pseudo_palette = info->par;
	info->flags = FBINFO_DEFAULT | FBINFO_VIRTFB;
	info->node = -1;

	ret = register_framebuffer(info);
	if (ret) {
		pr_err(DESK_NAME ": register_framebuffer: %d\n", ret);
		goto err_release;
	}
	hfb->info = info;
	deskfb = hfb;

	/* The control node the agent talks to. */
	ret = alloc_chrdev_region(&control_dev, 0, 1, DESK_NAME);
	if (ret)
		goto err_unregister;
	cdev_init(&control_cdev, &desk_fb_fops);
	control_cdev.owner = THIS_MODULE;
	ret = cdev_add(&control_cdev, control_dev, 1);
	if (ret)
		goto err_chrdev;
	control_class = class_create(THIS_MODULE, DESK_NAME);
	if (IS_ERR(control_class)) {
		ret = PTR_ERR(control_class);
		goto err_cdev;
	}
	control_device = device_create(control_class, NULL, control_dev, NULL,
				       DESK_NAME "-fb");
	if (IS_ERR(control_device)) {
		ret = PTR_ERR(control_device);
		goto err_class;
	}

	pr_info(DESK_NAME ": %dx%d, %d bpp, %u bytes; /dev/fb0 and /dev/%s-fb\n", width,
		height, bpp, hfb->size, DESK_NAME);
	pr_info(DESK_NAME ": the control node is /dev/" DESK_NAME "-fb\n");
	return 0;

err_class:
	class_destroy(control_class);
err_cdev:
	cdev_del(&control_cdev);
err_chrdev:
	unregister_chrdev_region(control_dev, 1);
err_unregister:
	unregister_framebuffer(info);
err_release:
	framebuffer_release(info);
err_free:
	vfree(hfb->screen);
	kfree(hfb);
	return ret;
}

static void __exit desk_fb_exit(void)
{
	struct desk_fb *hfb = deskfb;

	if (!hfb)
		return;
	device_destroy(control_class, control_dev);
	class_destroy(control_class);
	cdev_del(&control_cdev);
	unregister_chrdev_region(control_dev, 1);
	unregister_framebuffer(hfb->info);
	framebuffer_release(hfb->info);
	vfree(hfb->screen);
	kfree(hfb);
	deskfb = NULL;
}

module_init(desk_fb_init);
module_exit(desk_fb_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("desktop-cracker's framebuffer: the guest's screen, backed by guest memory");
