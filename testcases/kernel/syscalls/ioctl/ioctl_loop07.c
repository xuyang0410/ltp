// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2020 FUJITSU LIMITED. All rights reserved.
 * Author: Yang Xu <xuyang2018.jy@cn.jujitsu.com>
 *
 * This is a basic ioctl test about loopdevice LOOP_SET_BLOCK_SIZE
 * and LOOP_SET_DIRECT_IO.
 * When blocksize is 1024(default align size is 512), set dio with
 * 512 offset will fail.
 */

#include <stdio.h>
#include <linux/loop.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>
#include "ioctl_loop_support.h"
#include "lapi/loop.h"
#include "tst_test.h"

static char dev_path[1024], sys_loop_logicalpath[1024];
static int dev_num, dev_fd, attach_flag;

static void verify_ioctl_loop(void)
{
	SAFE_IOCTL(dev_fd, LOOP_SET_BLOCK_SIZE, 1024);
	check_sys_value(sys_loop_logicalpath, 1024);

	/*
	 * update dio with offset 512 to check this value is effective,
	 * it should get EINVAL error.
	 */
	tst_res(TINFO, "logical block size is 1024");
	TEST(ioctl(dev_fd, LOOP_SET_DIRECT_IO, 1));
	if (TST_RET == 0) {
		tst_res(TFAIL, "LOOP_SET_DIRECT_IO succeeded unexpectedly");
		return;
	}
	if (TST_ERR == EINVAL)
		tst_res(TPASS | TTERRNO, "LOOP_SET_DIRECT_IO failed as expected");
	else
		tst_res(TFAIL | TTERRNO, "LOOP_SET_DIRECT_IO failed expected EINVAL got");
}

static void setup(void)
{
	struct loop_info loopinfo;

	memset(&loopinfo, 0, sizeof(loopinfo));
	loopinfo.lo_offset = 512;
	dev_num = tst_find_free_loopdev(dev_path, sizeof(dev_path));
	if (dev_num < 0)
		tst_brk(TBROK, "Failed to find free loop device");

	sprintf(sys_loop_logicalpath, "/sys/block/loop%d/queue/logical_block_size", dev_num);
	tst_fill_file("test.img", 0, 1024, 1024);
	tst_attach_device(dev_path, "test.img");
	attach_flag = 1;

	dev_fd = SAFE_OPEN(dev_path, O_RDWR);
	safe_set_status(dev_fd, loopinfo);
	check_support_cmd(dev_fd, LOOP_SET_DIRECT_IO, 0, "LOOP_SET_DIRECT_IO");
	check_support_cmd(dev_fd, LOOP_SET_BLOCK_SIZE, 512, "LOOP_SET_BLOCK_SIZE");
}

static void cleanup(void)
{
	if (dev_fd > 0)
		SAFE_CLOSE(dev_fd);
	if (attach_flag)
		tst_detach_device(dev_path);
	unlink("test.img");
}

static struct tst_test test = {
	.setup = setup,
	.cleanup = cleanup,
	.test_all = verify_ioctl_loop,
	.needs_root = 1,
	.needs_tmpdir = 1,
	.needs_drivers = (const char *const []) {
		"loop",
		NULL
	}
};
