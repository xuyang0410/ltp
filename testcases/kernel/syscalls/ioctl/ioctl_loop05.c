// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2020 FUJITSU LIMITED. All rights reserved.
 * Author: Yang Xu <xuyang2018.jy@cn.jujitsu.com>
 *
 * This is a basic ioctl test about loopdevice.
 *
 * It is designed to test LOOP_SET_DIRECT_IO can updata a live
 * loop device dio mode. It need the backing file also supports
 * dio mode and the lo_offset is aligned with the logical I/O size.
 */
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include "ioctl_loop_support.h"
#include "lapi/loop.h"
#include "tst_test.h"

#define DIO_MESSAGE "In dio mode"
#define NON_DIO_MESSAGE "In non dio mode"

static char dev_path[1024], sys_loop_diopath[1024];
static int dev_num, dev_fd, attach_flag;

static void check_dio_value(int flag)
{
	struct loop_info loopinfoget;

	memset(&loopinfoget, 0, sizeof(loopinfoget));

	SAFE_IOCTL(dev_fd, LOOP_GET_STATUS, &loopinfoget);
	tst_res(TINFO, "%s", flag ? DIO_MESSAGE : NON_DIO_MESSAGE);

	if (loopinfoget.lo_flags & LO_FLAGS_DIRECT_IO)
		tst_res(flag ? TPASS : TFAIL, "lo_flags has LO_FLAGS_DIRECT_IO flag");
	else
		tst_res(flag ? TFAIL : TPASS, "lo_flags doesn't have LO_FLAGS_DIRECT_IO flag");

	check_sys_value(sys_loop_diopath, flag);
}

static void verify_ioctl_loop(void)
{
	struct loop_info loopinfo;

	memset(&loopinfo, 0, sizeof(loopinfo));

	SAFE_IOCTL(dev_fd, LOOP_SET_DIRECT_IO, 0);
	check_dio_value(0);
	tst_res(TINFO, "Without setting lo_offset or sizelimit");
	SAFE_IOCTL(dev_fd, LOOP_SET_DIRECT_IO, 1);
	check_dio_value(1);

	tst_res(TINFO, "With offset equal to sector size");
	loopinfo.lo_offset = 512;
	safe_set_status(dev_fd, loopinfo);
	TEST(ioctl(dev_fd, LOOP_SET_DIRECT_IO, 1));
	if (TST_RET == 0) {
		tst_res(TPASS, "LOOP_SET_DIRECT_IO succeeded");
		check_dio_value(1);
	} else {
		tst_res(TFAIL | TTERRNO, "LOOP_SET_DIRECT_IO failed");
	}

	tst_res(TINFO, "With offset less than or unalign sector size");
	loopinfo.lo_offset = 256;
	safe_set_status(dev_fd, loopinfo);

	TEST(ioctl(dev_fd, LOOP_SET_DIRECT_IO, 1));
	if (TST_RET == 0) {
		tst_res(TFAIL, "LOOP_SET_DIRECT_IO succeeded unexpectedly");
		return;
	}
	if (TST_ERR == EINVAL)
		tst_res(TPASS | TTERRNO, "LOOP_SET_DIRECT_IO failed as expected");
	else
		tst_res(TFAIL | TTERRNO, "LOOP_SET_DIRECT_IO failed expected EINVAL got");

	loopinfo.lo_offset = 0;
	safe_set_status(dev_fd, loopinfo);
}

static void setup(void)
{
	if (tst_fs_type(".") == TST_TMPFS_MAGIC)
		tst_brk(TCONF, "tmpfd doesn't support O_DIRECT flag, skip it");

	dev_num = tst_find_free_loopdev(dev_path, sizeof(dev_path));
	if (dev_num < 0)
		tst_brk(TBROK, "Failed to find free loop device");

	sprintf(sys_loop_diopath, "/sys/block/loop%d/loop/dio", dev_num);
	tst_fill_file("test.img", 0, 1024, 1024);
	tst_attach_device(dev_path, "test.img");
	attach_flag = 1;
	dev_fd = SAFE_OPEN(dev_path, O_RDWR);
	check_support_cmd(dev_fd, LOOP_SET_DIRECT_IO, 0, "LOOP_SET_DIRECT_IO");
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
//	.needs_tmpdir = 1,
	.needs_drivers = (const char *const []) {
		"loop",
		NULL
	}
};
