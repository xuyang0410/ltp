// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2020 FUJITSU LIMITED. All rights reserved.
 * Author: Yang Xu <xuyang2018.jy@cn.jujitsu.com>
 *
 * This is a basic ioctl test about loopdevice.
 * It is designed to test LO_FLAGS_AUTOCLEAR and LO_FLAGS_PARTSCAN flag.
 *
 * For LO_FLAGS_AUTOCLEAR flag, we only check autoclear fieldvalue in sys
 * directory and also get lo_flags by using LOOP_GET_STATUS.
 *
 * For LO_FLAGS_PARTSCAN flag, it is the same as LO_FLAGS_AUTOCLEAR flag.
 * But we also check whether we can scan partition table correctly ie check
 * whether /dev/loopnp1 and /sys/bloclk/loop0/loop0p1 existed.
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "ioctl_loop_support.h"
#include "lapi/loop.h"
#include "tst_test.h"

static char dev_path[1024], backing_path[1024], backing_file_path[1024];
static int dev_num, attach_flag, dev_fd;
/*
 *In drivers/block/loop.c code, set status function doesn't handle
 *LO_FLAGS_READ_ONLY flag and ingore it. Only loop_set_fd with rondonly
 *mode file_fd, lo_flags will include LO_FLAGS_READ_ONLY.
 */
#define set_flags (LO_FLAGS_AUTOCLEAR | LO_FLAGS_PARTSCAN | LO_FLAGS_READ_ONLY | LO_FLAGS_DIRECT_IO)
#define get_flags (LO_FLAGS_AUTOCLEAR | LO_FLAGS_PARTSCAN)

static char partscan_path[1024], autoclear_path[1024];
static char loop_partpath[1026], sys_loop_partpath[1026];

static void verify_ioctl_loop(void)
{
	int ret;
	struct loop_info loopinfo, loopinfoget;

	tst_attach_device(dev_path, "test.img");
	attach_flag = 1;

	check_sys_value(partscan_path, 0);
	check_sys_value(autoclear_path, 0);
	check_sys_string(backing_path, backing_file_path);

	dev_fd = SAFE_OPEN(dev_path, O_RDWR);
	memset(&loopinfo, 0, sizeof(loopinfo));
	memset(&loopinfo, 0, sizeof(loopinfoget));

	loopinfo.lo_flags = set_flags;
	SAFE_IOCTL(dev_fd, LOOP_SET_STATUS, &loopinfo);

	SAFE_IOCTL(dev_fd, LOOP_GET_STATUS, &loopinfoget);

	if (loopinfoget.lo_flags & ~get_flags)
		tst_res(TFAIL, "expect %d but got %d", get_flags, loopinfoget.lo_flags);
	else
		tst_res(TPASS, "get expected lo_flag %d", loopinfoget.lo_flags);

	ret = access(loop_partpath, F_OK);
	if (ret == 0)
		tst_res(TPASS, "access %s succeeds", loop_partpath);
	else
		tst_res(TFAIL, "access %s fails", loop_partpath);

	ret = access(sys_loop_partpath, F_OK);
	if (ret == 0)
		tst_res(TPASS, "access %s succeeds", sys_loop_partpath);
	else
		tst_res(TFAIL, "access %s fails", sys_loop_partpath);

	check_sys_value(partscan_path, 1);
	check_sys_value(autoclear_path, 1);

	SAFE_CLOSE(dev_fd);
	tst_detach_device(dev_path);
	attach_flag = 0;
}

static void setup(void)
{
	const char *const cmd_dd[] = {"dd", "if=/dev/zero", "of=test.img", "bs=1M", "count=10", NULL};
	const char *const cmd_parted[] = {"parted", "-s", "test.img", "mklabel", "msdos", "mkpart",
						"primary", "ext4", "1M", "10M", NULL};

	dev_num = tst_find_free_loopdev(dev_path, sizeof(dev_path));
	if (dev_num < 0)
		tst_brk(TBROK, "Failed to find free loop device");

	SAFE_CMD(cmd_dd, NULL, NULL);
	SAFE_CMD(cmd_parted, NULL, NULL);

	sprintf(partscan_path, "/sys/block/loop%d/loop/partscan", dev_num);
	sprintf(autoclear_path, "/sys/block/loop%d/loop/autoclear", dev_num);
	sprintf(backing_path, "/sys/block/loop%d/loop/backing_file", dev_num);
	sprintf(sys_loop_partpath, "/sys/block/loop%d/loop%dp1", dev_num, dev_num);
	sprintf(backing_file_path, "%s/test.img", tst_get_tmpdir());
	sprintf(loop_partpath, "%sp1", dev_path);
}

static void cleanup(void)
{
	if (dev_fd > 0)
		SAFE_CLOSE(dev_fd);
	if (attach_flag)
		tst_detach_device(dev_path);
}

static struct tst_test test = {
	.setup = setup,
	.cleanup = cleanup,
	.test_all = verify_ioctl_loop,
	.needs_root = 1,
	.needs_cmds = (const char *const []) {
		"dd",
		"parted",
		NULL
	},
	.needs_drivers = (const char *const []) {
		"loop",
		NULL
	},
	.needs_tmpdir = 1,
};
