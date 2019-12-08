// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2019 Red Hat, Inc.  All rights reserved.
 * Author: Zorro Lang <zlang@redhat.com>
 *
 * Use new mount API (fsopen, fsconfig, fsmount, move_mount) to mount
 * a filesystem without any specified mount options.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mount.h>

#include "tst_test.h"
#include "tst_safe_macros.h"
#include "lapi/newmount.h"

#define LINELENGTH 256
#define MNTPOINT "newmount_point"
static int sfd, mfd;
static int is_mounted = 0;

static int ismount(char *mntpoint)
{
	int ret = 0;
	FILE *file;
	char line[LINELENGTH];

	file = fopen("/proc/mounts", "r");
	if (file == NULL)
		tst_brk(TFAIL | TTERRNO, "Open /proc/mounts failed");

	while (fgets(line, LINELENGTH, file) != NULL) {
		if (strstr(line, mntpoint) != NULL) {
			ret = 1;
			break;
		}
	}
	fclose(file);
	return ret;
}

static void cleanup(void)
{
	if (is_mounted) {
		TEST(tst_umount(MNTPOINT));
		if (TST_RET != 0)
			tst_brk(TFAIL | TTERRNO, "umount failed in cleanup");
	}
}

static void test_newmount(void)
{
	TEST(fsopen(tst_device->fs_type, FSOPEN_CLOEXEC));
	if (TST_RET < 0) {
		tst_brk(TFAIL | TTERRNO,
		        "fsopen %s", tst_device->fs_type);
	}
	sfd = TST_RET;
	tst_res(TPASS, "fsopen %s", tst_device->fs_type);

	TEST(fsconfig(sfd, FSCONFIG_SET_STRING, "source", tst_device->dev, 0));
	if (TST_RET < 0) {
		tst_brk(TFAIL | TTERRNO,
		        "fsconfig set source to %s", tst_device->dev);
	}
	tst_res(TPASS, "fsconfig set source to %s", tst_device->dev);


	TEST(fsconfig(sfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0));
	if (TST_RET < 0) {
		tst_brk(TFAIL | TTERRNO,
		        "fsconfig create superblock");
	}
	tst_res(TPASS, "fsconfig create superblock");

	TEST(fsmount(sfd, FSMOUNT_CLOEXEC, 0));
	if (TST_RET < 0) {
		tst_brk(TFAIL | TTERRNO, "fsmount");
	}
	mfd = TST_RET;
	tst_res(TPASS, "fsmount");
	SAFE_CLOSE(sfd);

	TEST(move_mount(mfd, "", AT_FDCWD, MNTPOINT, MOVE_MOUNT_F_EMPTY_PATH));
	if (TST_RET < 0) {
		tst_brk(TFAIL | TTERRNO, "move_mount attach to mount point");
	}
	is_mounted = 1;
	tst_res(TPASS, "move_mount attach to mount point");
	SAFE_CLOSE(mfd);

	if (ismount(MNTPOINT)) {
		tst_res(TPASS, "new mount works");
		TEST(tst_umount(MNTPOINT));
		if (TST_RET != 0)
			tst_brk(TFAIL | TTERRNO, "umount failed");
		is_mounted = 0;
	} else {
		tst_res(TFAIL, "new mount fails");
	}
}

static struct tst_test test = {
	.test_all	= test_newmount,
	.cleanup	= cleanup,
	.needs_root	= 1,
	.mntpoint	= MNTPOINT,
	.needs_device	= 1,
	.format_device	= 1,
	.all_filesystems = 1,
};
