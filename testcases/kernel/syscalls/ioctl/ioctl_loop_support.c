// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2020 FUJITSU LIMITED. All rights reserved.
 * Author: Yang Xu <xuyang2018.jy@cn.fujitsu.com>
 */
#define TST_NO_DEFAULT_MAIN
#include "ioctl_loop_support.h"
#include "tst_test.h"

void check_sys_value(char *path, int setvalue)
{
	int getvalue;

	SAFE_FILE_SCANF(path, "%d", &getvalue);
	if (setvalue == getvalue)
		tst_res(TPASS, "%s value is %d", path, setvalue);
	else
		tst_res(TFAIL, "%s value expected %d got %d", path, setvalue, getvalue);
}

void check_sys_string(char *path, char *setmessage)
{
	char getmessage[1024];

	SAFE_FILE_SCANF(path, "%s", getmessage);
	if (strcmp(setmessage, getmessage))
		tst_res(TFAIL, "%s expected %s got %s", path, setmessage, getmessage);
	else
		tst_res(TPASS, "%s string is %s", path, getmessage);
}

void safe_set_status(int dev_fd, struct loop_info loopinfo)
{
	int sleep_us = 4096;
	int ret = 0;

	/*
	 * It may have dirty page, so loop dirver may get EAGAIN error
	 * when we use different offset or sizelimit.
	 */
	ret = ioctl(dev_fd, LOOP_SET_STATUS, &loopinfo);
	while (ret != 0 && errno == EAGAIN && sleep_us < 100000) {
		ret = ioctl(dev_fd, LOOP_SET_STATUS, &loopinfo);
		usleep(sleep_us);
		sleep_us *= 2;
	}
}

void safe_set_status64(int dev_fd, struct loop_info64 loopinfo)
{
	int sleep_us = 4096;
	int ret = 0;

	/*
	 * It may have dirty page, so loop dirver may get EAGAIN error
	 * when we use different offset or sizelimit.
	 */
	ret = ioctl(dev_fd, LOOP_SET_STATUS64, &loopinfo);
	while (ret != 0 && errno == EAGAIN && sleep_us < 100000) {
		ret = ioctl(dev_fd, LOOP_SET_STATUS64, &loopinfo);
		usleep(sleep_us);
		sleep_us *= 2;
	}
}

void check_support_cmd(int dev_fd, int ioctl_flag, int value, char *message)
{
	int ret = 0;

	ret = ioctl(dev_fd, ioctl_flag, value);
	if (ret && errno == EINVAL)
		tst_brk(TCONF, "Current environment doesn't support this flag(%s)",
				message);
}
