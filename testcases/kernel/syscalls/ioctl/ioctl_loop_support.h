// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2020 FUJITSU LIMITED. All rights reserved.
 * Author: Yang Xu <xuyang2018.jy@cn.fujitsu.com>
 */
#ifndef IOCTL_LOOP_H
#define IOCTL_lOOP_H
#include <linux/loop.h>
void check_sys_value(char *path, int setvalue);
void check_sys_string(char *path, char *setmessage);
void safe_set_status(int dev_fd, struct loop_info loopinfo);
void safe_set_status64(int dev_fd, struct loop_info64 loopinfo);
void check_support_cmd(int dev_fd, int ioctl_flag, int value, char *message);
#endif
