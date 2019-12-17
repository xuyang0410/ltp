// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2019 FUJITSU LIMITED. All rights reserved.
 * Author: Yang Xu <xuyang2018.jy@cn.fujitsu.com
 *
 * capset() fails with errno set or EPERM if the new_Inheritable is
 * not a subset of old_Inheritable and old_Permitted without CAP_SETPCAP.
 */
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/prctl.h>
#include "tst_test.h"
#include "lapi/syscalls.h"
#include <linux/capability.h>

static struct __user_cap_header_struct header = {
	.version = 0x20080522,
	.pid = 0,
};

static struct __user_cap_data_struct data[2] = {
	{
		.effective = 1 << CAP_KILL,
		.permitted = 1 << CAP_KILL,
		.inheritable = 1 << CAP_KILL,
	},
};

static void verify_capset(void)
{
	tst_res(TINFO, "Test bad value data(when pI is not old pP or old pI without CAP_SETPCAP)");
	data[0].inheritable = (1 << CAP_KILL | 1 << CAP_NET_RAW);
	TEST(tst_syscall(__NR_capset, &header, data));
	if (TST_RET == 0) {
		tst_res(TFAIL, "capset succeed unexpectedly");
		return;
	}
	if (TST_ERR == EPERM)
		tst_res(TPASS | TTERRNO, "capset() failed as expected");
	else
		tst_res(TFAIL | TTERRNO, "capset expected EPERM, bug got");
}

static void setup(void)
{
	pid_t pid;

	pid = getpid();
	header.pid = pid;
	if (geteuid() == 0) {
		TEST(tst_syscall(__NR_capset, &header, data));
		if (TST_RET == -1)
			tst_brk(TBROK | TTERRNO, "capset data failed");
	}
}

static struct tst_test test = {
	.setup = setup,
	.test_all = verify_capset,
	.caps = (struct tst_cap []) {
		TST_CAP(TST_CAP_DROP, CAP_SETPCAP),
		{}
	},
};
