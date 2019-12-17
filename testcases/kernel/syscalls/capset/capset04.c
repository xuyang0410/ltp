// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) Wipro Technologies Ltd, 2002.  All Rights Reserved.
 * Author: Saji Kumar.V.R <saji.kumar@wipro.com>
 *
 * Tests whether we can use capset() to modify the capabilities of a thread
 * other than itself. Now, most linux distributions with kernel supporting
 * VFS capabilities, this should be never permitted.
 */
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include "tst_test.h"
#include "lapi/syscalls.h"
#include <linux/capability.h>

static struct __user_cap_header_struct header = {
	.version = 0x20080522,
	.pid = 0,
};
static struct __user_cap_data_struct data[2];
static pid_t child_pid;
static int clean_nflag;
static void cleanup(void);

static void child_func(void)
{
	for (;;)
		sleep(10);
}

static void verify_capset(void)
{
	child_pid = SAFE_FORK();
	if (child_pid == 0) {
		child_func();
		exit(0);
	}

	clean_nflag = 0;
	header.pid = child_pid;

	TEST(tst_syscall(__NR_capset, &header, data));
	if (TST_RET == 0) {
		tst_res(TFAIL, "capset succeed unexpectedly");
		cleanup();
		return;
	}
	if (TST_ERR == EPERM)
		tst_res(TPASS, "capset doesn't can modify other process capabilities");
	else
		tst_res(TFAIL | TTERRNO, "capset expected EPERM, bug got");

	cleanup();
}

static void setup(void)
{
	pid_t pid;

	pid = getpid();
	header.pid = pid;
	TEST(tst_syscall(__NR_capget, &header, data));
	if (TST_RET == -1)
		tst_brk(TBROK | TTERRNO, "capget data failed");
}

static void cleanup(void)
{
	if (child_pid > 0 && !clean_nflag) {
		SAFE_KILL(child_pid, SIGTERM);
		SAFE_WAIT(NULL);
		clean_nflag = 1;
	}
}

static struct tst_test test = {
	.setup = setup,
	.cleanup = cleanup,
	.test_all = verify_capset,
	.forks_child = 1,
	.caps = (struct tst_cap []) {
		TST_CAP(TST_CAP_REQ, CAP_SETPCAP),
		{}
	},
};
