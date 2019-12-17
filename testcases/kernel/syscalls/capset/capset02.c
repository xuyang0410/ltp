// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) Wipro Technologies Ltd, 2002.  All Rights Reserved.
 * Author: Saji Kumar.V.R <saji.kumar@wipro.com>
 *
 * Tests basic error handling of the capset syscall.
 * 1) capset() fails with errno set to EFAULT if an invalid address
 * is given for header.
 * 2) capset() fails with errno set to EFAULT if an invalid address
 * is given for data.
 * 3) capset() fails with errno set ot EINVAL if an unused pid is
 * given for header->pid.
 * 4) capset() fails with errno set to EINVAL if an invalid value
 * is given for header->version.
 * 5) capset() fails with errno set to EPERM if the new_Effective is
 * not a subset of the new_Permitted.
 * 6) capset() fails with errno set to EPERM if the new_Permitted is
 * not a subset of the old_Permitted.
 * 7) capset() fails with errno set ot EPERM if the new_Inheritable is
 * not a subset of  the old_Inheritable and bounding set.
 */
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/prctl.h>
#include "tst_test.h"
#include "lapi/syscalls.h"
#include <linux/capability.h>

#define CAP1 (1 << CAP_NET_RAW | 1 << CAP_CHOWN  | 1 << CAP_SETPCAP)
#define CAP2 (CAP1 | 1 << CAP_KILL)

static unsigned int check_root_flag, drop_flag;
static struct __user_cap_header_struct header, bad_version_header, unused_pid_header;
static struct __user_cap_data_struct data[2];
static struct __user_cap_data_struct good_data[2] = {
	{
		.effective = CAP1,
		.permitted = CAP1,
		.inheritable = CAP1,
	},
};

static struct __user_cap_data_struct bad_data_pe[2] = {
	{
		.effective = CAP2,
		.permitted = CAP1,
		.inheritable = CAP1,
	},
};

static struct __user_cap_data_struct bad_data_pp[2] = {
	{
		.effective = CAP1,
		.permitted = CAP2,
		.inheritable = CAP1,
	},
};

static struct __user_cap_data_struct bad_data_pi[2] = {
	{
		.effective = CAP1,
		.permitted = CAP1,
		.inheritable = CAP2,
	},
};

static struct tcase {
	cap_user_header_t headerp;
	cap_user_data_t datap;
	int exp_err;
	/*
	 * 1 needs reset header version
	 * 2 needs root privilege
	 * 3 needs drop cap in bouding set
	 */
	int flag;
	char *message;
} tcases[] = {
	{NULL, data, EFAULT, 0, "Test bad address header"},
	{&header, NULL, EFAULT, 0, "Test bad address data"},
	{&unused_pid_header, data, EINVAL, 1, "Test bad pid"},
	{&bad_version_header, data, EINVAL, 1, "Test bad version"},
	{&header, bad_data_pe, EPERM, 0, "Test bad value data(when pE is not in pP)"},
	{&header, bad_data_pp, EPERM, 2, "Test bad value data(when pP is not in old pP)"},
	{&header, bad_data_pi, EPERM, 3, "Test bad value data(when pI is not in bounding set or old pI)"},
};

static void verify_capset(unsigned int n)
{
	struct tcase *tc = &tcases[n];

	tst_res(TINFO, "%s", tc->message);
	if (tc->flag == 2 && !check_root_flag) {
		tst_res(TCONF, "This test needs root privilege, skip it");
		return;
	}
	if (tc->flag == 3 && !drop_flag) {
		tst_res(TCONF, "This test needs to drop CAP_KILL in bounding set, skip it");
		return;
	}

	TEST(tst_syscall(__NR_capset, tc->headerp, tc->datap));
	if (TST_RET == 0) {
		tst_res(TFAIL, "capset() succeed unexpectedly");
		return;
	}
	if (TST_ERR == tc->exp_err)
		tst_res(TPASS | TTERRNO, "capset() failed as expected");
	else
		tst_res(TFAIL | TTERRNO, "capset() expected %s got ",
			tst_strerrno(tc->exp_err));
	/*
	 * When an unsupported version value is specified, it will
	 * return the kernel preferred value of _LINUX_CAPABILITY_VERSION_?.
	 * Since linux 2.6.26, version 3 is default. We use it.
	 */
	if (tc->flag == 1) {
		if (tc->headerp->version == 0x20080522)
			tc->headerp->version = 0;
		else
			tst_res(TFAIL, "kernel doesn't return preferred linux"
				" capability version when using bad version");
	}
}

static void setup(void)
{
	unsigned int i;
	pid_t pid;

	pid = getpid();

	header.version = 0x20080522;
	header.pid = pid;
	bad_version_header.version = 0;
	bad_version_header.pid = pid;
	unused_pid_header.pid = 0x20080522;
	unused_pid_header.pid = tst_get_unused_pid();


	for (i = 0; i < ARRAY_SIZE(tcases); i++) {
		if (!tcases[i].headerp)
			tcases[i].headerp = tst_get_bad_addr(NULL);
		if (!tcases[i].datap)
			tcases[i].datap = tst_get_bad_addr(NULL);
	}

	if (geteuid() == 0) {
		TEST(tst_syscall(__NR_capset, &header, good_data));
		if (TST_RET == -1)
			tst_res(TFAIL | TTERRNO, "capset good_data failed");
		else
			check_root_flag = 1;
		TEST(prctl(PR_CAPBSET_DROP, CAP_KILL));
		if (TST_RET == -1)
			tst_res(TFAIL | TTERRNO, "drop CAP_KILL failed");
		else
			drop_flag = 1;
	}
}

static struct tst_test test = {
	.setup = setup,
	.tcnt = ARRAY_SIZE(tcases),
	.test = verify_capset,
};
