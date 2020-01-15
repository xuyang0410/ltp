// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2014-2020 FUJITSU LIMITED. All rights reserved.
 * Author: Xiaoguang Wang <wangxg.fnst@cn.fujitsu.com>
 * Author: Yang Xu <xuyang2018.jy@cn.jujitsu.com>
 *
 * Description:
 * Basic test for fcntl(2) using F_SETPIPE_SZ, F_GETPIPE_SZ argument.
 */

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include "tst_test.h"
#include "lapi/fcntl.h"
#include "lapi/abisize.h"
#include "lapi/capability.h"

static int fds[2];
static unsigned int orig_value, struct_shift, max_shift;
static int pg_size;

static struct tcase {
	unsigned int multi;
	unsigned int exp_multi;
	int hole;
	int pass_flag;
	char *message;
} tcases[] = {
	{1, 1, 1, 1, "set a value of blew page size"},
	{2, 2, 0, 1, "set a normal value"},
	{0, 0, 0, 1, "set a max value"},
	{0, 0, -1, 0, "set a value beyond max"},
};

static void verify_fcntl(unsigned int n)
{
	struct tcase *tc = &tcases[n];
	unsigned int pipe_value, shift;

	shift = max_shift - struct_shift;
	if (!tc->multi)
		tc->multi = pg_size << shift;
	if (!tc->exp_multi)
		tc->exp_multi = pg_size << shift;

	tst_res(TINFO, "%s", tc->message);

	pipe_value = tc->multi * pg_size - tc->hole;
	TEST(fcntl(fds[1], F_SETPIPE_SZ, pipe_value));
	if (tc->pass_flag && TST_RET == -1) {
		tst_res(TFAIL | TTERRNO, "F_SETPIPE_SZ failed");
		return;
	}
	if (!tc->pass_flag) {
		if (TST_RET == -1) {
			if (TST_ERR == ENOMEM)
				tst_res(TPASS | TTERRNO, "F_SETPIPE_SZ failed");
			else
				tst_res(TFAIL | TTERRNO,
					"F_SETPIPE_SZ failed expected ENOMEM got");
		} else
			tst_res(TFAIL, "F_SETPIPE_SZ succeed unexpectedly");
	}

	TEST(fcntl(fds[1], F_GETPIPE_SZ));
	if (TST_RET == -1) {
		tst_res(TFAIL | TTERRNO, "F_GETPIPE_SZ failed");
		return;
	}
	if (TST_RET == tc->exp_multi * pg_size)
		tst_res(TPASS, "F_SETPIPE_SZ %u bytes F_GETPIPE_SZ %lu bytes",
			pipe_value, TST_RET);
	else
		tst_res(TFAIL, "F_SETPIPE_SZ %u bytes but F_GETPIPE_SZ %lu bytes",
			pipe_value, TST_RET);
}

static void setup(void)
{
	SAFE_PIPE(fds);
	TEST(fcntl(fds[1], F_GETPIPE_SZ));
	if (TST_ERR == EINVAL)
		tst_brk(TCONF, "kernel doesn't support F_GET/SETPIPE_SZ");
	orig_value = TST_RET;
	/*
	 * See kernel fs/pipe.c, the size of struct pipe buffer is 40 bytes
	 * (round up 2^6) on 64bit system and 24 bytes(round up 2^5). kcalloc
	 * mallocs a memory space range stores struct pipe buffer. kcalloc can
	 * malloc max space depend on KMALLOC_SHIFT_MAX macro.
	 *  #define KMALLOC_SHIFT_MAX  (MAX_ORDER + PAGE_SHIFT - 1)
	 * the MAX_ORDER is 11.
	 * For example, if page size is 4k, on 64bit system. the max pipe size
	 * as below:
	 *  kcalloc space(4M): 1 << (11+12-1)= 2^22
	 *  space can store struct pipi buffer: 2^22/2^6= 2^16
	 *  max pipe size: 2^16* 2^12 = 2^28
	 * it should be 256M. On 32bit system, this value is 512M.
	 */
#ifdef TST_ABI64
	struct_shift = 6;
#else
	struct_shift = 5;
#endif
	max_shift = 10;

	pg_size = getpagesize();
	tst_res(TINFO, "page size is %d bytes", pg_size);
}

static void cleanup(void)
{
	SAFE_FCNTL(fds[1], F_SETPIPE_SZ, orig_value);
	if (fds[0] > 0)
		SAFE_CLOSE(fds[0]);
	if (fds[1] > 0)
		SAFE_CLOSE(fds[1]);
}

static struct tst_test test = {
	.setup = setup,
	.cleanup = cleanup,
	.tcnt = ARRAY_SIZE(tcases),
	.test = verify_fcntl,
	.caps = (struct tst_cap []) {
		TST_CAP(TST_CAP_REQ, CAP_SYS_RESOURCE),
		{}
	},
};
