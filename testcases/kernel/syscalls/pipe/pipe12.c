// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2019 FUJITSU LIMITED. All rights reserved.
 * Author: Yang Xu <xuyang2018.jy@cn.fujitsu.com>
 *
 * Test Description:
 * A pipe has a limited capacity. If the pipe with non block mode is full,
 * then a write(2) will fail and get EAGAIN error. Otherwise, from 1 to
 * PIPE_BUF bytes may be written.
 */
#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include "tst_test.h"

static int fds[2];
static char *wrbuf;
static char *rdbuf;
static ssize_t max_size, invalid_size;

static struct tcase {
	int full_flag;
	int need_offset;
	char *message;
} tcases[] = {
	{1, 0, "Test on full pipe"},
	{0, 1, "Test on non full pipe from 1 offset"},
	{0, 0, "Test on non full pipe from 0 offset"},
};

static void verify_pipe(unsigned int n)
{
	struct tcase *tc = &tcases[n];

	memset(rdbuf, 0, max_size);

	tst_res(TINFO, "%s", tc->message);
	if (tc->full_flag) {
		SAFE_WRITE(1, fds[1], wrbuf, max_size);
		TEST(write(fds[1], "x", 1));
		if (TST_RET == 0) {
			tst_res(TFAIL, "write succeed unexpectedly");
			goto clean_pipe_buf;
			return;
		}
		if (TST_ERR == EAGAIN)
			tst_res(TPASS | TTERRNO, "write failed as expected");
		else
			tst_res(TFAIL | TTERRNO, "write failed expected EAGAIN but got");
	} else {
		if (tc->need_offset)
			SAFE_WRITE(1, fds[1], "x", 1);
		TEST(write(fds[1], wrbuf, invalid_size));
		if (TST_RET == invalid_size)
			tst_res(TFAIL, "write size %ld larger than PIPE_BUF %ld", TST_RET, max_size);
		else
			tst_res(TPASS, "write size %ld between [1, %ld]", TST_RET, max_size);
	}

clean_pipe_buf:
	SAFE_READ(0, fds[0], rdbuf, max_size);
}


static void cleanup(void)
{
	if (fds[0] > 0)
		SAFE_CLOSE(fds[0]);
	if (fds[1] > 0)
		SAFE_CLOSE(fds[1]);
	if (wrbuf)
		free(wrbuf);
	if (rdbuf)
		free(rdbuf);
}

static void setup(void)
{

	TEST(pipe(fds));
	if (TST_RET == -1) {
		tst_brk(TBROK | TTERRNO, "pipe");
		return;
	}

	max_size = SAFE_FCNTL(fds[1], F_GETPIPE_SZ);
	invalid_size = max_size + 4096;
	wrbuf = SAFE_MALLOC(invalid_size);
	rdbuf = SAFE_MALLOC(max_size);
	memset(wrbuf, 'x', invalid_size);

	SAFE_FCNTL(fds[1], F_SETFL, O_NONBLOCK);
	SAFE_FCNTL(fds[0], F_SETFL, O_NONBLOCK);
}

static struct tst_test test = {
	.test = verify_pipe,
	.setup = setup,
	.cleanup = cleanup,
	.tcnt = ARRAY_SIZE(tcases),
};
