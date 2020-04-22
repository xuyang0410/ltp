// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2020 FUJITSU LIMITED. All rights reserved.
 * Author: Yang Xu <xuyang2018.jy@cn.fujitsu.com>
 *
 * This case is designed to test the basic functionality about the
 * O_DIRECT flag of pipe2.
 *
 * It includes three sub tests.
 * 1) Each write(2) to the pipe is dealt with as a separate packet, and
 * read(2)s from the pipe will read one packet at a time.
 * 2) Writes of greater than PIPE_BUF bytes (see pipe(7)) will be split
 * into multiple packet.
 * 3)If a read(2) specifies a buffer size that is smaller than the next
 * packet, then the requested number of bytes are read, and the excess
 * bytes in the packet are discarded.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <linux/limits.h>
#include "lapi/fcntl.h"
#include "tst_test.h"

static int fds[2], packet_num, pipe_size;
static char *wrbuf;
static char *rdbuf;
static void check_peer_rw(void);
static void check_split(void);
static void check_discard(void);

static void (*test_func[])(void) = {check_peer_rw, check_split, check_discard};

static void check_peer_rw(void)
{
	int i, pid;

	SAFE_PIPE2(fds, O_DIRECT | O_NONBLOCK);

	pid = SAFE_FORK();
	if (!pid) {
		SAFE_CLOSE(fds[1]);
		memset(rdbuf, 0, pipe_size);
		TST_CHECKPOINT_WAIT(0);
		for (i = 0; i < packet_num; i++) {
			TEST(SAFE_READ(0, fds[0], rdbuf, pipe_size));
			if (TST_RET != 1)
				tst_res(TFAIL,
					"Each read(2) doesn't read a separate packet, return %ld", TST_RET);
		}
		tst_res(TPASS, "Each read(2) reads a separate packet");
		 _exit(0);
	}

	SAFE_CLOSE(fds[0]);
	for (i = 0; i < packet_num; i++)
                SAFE_WRITE(1, fds[1], "x", 1);

        TEST(write(fds[1], "x", 1));
        if (TST_RET != -1) {
                tst_res(TFAIL, "write succeeded unexpectedly");
        } else {
                if (TST_ERR == EAGAIN)
                        tst_res(TPASS, "Each write(2) uses a separate packet");
                else
                        tst_res(TFAIL | TTERRNO, "write failed, expected EAGAIN but got");
        }
	TST_CHECKPOINT_WAKE(0);
	SAFE_CLOSE(fds[1]);
	tst_reap_children();
}

static void check_split(void)
{
	int i, pid;

	SAFE_PIPE2(fds, O_DIRECT);

	pid = SAFE_FORK();
	if (!pid) {
		SAFE_CLOSE(fds[1]);
		memset(rdbuf, 0, pipe_size);
		TST_CHECKPOINT_WAIT(0);
		for (i = 0; i < 2; i++) {
			TEST(SAFE_READ(0, fds[0], rdbuf, pipe_size));
			if (TST_RET != PIPE_BUF)
				tst_res(TFAIL,
					"write(higner than PIPE_BUF) split into multiple packet, return %ld", TST_RET);
		}
		tst_res(TPASS, "write(higner than PIPE_BUF) split into multiple packet");
		 _exit(0);
	}
	SAFE_CLOSE(fds[0]);
	SAFE_WRITE(1, fds[1], wrbuf, PIPE_BUF * 2);
	TST_CHECKPOINT_WAKE(0);
	SAFE_CLOSE(fds[1]);
	tst_reap_children();
}

static void check_discard(void)
{
	int pid;
	char tmp_buf[20];
	char tmp_secondbuf[20];

	SAFE_PIPE2(fds, O_DIRECT);

	pid = SAFE_FORK();
	if (!pid) {
		SAFE_CLOSE(fds[1]);
		TST_CHECKPOINT_WAIT(0);
		TEST(SAFE_READ(0, fds[0], tmp_buf, 20));
		if (TST_RET != 20)
			tst_res(TFAIL,
				"the excess bytes in the packet isn't discarded by read, return %ld", TST_RET);
		TEST(SAFE_READ(0, fds[0], tmp_secondbuf, 20));
		if (TST_RET == 1) {
			if (!memcmp(tmp_secondbuf, "1", 1))
				tst_res(TPASS,
					"the excess bytes in the packet is discarded by read, only read 1");
			else
				tst_res(TFAIL,
					"the excess bytes in the packet is discarded by read, expect 1 got %s", tmp_secondbuf);
		}
		 _exit(0);
	}
	SAFE_CLOSE(fds[0]);
	SAFE_WRITE(1, fds[1], wrbuf, PIPE_BUF);
	SAFE_WRITE(1, fds[1], "1", 1);
	TST_CHECKPOINT_WAKE(0);
	SAFE_CLOSE(fds[1]);
	tst_reap_children();
}

static void verify_pipe2(unsigned int n)
{
	(*test_func[n])();
}

static void setup(void)
{
	SAFE_PIPE2(fds, O_DIRECT);
	pipe_size = SAFE_FCNTL(fds[1], F_GETPIPE_SZ);
	wrbuf = SAFE_MALLOC(PIPE_BUF * 2);
	rdbuf = SAFE_MALLOC(pipe_size);
	memset(wrbuf, 'x', PIPE_BUF * 2);
	packet_num = pipe_size / PIPE_BUF;
	SAFE_CLOSE(fds[0]);
	SAFE_CLOSE(fds[1]);
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

static struct tst_test test = {
	.setup = setup,
	.cleanup = cleanup,
	.forks_child = 1,
	.test = verify_pipe2,
	.tcnt = ARRAY_SIZE(test_func),
	.needs_checkpoints = 1,
};
