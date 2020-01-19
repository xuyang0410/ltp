// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2020 FUJITSU LIMITED. All rights reserved.
 * Author: Yang Xu <xuyang2018.jy@cn.fujitsu.com>
 *
 * This case test various key type can support how many long
 * bytes payload.
 * keyring: 0 bytes
 * user/logon: 32767 bytes
 * big_key: 1M -1byte
 */

#include <errno.h>
#include "tst_test.h"
#include "lapi/keyctl.h"

struct tcase {
	const char *type;
	const char *desc;
	size_t plen;
	int pass_flag;
	char *message;
} tcases[] = {
	{"keyring", "abc", 0, 1,
	"The key type is keyrings and plen is 0"},

	{"keyring", "bcd", 1, 0,
	"the key type is keyrings and plen is 1"},

	{"user", "cde", 32767, 1,
	"The key type is user and plen is 32767"},

	{"user", "def", 32768, 0,
	"The key type is user and plen is 32768"},

	{"logon", "ef:g", 32767, 1,
	"The key type is logon and plen is 32767"},

	{"logon", "fg:h", 32768, 0,
	"The key type is logon and plen is 32768"},

	{"big_key", "ghi", (1 << 20) - 1, 1,
	"The key type is big_key and plen is 1048575"},

	{"big_key", "hij", 1 << 20, 0,
	"The key type is big_key and plen is 1048576"},
};

static char *buf;
static unsigned int logon_nsup, big_key_nsup;

static void verify_add_key(unsigned int n)
{
	struct tcase *tc = &tcases[n];

	tst_res(TINFO, "%s", tc->message);

	if (!strcmp(tc->type, "logon") && logon_nsup) {
		tst_res(TINFO,
			"current system doesn't support logon key type, skip it");
		return;
	}
	if (!strcmp(tc->type, "big_key") && big_key_nsup) {
		tst_res(TINFO,
			"current system doesn't support big_key key type, skip it");
		return;
	}

	TEST(add_key(tc->type, tc->desc, buf, tc->plen, KEY_SPEC_THREAD_KEYRING));
	if (TST_RET == -1) {
		if (TST_ERR == EINVAL)
			tst_res(tc->pass_flag ? TFAIL : TPASS, "add_key call failed as expected");
		else
			tst_res(TFAIL | TTERRNO, "add_key call failed expected EINVAL but got");
		return;
	}
	tst_res(tc->pass_flag ? TPASS : TFAIL, "add_key call succeeded");
}

static void setup(void)
{
	TEST(add_key("logon", "test:sup_logon", buf, 64, KEY_SPEC_THREAD_KEYRING));
	if (TST_RET == -1)
		logon_nsup = 1;

	TEST(add_key("big_key", "sup_big_key", buf, 64, KEY_SPEC_THREAD_KEYRING));
	if (TST_RET == 0)
		big_key_nsup = 1;
}

static struct tst_test test = {
	.setup = setup,
	.tcnt = ARRAY_SIZE(tcases),
	.test = verify_add_key,
	.bufs = (struct tst_buffers []) {
		{&buf, .size = 1 << 20},
		{}
	}
};
