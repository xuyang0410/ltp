// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2020 FUJITSU LIMITED. All rights reserved.
 * Author: Yang Xu <xuyang2018.jy@cn.fujitsu.com>
 *
 *Description:
 * Test unprivileged user can support the number of keys and the
 * number of bytes consumed in payloads of the keys.The defalut value
 * is 200 and 20000.
 * This is also a regresstion test for
 * commit a08bf91ce28e ("KEYS: allow reaching the keys quotas exact")
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <pwd.h>
#include "tst_test.h"
#include "lapi/keyctl.h"

static char *user_buf, *user_buf1, *keyring_buf;
static const char *username = "ltp_add_key05";
static int user_added;
struct passwd *ltpuser;
static unsigned int used_bytes, max_bytes, used_key, max_key, data_len;
char fmt[1024];
int flag[2] = {1, 0};

void add_user(void)
{
	if (user_added)
		return;

	const char *const cmd_useradd[] = {"useradd", username, NULL};
	int rc;

	switch ((rc = tst_run_cmd(cmd_useradd, NULL, NULL, 1))) {
	case 0:
		user_added = 1;
		ltpuser = SAFE_GETPWNAM(username);
		break;
	case 1:
	case 255:
		break;
	default:
		tst_brk(TBROK, "Useradd failed (%d)", rc);
	}
	sprintf(fmt, "%5u: %%*5d %%*d/%%*d %%d/%%d %%d/%%d", ltpuser->pw_uid);
}

void clean_user(void)
{
	if (!user_added)
		return;

	const char *const cmd_userdel[] = {"userdel", "-r", username, NULL};

	if (tst_run_cmd(cmd_userdel, NULL, NULL, 1))
		tst_res(TWARN | TERRNO, "'userdel -r %s' failed", username);
	else
		user_added = 0;
}

void verify_max_btyes(void)
{
	char *buf, *invalid_buf;
	int plen, invalid_plen;

	tst_res(TINFO, "test max bytes under unprivileged user");
	invalid_plen = max_bytes - used_bytes - data_len - 8;
	plen = invalid_plen - 1;
	buf = tst_alloc(plen);
	invalid_buf = tst_alloc(invalid_plen);

	TEST(add_key("user", "test_inv", invalid_buf, invalid_plen, KEY_SPEC_THREAD_KEYRING));
	if (TST_RET != -1)
		tst_res(TFAIL, "add_key(test_inv) succeeded unexpectedltly");
	else {
		if (TST_ERR == EDQUOT)
			tst_res(TPASS | TTERRNO, "add_key(test_inv) failed as expected");
		else
			tst_res(TFAIL | TTERRNO, "add_key(test_inv) failed expected EDQUOT got");
	}

	TEST(add_key("user", "test_max", buf, plen, KEY_SPEC_THREAD_KEYRING));
	if (TST_RET != -1) {
		tst_res(TPASS, "add_key(test_max) succeeded as expected");
		SAFE_FILE_LINES_SCANF("/proc/key-users", fmt, &used_key, &max_key, &used_bytes, &max_bytes);
		if (used_bytes == max_bytes)
			tst_res(TPASS, "allow reaching the max bytes exactly");
		else
			tst_res(TFAIL, "max used bytes %u, key allow max bytes %u", used_bytes, max_bytes);
	} else
		tst_res(TFAIL | TTERRNO, "add_key(test_max) failed unexpectedly");
}

void verify_max_keys(void)
{
	unsigned int i;
	char desc[10];

	tst_res(TINFO, "test max keys under unprivileged user");
	for (i = used_key + 1; i < max_key; i++) {
		sprintf(desc, "abc%d", i);
		TEST(add_key("keyring", desc, keyring_buf, 0, KEY_SPEC_THREAD_KEYRING));
		if (TST_RET == -1)
			tst_res(TFAIL | TTERRNO, "add keyring key(%s) failed", desc);
	}

	TEST(add_key("keyring", "abc200", keyring_buf, 0, KEY_SPEC_THREAD_KEYRING));
	if (TST_RET == -1) {
		tst_res(TFAIL | TTERRNO, "add keyring key(abc200) failed");
		goto count;
	} else
		tst_res(TPASS, "add keyring key(abc200) succedd");

	TEST(add_key("keyring", "abc201", keyring_buf, 0, KEY_SPEC_THREAD_KEYRING));
	if (TST_RET != -1) {
		tst_res(TFAIL, "add keyring key(abc201) succeeded unexpectedly");
		goto count;
	} else {
		if (TST_ERR == EDQUOT)
			tst_res(TPASS | TTERRNO, "add keyring key(abc201) failed as expected over max key");
		else
			tst_res(TFAIL | TTERRNO, "add_keyring failed expected EDQUOT got");
	}
count:
	SAFE_FILE_LINES_SCANF("/proc/key-users", fmt, &used_key, &max_key, &used_bytes, &max_bytes);
	if (used_key == max_key)
		tst_res(TPASS, "allow reaching the max key exactly");
	else
		tst_res(TFAIL, "max used key %u, key allow max key %u", used_key, max_key);
}

static void do_test(unsigned int n)
{
	add_user();
	int f_used_bytes = 0;

	if (!SAFE_FORK()) {
		SAFE_SETUID(ltpuser->pw_uid);

		TEST(add_key("user", "test1", user_buf, 64, KEY_SPEC_THREAD_KEYRING));
		if (TST_RET == -1)
			tst_brk(TFAIL | TTERRNO, "add key test1 failed");
		SAFE_FILE_LINES_SCANF("/proc/key-users", fmt, &used_key, &max_key, &used_bytes, &max_bytes);
		f_used_bytes = used_bytes;

		TEST(add_key("user", "test2", user_buf1, 64, KEY_SPEC_THREAD_KEYRING));
		if (TST_RET == -1)
			tst_brk(TFAIL | TTERRNO, "add key test2 failed");
		SAFE_FILE_LINES_SCANF("/proc/key-users", fmt, &used_key, &max_key, &used_bytes, &max_bytes);

		data_len = used_bytes - f_used_bytes - strlen("test1") - 1 - 64;
		if (flag[n])
			verify_max_btyes();
		else
			verify_max_keys();
		exit(0);
	}
	tst_reap_children();
	clean_user();
}

static struct tst_test test = {
	.test = do_test,
	.tcnt = 2,
	.needs_root = 1,
	.forks_child = 1,
	.cleanup = clean_user,
	.bufs = (struct tst_buffers []) {
		{&keyring_buf, .size = 1},
		{&user_buf, .size = 64},
		{&user_buf1, .size = 64},
		{}
	},
	.tags = (const struct tst_tag[]) {
		{"linux-git", "a08bf91ce28"},
		{}
	}
};
