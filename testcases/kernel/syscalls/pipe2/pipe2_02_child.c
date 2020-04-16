// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2020 FUJITSU LIMITED. All rights reserved.
 * Author: Yang Xu <xuyang2018.jy@cn.fujitsu.com
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	int ret;
	int fd;

	if (argc != 2) {
		fprintf(stderr, "Only two arguments: %s <fd>\n", argv[0]);
		exit(1);
	}

	fd = atoi(argv[1]);
	ret = write(fd, "x", 1);

	return ret != -1;
}
