// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2019 Red Hat, Inc.  All rights reserved.
 * Author: Zorro Lang <zlang@redhat.com>
 */

#ifndef NEWMOUNT_H__
#define NEWMOUNT_H__

#include <stdint.h>
#include <unistd.h>
#include "config.h"
#include "lapi/syscalls.h"

#if !defined(HAVE_NEWMOUNT)
static inline int fsopen(const char *fs_name, unsigned int flags)
{
	return tst_syscall(__NR_fsopen, fs_name, flags);
}

/*
 * fsopen() flags.
 */
#define FSOPEN_CLOEXEC		0x00000001

static inline int fsconfig(int fsfd, unsigned int cmd,
                           const char *key, const void *val, int aux)
{
	return tst_syscall(__NR_fsconfig, fsfd, cmd, key, val, aux);
}

/*
 * The type of fsconfig() call made.
 */
enum fsconfig_command {
	FSCONFIG_SET_FLAG	= 0,    /* Set parameter, supplying no value */
	FSCONFIG_SET_STRING	= 1,    /* Set parameter, supplying a string value */
	FSCONFIG_SET_BINARY	= 2,    /* Set parameter, supplying a binary blob value */
	FSCONFIG_SET_PATH	= 3,    /* Set parameter, supplying an object by path */
	FSCONFIG_SET_PATH_EMPTY	= 4,    /* Set parameter, supplying an object by (empty) path */
	FSCONFIG_SET_FD		= 5,    /* Set parameter, supplying an object by fd */
	FSCONFIG_CMD_CREATE	= 6,    /* Invoke superblock creation */
	FSCONFIG_CMD_RECONFIGURE = 7,   /* Invoke superblock reconfiguration */
};

static inline int fsmount(int fsfd, unsigned int flags, unsigned int ms_flags)
{
	return tst_syscall(__NR_fsmount, fsfd, flags, ms_flags);
}

/*
 * fsmount() flags.
 */
#define FSMOUNT_CLOEXEC		0x00000001

/*
 * Mount attributes.
 */
#define MOUNT_ATTR_RDONLY	0x00000001 /* Mount read-only */
#define MOUNT_ATTR_NOSUID	0x00000002 /* Ignore suid and sgid bits */
#define MOUNT_ATTR_NODEV	0x00000004 /* Disallow access to device special files */
#define MOUNT_ATTR_NOEXEC	0x00000008 /* Disallow program execution */
#define MOUNT_ATTR__ATIME	0x00000070 /* Setting on how atime should be updated */
#define MOUNT_ATTR_RELATIME	0x00000000 /* - Update atime relative to mtime/ctime. */
#define MOUNT_ATTR_NOATIME	0x00000010 /* - Do not update access times. */
#define MOUNT_ATTR_STRICTATIME	0x00000020 /* - Always perform atime updates */
#define MOUNT_ATTR_NODIRATIME	0x00000080 /* Do not update directory access times */

static inline int move_mount(int from_dfd, const char *from_pathname,
                             int to_dfd, const char *to_pathname,
                             unsigned int flags)
{
	return tst_syscall(__NR_move_mount, from_dfd, from_pathname, to_dfd,
	                   to_pathname, flags);
}

/*
 * move_mount() flags.
 */
#define MOVE_MOUNT_F_SYMLINKS		0x00000001 /* Follow symlinks on from path */
#define MOVE_MOUNT_F_AUTOMOUNTS		0x00000002 /* Follow automounts on from path */
#define MOVE_MOUNT_F_EMPTY_PATH		0x00000004 /* Empty from path permitted */
#define MOVE_MOUNT_T_SYMLINKS		0x00000010 /* Follow symlinks on to path */
#define MOVE_MOUNT_T_AUTOMOUNTS		0x00000020 /* Follow automounts on to path */
#define MOVE_MOUNT_T_EMPTY_PATH		0x00000040 /* Empty to path permitted */
#define MOVE_MOUNT__MASK		0x00000077

#endif /* HAVE_NEWMOUNT */
#endif /* NEWMOUNT_H__ */
