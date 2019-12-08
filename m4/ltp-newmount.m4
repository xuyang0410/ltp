dnl SPDX-License-Identifier: GPL-2.0-or-later
dnl Copyright (C) 2019 Red Hat, Inc. All Rights Reserved.

AC_DEFUN([LTP_CHECK_NEWMOUNT],[
AC_CHECK_FUNCS(fsopen,,)
AC_CHECK_FUNCS(fsconfig,,)
AC_CHECK_FUNCS(fsmount,,)
AC_CHECK_FUNCS(move_mount,,)
AC_CHECK_HEADER(sys/mount.h,,,)
])
