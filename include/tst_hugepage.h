// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2019 Red Hat, Inc.
 */

#ifndef TST_HUGEPAGE__
#define TST_HUGEPAGE__

#define PATH_HUGEPAGES	"/sys/kernel/mm/hugepages/"
#define PATH_NR_HPAGES	"/proc/sys/vm/nr_hugepages"

/*
 * Try the best to request a specified number of huge pages from system,
 * it will store the reserved hpage number in tst_hugepages.
 *
 * Note: this depend on the status of system memory fragmentation.
 */
int tst_request_hugepages(int hpages);

/*
 * This variable is used for recording the number of hugepages which system can
 * provides. It will be equal to 'hpages' if tst_request_hugepages on success,
 * otherwise set it to a number of hugepages that we were able to reserve.
 *
 * If system does not support hugetlb, then it will be set to 0.
 */
extern unsigned int tst_hugepages;

#endif /* TST_HUGEPAGE_H */
