// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2020 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
/*
 * Basic test coverage for critical regions and rseq_current_cpu().
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include <rseq/rseq.h>

#include "tap.h"

static void test_cpu_pointer(void)
{
	cpu_set_t affinity, test_affinity;
	int ret, i;

	ret = sched_getaffinity(0, sizeof(affinity), &affinity);
	ok(ret == 0, "Get current thread affinity mask");

	CPU_ZERO(&test_affinity);
	for (i = 0; i < CPU_SETSIZE; i++) {
		if (CPU_ISSET(i, &affinity)) {
			int node;

			CPU_SET(i, &test_affinity);

			ret = sched_setaffinity(0, sizeof(test_affinity),
					&test_affinity);
			ok(ret == 0, "Set affinity mask to CPU %d exclusively", i);

			ok(sched_getcpu() == i, "sched_getcpu returns CPU %d", i);
			ok(rseq_current_cpu() == (unsigned int) i, "rseq_current_cpu returns CPU %d", i);
			ok(rseq_current_cpu_raw() == i, "rseq_current_cpu_raw returns CPU %d", i);
			ok(rseq_cpu_start() == (unsigned int) i, "rseq_cpu_start returns CPU %d", i);
			node = rseq_fallback_current_node();
			ok(rseq_fallback_current_node() == node, "rseq_fallback_current_node returns node %d", node);
			CPU_CLR(i, &test_affinity);
		}
	}

	ret = sched_setaffinity(0, sizeof(affinity), &affinity);
	ok(ret == 0, "Restore current thread initial affinity mask");
}

int main(void)
{
	/*
	 * Skip all tests if the rseq syscall is unavailable
	 */
	if (rseq_available(RSEQ_AVAILABLE_QUERY_KERNEL)) {
		plan_no_plan();
	} else {
		plan_skip_all("The rseq syscall is unavailable");
	}

	if (rseq_register_current_thread()) {
		fail("rseq_register_current_thread(...) failed(%d): %s\n",
			errno, strerror(errno));
		goto end;
	} else {
		pass("Registered current thread with rseq");
	}

	test_cpu_pointer();

	if (rseq_unregister_current_thread()) {
		fail("rseq_unregister_current_thread(...) failed(%d): %s\n",
			errno, strerror(errno));
		goto end;
	} else {
		pass("Unregistered current thread with rseq");
	}

end:
	exit(exit_status());
}
