// SPDX-License-Identifier: LGPL-2.1-only
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

void test_cpu_pointer(void)
{
	cpu_set_t affinity, test_affinity;
	int ret, i;

	diag("testing current cpu");

	ret = sched_getaffinity(0, sizeof(affinity), &affinity);
	ok(ret == 0, "Get current thread affinity mask");

	CPU_ZERO(&test_affinity);
	for (i = 0; i < CPU_SETSIZE; i++) {
		if (CPU_ISSET(i, &affinity)) {
			CPU_SET(i, &test_affinity);

			ret = sched_setaffinity(0, sizeof(test_affinity),
					&test_affinity);
			ok(ret == 0, "Set affinity mask to CPU %d exclusively", i);

			ok(sched_getcpu() == i, "sched_getcpu returns CPU %d", i);
			ok(rseq_current_cpu() == (unsigned int) i, "rseq_current_cpu returns CPU %d", i);
			ok(rseq_current_cpu_raw() == i, "rseq_current_cpu_raw returns CPU %d", i);
			ok(rseq_cpu_start() == (unsigned int) i, "rseq_cpu_start returns CPU %d", i);

			CPU_CLR(i, &test_affinity);
		}
	}

	ret = sched_setaffinity(0, sizeof(affinity), &affinity);
	ok(ret == 0, "Restore current thread initial affinity mask");
}

int main(void)
{

	plan_no_plan();

	if (rseq_register_current_thread()) {
		fprintf(stderr, "Error: rseq_register_current_thread(...) failed(%d): %s\n",
			errno, strerror(errno));
		goto init_thread_error;
	}

	test_cpu_pointer();

	if (rseq_unregister_current_thread()) {
		fprintf(stderr, "Error: rseq_unregister_current_thread(...) failed(%d): %s\n",
			errno, strerror(errno));
		goto init_thread_error;
	}

	exit(EXIT_SUCCESS);

init_thread_error:
	exit(EXIT_FAILURE);;
}
