// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2025 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
/*
 * Percpu counter test
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
#include <stdlib.h>

#include <rseq/rseq.h>
#include <rseq/percpu-counter.h>

#include "tap.h"

static struct percpu_counter counter;

static
void print_report(struct percpu_counter *arg_counter)
{
	long approx, precise;

	approx = counter_approx_sum(arg_counter);
	precise = counter_precise_sum(arg_counter);
	printf("Counter after sum: approx: %ld precise: %ld delta: %ld max_inaccuracy: ±%ld\n",
		approx, precise, approx - precise,
		counter_inaccuracy(&counter));
}

static
void counter_check(struct percpu_counter *arg_counter)
{
	long approx, precise;

	approx = counter_approx_sum(arg_counter);
	precise = counter_precise_sum(arg_counter);
	if (labs(precise - approx) > counter_inaccuracy(arg_counter)) {
		printf("ERROR !!!! too large delta detected: %ld.\n", approx - precise);
		print_report(arg_counter);
		abort();
	}
}

static
void test_counter_incdec(void)
{
	long i;
	int ret;

	ret = counter_init(&counter, 32);
	if (ret)
		abort();
	printf("Testing: %s\n", __func__);
	srand(time(NULL));

	for (i = 0; i < 10000000; i++) {
		int v1 = rand() - (RAND_MAX / 2);
		int v2 = rand() - (RAND_MAX / 2);

		counter_add(&counter, v1);
		counter_add(&counter, -v2);
		counter_add(&counter, -v1);
		counter_add(&counter, v2);

		counter_check(&counter);
	}
	print_report(&counter);
	counter_destroy(&counter);
}

static
void test_counter_random(void)
{
	long i;
	int ret;

	printf("Testing: %s\n", __func__);
	srand(time(NULL));
	ret = counter_init(&counter, 32);
	if (ret)
		abort();

	for (i = 0; i < 1000000; i++) {
		int v = rand() - (RAND_MAX / 2);

		counter_add(&counter, v);
		counter_check(&counter);
	}
	print_report(&counter);
	counter_destroy(&counter);
}

static
void test_counter_random_cpu_hop(void)
{
	long i;
	int ret;

	printf("Testing: %s\n", __func__);

	srand(time(NULL));
	ret = counter_init(&counter, 32);
	if (ret)
		abort();

	for (i = 0; i < 10000; i++) {
		cpu_set_t affinity, test_affinity;
		int j;

		ret = sched_getaffinity(0, sizeof(affinity), &affinity);
		if (ret)
			abort();

		CPU_ZERO(&test_affinity);
		for (j = 0; j < CPU_SETSIZE; j++) {
			if (CPU_ISSET(j, &affinity)) {
				int v;

				CPU_SET(j, &test_affinity);
				ret = sched_setaffinity(0, sizeof(test_affinity), &test_affinity);
				if (ret)
					abort();
				v = rand() - (RAND_MAX / 2);
				counter_add(&counter, v);
				counter_check(&counter);
				CPU_CLR(j, &test_affinity);
			}
		}

		ret = sched_setaffinity(0, sizeof(affinity), &affinity);
		if (ret)
			abort();
	}
	print_report(&counter);
	counter_destroy(&counter);
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

	test_counter_incdec();
	test_counter_random();
	test_counter_random_cpu_hop();

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
