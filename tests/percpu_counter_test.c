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
#include <rseq/percpu-counter-tree.h>

#include "tap.h"

static
long get_value(struct percpu_counter_tree *counter, unsigned long batch_size)
{
	return (rand() - (RAND_MAX / 2)) & (((1UL << percpu_counter_get_depth(counter)) * batch_size) - 1);
}

static
void print_report(struct percpu_counter_tree *counter)
{
	long approx, precise;

	approx = percpu_counter_tree_approximate_sum(counter);
	precise = percpu_counter_tree_precise_sum(counter);
	printf("Counter after sum: approx: %ld precise: %ld delta: %ld max_inaccuracy: ±%ld\n",
		approx, precise, approx - precise,
		percpu_counter_tree_inaccuracy(counter));
}

static
void counter_check(struct percpu_counter_tree *counter, long cnt)
{
	long approx, precise;
	bool error = false;

	approx = percpu_counter_tree_approximate_sum(counter);
	precise = percpu_counter_tree_precise_sum(counter);
	if (precise != cnt) {
		printf("ERROR !!!! inexact precise counter sum: expected: %ld, precise sum: %ld.\n",
			cnt, precise);
		error = true;
	}
	if (labs(precise - approx) > percpu_counter_tree_inaccuracy(counter)) {
		printf("ERROR !!!! too large delta detected: %ld.\n", approx - precise);
		error = true;
	}
	if (error) {
		print_report(counter);
		abort();
	}
}

static
void test_counter_negative(unsigned long batch_size)
{
	struct percpu_counter_tree *counter;
	long cnt = 0, v = -1;

	counter = percpu_counter_tree_alloc(batch_size);
	if (!counter)
		abort();
	printf("Testing: %s\n", __func__);
	srand(time(NULL));

	percpu_counter_tree_add(counter, v);
	cnt += v;
	counter_check(counter, cnt);
	print_report(counter);
	percpu_counter_tree_destroy(counter);
}

static
void test_counter_incdec(unsigned long batch_size)
{
	struct percpu_counter_tree *counter;
	long cnt = 0, i;

	counter = percpu_counter_tree_alloc(batch_size);
	if (!counter)
		abort();
	printf("Testing: %s\n", __func__);
	srand(time(NULL));

	for (i = 0; i < 10000000; i++) {
		int v1 = get_value(counter, batch_size);
		int v2 = get_value(counter, batch_size);

		percpu_counter_tree_add(counter, v1);
		cnt += v1;
		percpu_counter_tree_add(counter, -v2);
		cnt -= v2;
		percpu_counter_tree_add(counter, -v1);
		cnt -= v1;
		percpu_counter_tree_add(counter, v2);
		cnt += v2;

		counter_check(counter, cnt);
	}
	print_report(counter);
	percpu_counter_tree_destroy(counter);
}

static
void test_counter_random(unsigned long batch_size)
{
	struct percpu_counter_tree *counter;
	long cnt = 0, i;

	printf("Testing: %s\n", __func__);
	srand(time(NULL));
	counter = percpu_counter_tree_alloc(batch_size);
	if (!counter)
		abort();

	for (i = 0; i < 1000000; i++) {
		int v = get_value(counter, batch_size);

		percpu_counter_tree_add(counter, v);
		cnt += v;

		counter_check(counter, cnt);
	}
	print_report(counter);
	percpu_counter_tree_destroy(counter);
}

static
void test_counter_random_cpu_hop(unsigned long batch_size)
{
	struct percpu_counter_tree *counter;
	long cnt = 0, i;
	int ret;

	printf("Testing: %s\n", __func__);

	srand(time(NULL));
	counter = percpu_counter_tree_alloc(batch_size);
	if (!counter)
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
				v = get_value(counter, batch_size);
				percpu_counter_tree_add(counter, v);
				cnt += v;
				counter_check(counter, cnt);
				CPU_CLR(j, &test_affinity);
			}
		}

		ret = sched_setaffinity(0, sizeof(affinity), &affinity);
		if (ret)
			abort();
	}
	print_report(counter);
	percpu_counter_tree_destroy(counter);
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

	test_counter_negative(32);
	test_counter_incdec(32);
	test_counter_random(32);
	test_counter_random_cpu_hop(32);

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
