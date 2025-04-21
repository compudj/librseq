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
#include <inttypes.h>

#include <rseq/rseq.h>
#include <rseq/percpu-counter-tree.h>

#include "tap.h"

#define NR_ITER 1000000000ULL
#define NSEC_PER_SEC 1000000000LL

static unsigned long global_count;

static int64_t difftimespec_ns(const struct timespec after, const struct timespec before)
{
	return ((int64_t)after.tv_sec - (int64_t)before.tv_sec) * NSEC_PER_SEC
		+ ((int64_t)after.tv_nsec - (int64_t)before.tv_nsec);
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
void benchmark_global_counter_inc(void)
{
	struct timespec t1, t2;
	uint64_t i;
	int64_t total_time = 0;

	printf("Benchmark: %s\n", __func__);

	clock_gettime(CLOCK_MONOTONIC, &t1);
	for (i = 0; i < NR_ITER; i++) {
		(void)__atomic_add_fetch(&global_count, 1, __ATOMIC_RELAXED);
	}
	clock_gettime(CLOCK_MONOTONIC, &t2);
	total_time += difftimespec_ns(t2, t1);
	printf("Benchmark %s: total time: %.2f s, %.2f ns/iter\n",
		__func__, (double)total_time / NSEC_PER_SEC, (double)total_time / NR_ITER);
}

static
void benchmark_counter_inc(unsigned long batch_size, enum percpu_counter_tree_type type)
{
	struct timespec t1, t2;
	struct percpu_counter_tree *counter;
	uint64_t i;
	int64_t total_time = 0;

	counter = percpu_counter_tree_alloc(batch_size, type);
	if (!counter)
		abort();
	printf("Benchmark: %s\n", __func__);

	clock_gettime(CLOCK_MONOTONIC, &t1);
	for (i = 0; i < NR_ITER; i++) {
		percpu_counter_tree_add(counter, 1);
	}
	clock_gettime(CLOCK_MONOTONIC, &t2);
	print_report(counter);
	percpu_counter_tree_destroy(counter);
	total_time += difftimespec_ns(t2, t1);
	printf("Benchmark %s: total time: %.2f s, %.2f ns/iter\n",
		__func__, (double)total_time / NSEC_PER_SEC, (double)total_time / NR_ITER);
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

	benchmark_global_counter_inc();
	printf("Byte counter\n");
	benchmark_counter_inc(32, PERCPU_COUNTER_TREE_TYPE_BYTE);
	printf("Long counter\n");
	benchmark_counter_inc(32, PERCPU_COUNTER_TREE_TYPE_LONG);

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
