// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
/*
 * rseq memory pool test.
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
#include <inttypes.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include <rseq/mempool.h>
#include "../src/rseq-utils.h"

#include "list.h"
#include "tap.h"

#if RSEQ_BITS_PER_LONG == 64
# define POISON_VALUE	0xABCDABCDABCDABCDULL
#else
# define POISON_VALUE	0xABCDABCDUL
#endif

struct test_data {
	uintptr_t value;
	struct test_data __rseq_percpu *backref;
	struct list_head node;
};

static void test_mempool_fill(unsigned long max_nr_ranges, size_t stride)
{
	struct test_data __rseq_percpu *ptr;
	struct test_data *iter, *tmp;
	struct rseq_mempool *mempool;
	struct rseq_mempool_attr *attr;
	uint64_t count = 0;
	LIST_HEAD(list);
	int ret, i;

	attr = rseq_mempool_attr_create();
	ok(attr, "Create pool attribute");
	ret = rseq_mempool_attr_set_robust(attr);
	ok(ret == 0, "Setting mempool robust attribute");
	ret = rseq_mempool_attr_set_percpu(attr, stride, CPU_SETSIZE);
	ok(ret == 0, "Setting mempool percpu type");
	ret = rseq_mempool_attr_set_max_nr_ranges(attr, max_nr_ranges);
	ok(ret == 0, "Setting mempool max_nr_ranges=%lu", max_nr_ranges);
	ret = rseq_mempool_attr_set_poison(attr, POISON_VALUE);
	ok(ret == 0, "Setting mempool poison");
	mempool = rseq_mempool_create("test_data",
			sizeof(struct test_data), attr);
	ok(mempool, "Create mempool of size %zu", stride);
	rseq_mempool_attr_destroy(attr);

	for (;;) {
		struct test_data *cpuptr;

		ptr = (struct test_data __rseq_percpu *) rseq_mempool_percpu_zmalloc(mempool);
		if (!ptr)
			break;
		/* Link items in cpu 0. */
		cpuptr = rseq_percpu_ptr(ptr, 0, stride);
		cpuptr->backref = ptr;
		/* Randomize items in list. */
		if (count & 1)
			list_add(&cpuptr->node, &list);
		else
			list_add_tail(&cpuptr->node, &list);
		count++;
	}

	ok(count * sizeof(struct test_data) == stride * max_nr_ranges,
		"Allocated %" PRIu64 " objects in pool", count);

	list_for_each_entry(iter, &list, node) {
		ptr = iter->backref;
		for (i = 0; i < CPU_SETSIZE; i++) {
			struct test_data *cpuptr = rseq_percpu_ptr(ptr, i, stride);

			if (cpuptr->value != 0)
				abort();
			cpuptr->value++;
		}
	}

	ok(1, "Check for pool content corruption");

	list_for_each_entry_safe(iter, tmp, &list, node) {
		ptr = iter->backref;
		rseq_mempool_percpu_free(ptr, stride);
	}
	ret = rseq_mempool_destroy(mempool);
	ok(ret == 0, "Destroy mempool");
}

static void test_robust_double_free(struct rseq_mempool *pool)
{
	struct test_data __rseq_percpu *ptr;

	ptr = (struct test_data __rseq_percpu *) rseq_mempool_percpu_malloc(pool);

	rseq_mempool_percpu_free(ptr);
	rseq_mempool_percpu_free(ptr);
}

static void test_robust_corrupt_after_free(struct rseq_mempool *pool)
{
	struct test_data __rseq_percpu *ptr;
	struct test_data *cpuptr;

	ptr = (struct test_data __rseq_percpu *) rseq_mempool_percpu_malloc(pool);
	cpuptr = (struct test_data *) rseq_percpu_ptr(ptr, 0);

	rseq_mempool_percpu_free(ptr);
	cpuptr->value = (uintptr_t) test_robust_corrupt_after_free;

	rseq_mempool_destroy(pool);
}

static void test_robust_memory_leak(struct rseq_mempool *pool)
{
	(void) rseq_mempool_percpu_malloc(pool);

	rseq_mempool_destroy(pool);
}

static void test_robust_free_list_corruption(struct rseq_mempool *pool)
{
	struct test_data __rseq_percpu *ptr;
	struct test_data *cpuptr;

	ptr = (struct test_data __rseq_percpu *) rseq_mempool_percpu_malloc(pool);
	cpuptr = (struct test_data *) rseq_percpu_ptr(ptr, 0);

	rseq_mempool_percpu_free(ptr);

	cpuptr->value = (uintptr_t) cpuptr;

	(void) rseq_mempool_percpu_malloc(pool);
	(void) rseq_mempool_percpu_malloc(pool);
}

static int run_robust_test(void (*test)(struct rseq_mempool*),
			struct rseq_mempool *pool)
{
	pid_t cpid;
	int status;

	cpid = fork();

	switch (cpid) {
	case -1:
		return 0;
	case 0:
		test(pool);
		_exit(EXIT_FAILURE);
	default:
		waitpid(cpid, &status, 0);
	}

	if (WIFSIGNALED(status) &&
	    (SIGABRT == WTERMSIG(status)))
		return 1;

	return 0;
}

static void run_robust_tests(void)
{
	struct rseq_mempool_attr *attr;
	struct rseq_mempool *pool;
	int ret;

	attr = rseq_mempool_attr_create();
	ok(attr, "Create mempool attributes");

	ret = rseq_mempool_attr_set_robust(attr);
	ok(ret == 0, "Setting mempool robust attribute");

	ret = rseq_mempool_attr_set_percpu(attr, RSEQ_MEMPOOL_STRIDE, 1);
	ok(ret == 0, "Setting mempool percpu type");

	pool = rseq_mempool_create("mempool-robust",
				sizeof(void*), attr);

	rseq_mempool_attr_destroy(attr);

	ok(run_robust_test(test_robust_double_free, pool),
		"robust-double-free");

	ok(run_robust_test(test_robust_corrupt_after_free, pool),
		"robust-corrupt-after-free");

	ok(run_robust_test(test_robust_memory_leak, pool),
		"robust-memory-leak");

	ok(run_robust_test(test_robust_free_list_corruption, pool),
		"robust-free-list-corruption");

	rseq_mempool_destroy(pool);
}

int main(void)
{
	size_t len;
	unsigned long nr_ranges;

	plan_no_plan();

	for (nr_ranges = 1; nr_ranges < 32; nr_ranges <<= 1) {
		/* From page size to 64kB */
		for (len = rseq_get_page_len(); len < 65536; len <<= 1) {
			test_mempool_fill(nr_ranges, len);
		}
	}

	len = rseq_get_page_len();
	if (len < 65536)
		len = 65536;
	/* From min(page size, 64kB) to 4MB */
	for (; len < 4096 * 1024; len <<= 1)
		test_mempool_fill(1, len);

	run_robust_tests();

	exit(exit_status());
}
