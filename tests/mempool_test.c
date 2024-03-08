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

#include <rseq/mempool.h>

#include "list.h"
#include "tap.h"

struct test_data {
	uintptr_t value;
	struct test_data __rseq_percpu *backref;
	struct list_head node;
};

static void test_mempool_fill(size_t len)
{
	struct test_data __rseq_percpu *ptr;
	struct test_data *iter, *tmp;
	struct rseq_percpu_pool *mempool;
	struct rseq_pool_attr *attr;
	uint64_t count = 0;
	LIST_HEAD(list);
	int ret, i;

	attr = rseq_pool_attr_create();
	ret = rseq_pool_attr_set_robust(attr);
	ok(ret == 0, "Setting mempool robust attribute");

	mempool = rseq_percpu_pool_create("test_data",
			sizeof(struct test_data),
			len, CPU_SETSIZE, attr);
	ok(mempool, "Create mempool of size %zu", len);
	rseq_pool_attr_destroy(attr);

	for (;;) {
		struct test_data *cpuptr;

		ptr = (struct test_data __rseq_percpu *) rseq_percpu_zmalloc(mempool);
		if (!ptr)
			break;
		/* Link items in cpu 0. */
		cpuptr = rseq_percpu_ptr(ptr, 0);
		cpuptr->backref = ptr;
		/* Randomize items in list. */
		if (count & 1)
			list_add(&cpuptr->node, &list);
		else
			list_add_tail(&cpuptr->node, &list);
		count++;
	}

	ok(count * sizeof(struct test_data) == len, "Allocated %" PRIu64 " objects in pool", count);

	list_for_each_entry(iter, &list, node) {
		ptr = iter->backref;
		for (i = 0; i < CPU_SETSIZE; i++) {
			struct test_data *cpuptr = rseq_percpu_ptr(ptr, i);

			if (cpuptr->value != 0)
				abort();
			cpuptr->value++;
		}
	}

	ok(1, "Check for pool content corruption");

	list_for_each_entry_safe(iter, tmp, &list, node) {
		ptr = iter->backref;
		rseq_percpu_free(ptr);
	}
	ret = rseq_percpu_pool_destroy(mempool);
	ok(ret == 0, "Destroy mempool");
}

int main(void)
{
	size_t len;

	/* From 4kB to 4MB */
	for (len = 4096; len < 4096 * 1024; len <<= 1) {
		test_mempool_fill(len);
	}

	exit(exit_status());
}
