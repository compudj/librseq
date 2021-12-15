// SPDX-License-Identifier: LGPL-2.1-only
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

#include <rseq/rseq.h>

#include "tap.h"

#define NR_TESTS 4

#define ARRAY_SIZE(arr)	(sizeof(arr) / sizeof((arr)[0]))

struct percpu_list_node {
	intptr_t data;
	struct percpu_list_node *next;
};

struct percpu_list_entry {
	struct percpu_list_node *head;
} __attribute__((aligned(128)));

struct percpu_list {
	struct percpu_list_entry c[CPU_SETSIZE];
};

/*
 * Unlike a traditional lock-less linked list; the availability of a
 * rseq primitive allows us to implement pop without concerns over
 * ABA-type races.
 */
struct percpu_list_node *this_cpu_list_pop(struct percpu_list *list,
					   int *_cpu)
{
	for (;;) {
		struct percpu_list_node *head;
		intptr_t *targetptr, expectnot, *load;
		off_t offset;
		int ret, cpu;

		cpu = rseq_cpu_start();
		targetptr = (intptr_t *)&list->c[cpu].head;
		expectnot = (intptr_t)NULL;
		offset = offsetof(struct percpu_list_node, next);
		load = (intptr_t *)&head;
		ret = rseq_cmpnev_storeoffp_load(targetptr, expectnot,
						 offset, load, cpu);
		if (rseq_likely(!ret)) {
			if (_cpu)
				*_cpu = cpu;
			return head;
		}
		if (ret > 0)
			return NULL;
		/* Retry if rseq aborts. */
	}
}
