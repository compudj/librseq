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
#include <stdbool.h>
#include <string.h>
#include <stddef.h>
#include <errno.h>

#include <rseq/percpu-op.h>

#define ARRAY_SIZE(arr)	(sizeof(arr) / sizeof((arr)[0]))

struct percpu_lock_entry {
	intptr_t v;
} __attribute__((aligned(128)));

struct percpu_lock {
	struct percpu_lock_entry c[CPU_SETSIZE];
};

struct test_data_entry {
	intptr_t count;
} __attribute__((aligned(128)));

struct spinlock_test_data {
	struct percpu_lock lock;
	struct test_data_entry c[CPU_SETSIZE];
	int reps;
};

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

static bool is_rseq_available;

/* A simple percpu spinlock. */
void rseq_percpu_lock(struct percpu_lock *lock, int cpu)
{
	for (;;) {
		int ret;

		ret = percpu_cmpeqv_storev(&lock->c[cpu].v,
					   0, 1, cpu);
		if (rseq_likely(!ret))
			break;
		if (rseq_unlikely(ret < 0)) {
			perror("cpu_opv");
			abort();
		}
		/* Retry if comparison fails. */
	}
	/*
	 * Acquire semantic when taking lock after control dependency.
	 * Matches rseq_smp_store_release().
	 */
	rseq_smp_acquire__after_ctrl_dep();
}

void rseq_percpu_unlock(struct percpu_lock *lock, int cpu)
{
	assert(lock->c[cpu].v == 1);
	/*
	 * Release lock, with release semantic. Matches
	 * rseq_smp_acquire__after_ctrl_dep().
	 */
	rseq_smp_store_release(&lock->c[cpu].v, 0);
}

void *test_percpu_spinlock_thread(void *arg)
{
	struct spinlock_test_data *data = arg;
	int i;

	if (is_rseq_available && rseq_register_current_thread()) {
		fprintf(stderr, "Error: rseq_register_current_thread(...) failed(%d): %s\n",
			errno, strerror(errno));
		abort();
	}
	for (i = 0; i < data->reps; i++) {
		int cpu = percpu_current_cpu();

		rseq_percpu_lock(&data->lock, cpu);
		data->c[cpu].count++;
		rseq_percpu_unlock(&data->lock, cpu);
	}
	if (is_rseq_available && rseq_unregister_current_thread()) {
		fprintf(stderr, "Error: rseq_unregister_current_thread(...) failed(%d): %s\n",
			errno, strerror(errno));
		abort();
	}

	return NULL;
}

/*
 * A simple test which implements a sharded counter using a per-cpu
 * lock.  Obviously real applications might prefer to simply use a
 * per-cpu increment; however, this is reasonable for a test and the
 * lock can be extended to synchronize more complicated operations.
 */
void test_percpu_spinlock(void)
{
	const int num_threads = 200;
	int i;
	uint64_t sum;
	pthread_t test_threads[num_threads];
	struct spinlock_test_data data;

	memset(&data, 0, sizeof(data));
	data.reps = 5000;

	for (i = 0; i < num_threads; i++)
		pthread_create(&test_threads[i], NULL,
			       test_percpu_spinlock_thread, &data);

	for (i = 0; i < num_threads; i++)
		pthread_join(test_threads[i], NULL);

	sum = 0;
	for (i = 0; i < CPU_SETSIZE; i++)
		sum += data.c[i].count;

	assert(sum == (uint64_t)data.reps * num_threads);
}

int percpu_list_push(struct percpu_list *list, struct percpu_list_node *node,
		     int cpu)
{
	for (;;) {
		intptr_t *targetptr, newval, expect;
		int ret;

		/* Load list->c[cpu].head with single-copy atomicity. */
		expect = (intptr_t)RSEQ_READ_ONCE(list->c[cpu].head);
		newval = (intptr_t)node;
		targetptr = (intptr_t *)&list->c[cpu].head;
		node->next = (struct percpu_list_node *)expect;
		ret = percpu_cmpeqv_storev(targetptr, expect, newval, cpu);
		if (rseq_likely(!ret))
			break;
		if (rseq_unlikely(ret < 0)) {
			perror("cpu_opv");
			abort();
		}
		/* Retry if comparison fails. */
	}
	return cpu;
}

/*
 * Unlike a traditional lock-less linked list; the availability of a
 * rseq primitive allows us to implement pop without concerns over
 * ABA-type races.
 */
struct percpu_list_node *percpu_list_pop(struct percpu_list *list,
					 int cpu)
{
	struct percpu_list_node *head;
	intptr_t *targetptr, expectnot, *load;
	off_t offset;
	int ret;

	targetptr = (intptr_t *)&list->c[cpu].head;
	expectnot = (intptr_t)NULL;
	offset = offsetof(struct percpu_list_node, next);
	load = (intptr_t *)&head;
	ret = percpu_cmpnev_storeoffp_load(targetptr, expectnot,
					   offset, load, cpu);
	if (rseq_unlikely(ret < 0)) {
		perror("cpu_opv");
		abort();
	}
	if (ret > 0)
		return NULL;
	return head;
}

void *test_percpu_list_thread(void *arg)
{
	int i;
	struct percpu_list *list = (struct percpu_list *)arg;

	if (is_rseq_available && rseq_register_current_thread()) {
		fprintf(stderr, "Error: rseq_register_current_thread(...) failed(%d): %s\n",
			errno, strerror(errno));
		abort();
	}

	for (i = 0; i < 100000; i++) {
		struct percpu_list_node *node;

		node = percpu_list_pop(list, percpu_current_cpu());
		sched_yield();  /* encourage shuffling */
		if (node)
			percpu_list_push(list, node, percpu_current_cpu());
	}

	if (is_rseq_available && rseq_unregister_current_thread()) {
		fprintf(stderr, "Error: rseq_unregister_current_thread(...) failed(%d): %s\n",
			errno, strerror(errno));
		abort();
	}

	return NULL;
}

/* Simultaneous modification to a per-cpu linked list from many threads.  */
void test_percpu_list(void)
{
	int i, j;
	uint64_t sum = 0, expected_sum = 0;
	struct percpu_list list;
	pthread_t test_threads[200];
	cpu_set_t allowed_cpus;

	memset(&list, 0, sizeof(list));

	/* Generate list entries for every usable cpu. */
	sched_getaffinity(0, sizeof(allowed_cpus), &allowed_cpus);
	for (i = 0; i < CPU_SETSIZE; i++) {
		if (!CPU_ISSET(i, &allowed_cpus))
			continue;
		for (j = 1; j <= 100; j++) {
			struct percpu_list_node *node;

			expected_sum += j;

			node = malloc(sizeof(*node));
			assert(node);
			node->data = j;
			node->next = list.c[i].head;
			list.c[i].head = node;
		}
	}

	for (i = 0; i < 200; i++)
		pthread_create(&test_threads[i], NULL,
		       test_percpu_list_thread, &list);

	for (i = 0; i < 200; i++)
		pthread_join(test_threads[i], NULL);

	for (i = 0; i < CPU_SETSIZE; i++) {
		struct percpu_list_node *node;

		if (!CPU_ISSET(i, &allowed_cpus))
			continue;

		while ((node = percpu_list_pop(&list, i))) {
			sum += node->data;
			free(node);
		}
	}

	/*
	 * All entries should now be accounted for (unless some external
	 * actor is interfering with our allowed affinity while this
	 * test is running).
	 */
	assert(sum == expected_sum);
}

int main(void)
{
	is_rseq_available = rseq_available();
	if (!is_rseq_available)
		fprintf(stderr, "Warning: rseq is not available\n");
	if (!cpu_op_available()) {
		fprintf(stderr, "Error: cpu_opv is not available\n");
		goto error;
	}

	if (is_rseq_available && rseq_register_current_thread()) {
		fprintf(stderr, "Error: rseq_register_current_thread(...) failed(%d): %s\n",
			errno, strerror(errno));
		goto error;
	}
	printf("spinlock\n");
	test_percpu_spinlock();
	printf("percpu_list\n");
	test_percpu_list();
	if (is_rseq_available && rseq_unregister_current_thread()) {
		fprintf(stderr, "Error: rseq_unregister_current_thread(...) failed(%d): %s\n",
			errno, strerror(errno));
		goto error;
	}
	return 0;

error:
	return -1;
}

