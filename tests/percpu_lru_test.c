// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
/*
 * percpu lru test.
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
#include <pthread.h>
#include <time.h>
#include <poll.h>

#include <rseq/mempool.h>
#include <rseq/rseq.h>
#include "../src/rseq-utils.h"
#include <urcu/ref.h>
#include <urcu/list.h>
#include <urcu/rculist.h>
#include <urcu/compiler.h>
#include <urcu/urcu.h>
#include <urcu/call-rcu.h>

#include "tap.h"
#include "prio-heap.h"

#define NR_LISTENERS	4
#define NR_FREE_ITEMS	5
#define KEYSPACE	20

struct percpu_lru_node {
	struct cds_list_head node;		/* Per-cpu LRU list node. */
	struct timespec last_access_time;	/* Last access time of node. { 0, 0 } initially. */
	struct global_object *obj;		/* Back-reference to object. */
};

/*
 * Locking dependency:
 * - The per-cpu LRU locks nest inside the lrulist_head_rwlock.
 * - The RCU list lock nest inside the per-cpu LRU locks.
 */

/*
 * A global object can be linked into at most nr_possible_cpus
 * per-CPU LRU lists. Each LRU list linking the global object holds
 * a reference on the object.
 *
 * global objects existence is guaranteed by RCU for lookups.
 * Their lifetime depends entirely on the reference count.
 *
 * Object "data" is considered immutable after creation, so it can
 * be read from an RCU read-side without locks. If an object needs to be
 * updated, just create a new object and replace the old one.
 */
struct global_object {
	struct urcu_ref refcount;
	struct percpu_lru_node __rseq_percpu *percpu_lru_node;
	struct rcu_head rcu_head;
	struct cds_list_head node;

	/* Lookup key. */
	int key;
	//TODO: add object data.
};

/*
 * The per-CPU LRU list contains the items most recently accessed from a
 * given CPU at the head of the list.
 */
struct percpu_lru_head {
	struct cds_list_head head;		/* Per-CPU LRU list head. */
	pthread_mutex_t lock;			/* Protect per-cpu LRU list and access time updates. */
	int cpu;
};

/* stop test. */
static int stop;

static struct rseq_mempool *pool_node, *pool_head;

static int nr_possible_cpus;

struct global_object;

/*
 * This reader-writer lock protects:
 * - writer: the heap which accesses the heads of each per-cpu lists,
 * - readers: concurrent modification of the per-cpu list head elements.
 *
 * Per-cpu LRU list updates therefore only need to hold the reader lock
 * when they update the LRU list head, which is typically not needed
 * because items are moved to the tail of the LRU list. The reader lock
 * is therefore only needed if the item to be updated is sitting at the
 * head of the list.
 */
static pthread_rwlock_t lrulist_head_rwlock = PTHREAD_RWLOCK_INITIALIZER;

static struct percpu_lru_head __rseq_percpu *percpu_lru_head;

/*
 * RCU list implements RCU lookup as a basic example (e.g. could be an
 * RCU trie instead).
 */
static CDS_LIST_HEAD(rculist);

/*
 * Protect rculist updates.
 */
static pthread_mutex_t rculist_lock = PTHREAD_MUTEX_INITIALIZER;

static unsigned int randseed = 42;

/* Call with RCU read-side lock held. */
static struct global_object *obj_lookup(int key)
{
	struct global_object *obj;

	cds_list_for_each_entry_rcu(obj, &rculist, node) {
		if (obj->key != key)
			continue;
		return obj;
	}
	return NULL;
}

static void reclaim_obj(struct rcu_head *head)
{
	struct global_object *obj = caa_container_of(head,
			struct global_object, rcu_head);
	fprintf(stderr, "free object key=%d\n", obj->key);
	free(obj);
}

static void release_obj(struct urcu_ref *ref)
{
	struct global_object *obj = caa_container_of(ref, struct global_object, refcount);

	pthread_mutex_lock(&rculist_lock);
	cds_list_del_rcu(&obj->node);
	pthread_mutex_unlock(&rculist_lock);

	urcu_memb_call_rcu(&obj->rcu_head, reclaim_obj);
}

/* Reverse gt logic to return min rather than max. */
static int compare_lru_lt(void *a, void *b)
{
	struct percpu_lru_head *lru_a, *lru_b;
	struct percpu_lru_node *node_a, *node_b;

	lru_a = (struct percpu_lru_head *) a;
	lru_b = (struct percpu_lru_head *) b;
	node_a = cds_list_first_entry(&lru_a->head, struct percpu_lru_node, node);
	node_b = cds_list_first_entry(&lru_b->head, struct percpu_lru_node, node);
	if (node_a->last_access_time.tv_sec < node_b->last_access_time.tv_sec)
		return 1;
	if (node_a->last_access_time.tv_sec > node_b->last_access_time.tv_sec)
		return 0;
	if (node_a->last_access_time.tv_nsec < node_b->last_access_time.tv_nsec)
		return 1;
	return 0;
}

/* Return true if release is called, false otherwise. */
static inline bool urcu_ref_put_is_released(struct urcu_ref *ref,
				void (*release)(struct urcu_ref *))
{
	long res = uatomic_sub_return(&ref->refcount, 1);
	urcu_posix_assert(res >= 0);
	if (res == 0) {
		release(ref);
		return true;
	}
	return false;
}

/* Called with RCU read-side lock held. */
static struct global_object *object_access(struct global_object *obj)
{
	struct percpu_lru_node *cpu_lru_node;
	struct percpu_lru_head *cpu_lru_head;
	bool rwlock_held = false;
	int cpu;

	cpu = rseq_current_cpu();
	cpu_lru_head = rseq_percpu_ptr(percpu_lru_head, cpu);
	cpu_lru_node = rseq_percpu_ptr(obj->percpu_lru_node, cpu);
	/* Opportunistically take reader lock. */
	if (cds_list_empty(&cpu_lru_head->head) || cds_list_first_entry(&cpu_lru_head->head,
			struct percpu_lru_node, node) == cpu_lru_node) {
		if (pthread_rwlock_rdlock(&lrulist_head_rwlock))
			abort();
		rwlock_held = true;
	}
	pthread_mutex_lock(&cpu_lru_head->lock);
	if (cpu_lru_node->last_access_time.tv_sec == 0 &&
			cpu_lru_node->last_access_time.tv_nsec == 0) {
		/*
		 * No per-CPU LRU node for this object. Increment reference
		 * count if it is not in the process of being reclaimed already,
		 * update access time and add to LRU list.
		 * Validate again list emptiness check with LRU lock held.
		 */
		if (!rwlock_held && cds_list_empty(&cpu_lru_head->head)) {
			pthread_mutex_unlock(&cpu_lru_head->lock);
			if (pthread_rwlock_rdlock(&lrulist_head_rwlock))
				abort();
			pthread_mutex_lock(&cpu_lru_head->lock);
			rwlock_held = true;
		}
		if (urcu_ref_get_unless_zero(&obj->refcount)) {
			if (clock_gettime(CLOCK_MONOTONIC, &cpu_lru_node->last_access_time))
				abort();
			cds_list_add_tail(&cpu_lru_node->node, &cpu_lru_head->head);
			cpu_lru_node->obj = obj;
		} else {
			obj = NULL;
		}
	} else {
		/*
		 * There is already a per-CPU LRU node for this object.
		 * Update access time and move it to the tail of the LRU.
		 * Validate again if first entry in list with LRU lock held.
		 */
		if (!rwlock_held && cds_list_first_entry(&cpu_lru_head->head,
				struct percpu_lru_node, node) == cpu_lru_node) {
			/*
			 * If node is at list head, grab reader lock to
			 * provide mutual exclusion with respect to heap state.
			 */
			pthread_mutex_unlock(&cpu_lru_head->lock);
			if (pthread_rwlock_rdlock(&lrulist_head_rwlock))
				abort();
			pthread_mutex_lock(&cpu_lru_head->lock);
			rwlock_held = true;
		}
		if (clock_gettime(CLOCK_MONOTONIC, &cpu_lru_node->last_access_time))
			abort();
		cds_list_del(&cpu_lru_node->node);
		cds_list_add_tail(&cpu_lru_node->node, &cpu_lru_head->head);
	}
	pthread_mutex_unlock(&cpu_lru_head->lock);
	if (rwlock_held && pthread_rwlock_unlock(&lrulist_head_rwlock))
		abort();
	return obj;
}

/* Called with RCU read-side lock held. */
static struct global_object *object_create(int key)
{
	struct percpu_lru_node __rseq_percpu *percpu_lru_node;
	struct percpu_lru_node *cpu_lru_node;
	struct percpu_lru_head *cpu_lru_head;
	struct global_object *obj;
	bool rwlock_held = false;
	int cpu;

retry:
	/* Create object and add to lookup RCU list. */
	pthread_mutex_lock(&rculist_lock);
	/* Check for duplicate keys with lock. */
	obj = obj_lookup(key);
	if (obj) {
		pthread_mutex_unlock(&rculist_lock);
		/*
		 * object_access() cannot nest within rculist_lock
		 * due to locking dependency.
		 */
		obj = object_access(obj);
		if (!obj)
			goto retry;	/* Concurrently removed. */
		return obj;
	}
	obj = (struct global_object *) calloc(1, sizeof(*obj));
	if (!obj)
		abort();
	urcu_ref_init(&obj->refcount);
	obj->key = key;
	percpu_lru_node = (struct percpu_lru_node __rseq_percpu *)
				rseq_mempool_percpu_zmalloc(pool_node);
	if (!percpu_lru_node)
		abort();
	obj->percpu_lru_node = percpu_lru_node;

	cds_list_add_rcu(&obj->node, &rculist);
	pthread_mutex_unlock(&rculist_lock);

	/* Newly created, add it to current CPU LRU list */
	cpu = rseq_current_cpu();
	cpu_lru_head = rseq_percpu_ptr(percpu_lru_head, cpu);
	cpu_lru_node = rseq_percpu_ptr(percpu_lru_node, cpu);

	/* Opportunistically take reader lock. */
	if (cds_list_empty(&cpu_lru_head->head)) {
		if (pthread_rwlock_rdlock(&lrulist_head_rwlock))
			abort();
		rwlock_held = true;
	}
	pthread_mutex_lock(&cpu_lru_head->lock);
	/*
	 * Validate again list emptiness check with LRU lock held.
	 */
	if (!rwlock_held && cds_list_empty(&cpu_lru_head->head)) {
		pthread_mutex_unlock(&cpu_lru_head->lock);
		if (pthread_rwlock_rdlock(&lrulist_head_rwlock))
			abort();
		rwlock_held = true;
		pthread_mutex_lock(&cpu_lru_head->lock);
	}
	cds_list_add_tail(&cpu_lru_node->node, &cpu_lru_head->head);
	if (clock_gettime(CLOCK_MONOTONIC, &cpu_lru_node->last_access_time))
		abort();
	cpu_lru_node->obj = obj;
	pthread_mutex_unlock(&cpu_lru_head->lock);
	if (rwlock_held && pthread_rwlock_unlock(&lrulist_head_rwlock))
		abort();
	return obj;
}

/*
 * Lookup by using a random key. If found, either move its LRU node to
 * the tail of the current per-CPU LRU list or add it to the per-CPU LRU
 * list, and update its access time.
 * If not found, create the object and add it to the lookup structure.
 */
static void *listener_thread(void *arg __attribute__((unused)))
{
	urcu_memb_register_thread();
	while (!__atomic_load_n(&stop, __ATOMIC_RELAXED)) {
		struct global_object *obj;
		int key;

		key = rand_r(&randseed) % KEYSPACE;
		urcu_memb_read_lock();
		obj = obj_lookup(key);
		if (!obj || !(obj = object_access(obj)))
			obj = object_create(key);

		/* TODO: Read from object data..... */

		urcu_memb_read_unlock();
		(void) poll(NULL, 0, 10);	/* wait 10ms */
	}
	urcu_memb_unregister_thread();
	return NULL;
}

/* Remove at most nr_items oldest items. */
static void free_items(int nr_items)
{
	struct ptr_heap heap;
	int nr_release = 0, cpu;

	/*
	 * Create and use prio heap iterator to remove oldest item from
	 * its per-cpu LRU (in global access time order).
	 */
	if (bt_heap_init(&heap, nr_possible_cpus, compare_lru_lt))
		abort();

	if (pthread_rwlock_wrlock(&lrulist_head_rwlock))
		abort();

	for (cpu = 0; cpu < nr_possible_cpus; cpu++) {
		struct percpu_lru_head *cpu_lru_head = rseq_percpu_ptr(percpu_lru_head, cpu);

		pthread_mutex_lock(&cpu_lru_head->lock);
		if (!cds_list_empty(&cpu_lru_head->head) && bt_heap_insert(&heap, cpu_lru_head))
			abort();
		pthread_mutex_unlock(&cpu_lru_head->lock);
	}

	fprintf(stderr, "Free %d oldest items (globally sorted)\n", nr_items);
	/* Remove oldest elements from "global" LRU in sorted order. */
	for (;;) {
		struct percpu_lru_head *cpu_lru_head;
		struct percpu_lru_node *cpu_lru_node;

		cpu_lru_head = (struct percpu_lru_head *) bt_heap_remove(&heap);
		if (!cpu_lru_head)
			break;
		pthread_mutex_lock(&cpu_lru_head->lock);
		cpu_lru_node = cds_list_first_entry(&cpu_lru_head->head, struct percpu_lru_node, node);
		fprintf(stderr, "Obj reference put. key=%d, cpu=%d, obj=%p, last_access_time=%10jd.%09ld\n",
			cpu_lru_node->obj->key, cpu_lru_head->cpu, cpu_lru_node->obj,
			cpu_lru_node->last_access_time.tv_sec,
			cpu_lru_node->last_access_time.tv_nsec);
		cds_list_del(&cpu_lru_node->node);
		cpu_lru_node->last_access_time.tv_sec = 0;
		cpu_lru_node->last_access_time.tv_nsec = 0;
		if (urcu_ref_put_is_released(&cpu_lru_node->obj->refcount, release_obj))
			nr_release++;
		if (!cds_list_empty(&cpu_lru_head->head) && bt_heap_insert(&heap, cpu_lru_head))
			abort();
		pthread_mutex_unlock(&cpu_lru_head->lock);
		if (nr_release == nr_items)
			break;
	}

	if (pthread_rwlock_unlock(&lrulist_head_rwlock))
		abort();

	bt_heap_free(&heap);
}

static void *manager_thread(void *arg __attribute__((unused)))
{
	urcu_memb_register_thread();
	while (!__atomic_load_n(&stop, __ATOMIC_RELAXED)) {
		free_items(NR_FREE_ITEMS);
		(void) poll(NULL, 0, 1000);	/* wait 1s */
	}
	urcu_memb_unregister_thread();
	return NULL;
}

int main(void)
{
	pthread_t listener_id[NR_LISTENERS];
	pthread_t manager_id;
	int cpu, i, err;
	void *tret;

	plan_no_plan();

	nr_possible_cpus = rseq_get_max_nr_cpus();

	pool_head = rseq_mempool_create("percpu-lru-head", sizeof(struct percpu_lru_head), NULL);
	if (!pool_head)
		abort();
	pool_node = rseq_mempool_create("percpu-lru-node", sizeof(struct percpu_lru_node), NULL);
	if (!pool_node)
		abort();

	percpu_lru_head = (struct percpu_lru_head __rseq_percpu *) rseq_mempool_percpu_zmalloc(pool_head);
	if (!percpu_lru_head)
		abort();
	for (cpu = 0; cpu < nr_possible_cpus; cpu++) {
		struct percpu_lru_head *cpu_lru_head = rseq_percpu_ptr(percpu_lru_head, cpu);
		pthread_mutex_init(&cpu_lru_head->lock, NULL);
		CDS_INIT_LIST_HEAD(&cpu_lru_head->head);
		cpu_lru_head->cpu = cpu;
	}

	err = pthread_create(&manager_id, NULL, manager_thread, NULL);
	if (err != 0)
		exit(1);
	for (i = 0; i < NR_LISTENERS; i++) {
		err = pthread_create(&listener_id[i], NULL, listener_thread, NULL);
		if (err != 0)
			exit(1);
	}

	sleep(20);
	__atomic_store_n(&stop, 1, __ATOMIC_RELAXED);

	for (i = 0; i < NR_LISTENERS; i++) {
		err = pthread_join(listener_id[i], &tret);
		if (err != 0)
			exit(1);
	}
	err = pthread_join(manager_id, &tret);
	if (err != 0)
		exit(1);

	fprintf(stderr, "Free unsorted (finalize)\n");
	/* Free all remaining items (in any global order). */
	for (cpu = 0; cpu < nr_possible_cpus; cpu++) {
		struct percpu_lru_head *cpu_lru_head = rseq_percpu_ptr(percpu_lru_head, cpu);
		struct percpu_lru_node *cpu_lru_node, *tmp;

		cds_list_for_each_entry_safe(cpu_lru_node, tmp, &cpu_lru_head->head, node) {
			fprintf(stderr, "Obj reference put. key=%d, cpu=%d, obj=%p, last_access_time=%10jd.%09ld\n",
				cpu_lru_node->obj->key, cpu, cpu_lru_node->obj,
				cpu_lru_node->last_access_time.tv_sec,
				cpu_lru_node->last_access_time.tv_nsec);
			cds_list_del(&cpu_lru_node->node);
			cpu_lru_node->last_access_time.tv_sec = 0;
			cpu_lru_node->last_access_time.tv_nsec = 0;
			urcu_ref_put(&cpu_lru_node->obj->refcount, release_obj);
		}
	}

	ok(1, "result");

	rseq_mempool_percpu_free(percpu_lru_head);

	if (rseq_mempool_destroy(pool_node))
		abort();
	if (rseq_mempool_destroy(pool_head))
		abort();

	exit(exit_status());
}
