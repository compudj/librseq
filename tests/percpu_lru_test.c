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

#define NR_LISTENERS		4
#define NR_FREE_ITEMS		5
#define KEYSPACE		20

#define TTL_RANDOM_RANGE	4	/* TTL random range in seconds. */

#define DATA_STR_LEN		128

struct percpu_lru_node {
	struct cds_list_head node;		/* Per-cpu LRU list node. */
	struct timespec last_access_time;	/* Last access time of node. { 0, 0 } initially. */
	struct global_object *obj;		/* Back-reference to object. */
};

/*
 * Locking dependency:
 * - The per-cpu LRU locks nest inside the lrulist_head_rwlock.
 * - The RCU list lock nest inside the per-cpu LRU locks.
 * - The ttl_heap_lock nest inside the RCU list lock.
 */

/*
 * object_data is immutable after creation. TTL expiry is handled by
 * replacing the object data with a new version. Replacing object data
 * is protected by the ttl_heap_lock.
 */
struct object_data {
	struct timespec ttl_expire_time;
	struct rcu_head rcu_head;	/* for call_rcu */
	char str[DATA_STR_LEN];
};

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
	struct rcu_head rcu_head;	/* for call_rcu */
	struct cds_list_head node;

	/* Lookup key. */
	int key;
	struct object_data *data;	/* RCU pointer. */
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

/*
 * TTL heap keeping track of object data TTL expire in sorted order.
 */
static struct ptr_heap ttl_heap;
/*
 * Protect TTL heap updates.
 */
static pthread_mutex_t ttl_heap_lock = PTHREAD_MUTEX_INITIALIZER;

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

static void reclaim_data(struct rcu_head *head)
{
	struct object_data *data = caa_container_of(head,
			struct object_data, rcu_head);
	printf("free object data=\"%s\"\n", data->str);
	free(data);
}

static void reclaim_obj(struct rcu_head *head)
{
	struct global_object *obj = caa_container_of(head,
			struct global_object, rcu_head);
	printf("free object key=%d, data=\"%s\"\n", obj->key, obj->data->str);
	free(obj->data);
	free(obj);
}

static void release_obj(struct urcu_ref *ref)
{
	struct global_object *obj = caa_container_of(ref, struct global_object, refcount);

	pthread_mutex_lock(&rculist_lock);
	pthread_mutex_lock(&ttl_heap_lock);
	cds_list_del_rcu(&obj->node);
	if (bt_heap_cherrypick(&ttl_heap, obj) != obj)
		abort();
	pthread_mutex_unlock(&ttl_heap_lock);
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

/*
 * Reverse gt logic to return min rather than max.
 * Called with ttl_heap_lock held.
 */
static int compare_ttl_lt(void *a, void *b)
{
	struct global_object *obj_a, *obj_b;

	obj_a = (struct global_object *) a;
	obj_b = (struct global_object *) b;
	if (obj_a->data->ttl_expire_time.tv_sec < obj_b->data->ttl_expire_time.tv_sec)
		return 1;
	if (obj_a->data->ttl_expire_time.tv_sec > obj_b->data->ttl_expire_time.tv_sec)
		return 0;
	if (obj_a->data->ttl_expire_time.tv_nsec < obj_b->data->ttl_expire_time.tv_nsec)
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
retry:
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
			rwlock_held = true;
			goto retry;
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
			rwlock_held = true;
			goto retry;
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

static struct object_data *populate_data(int key, struct timespec *ts)
{
	struct object_data *data;
	int ttl;

	data = (struct object_data *) calloc(1, sizeof(struct object_data));
	if (!data)
		abort();
	ttl = rand_r(&randseed) % TTL_RANDOM_RANGE;
	data->ttl_expire_time.tv_sec = ts->tv_sec + ttl;
	data->ttl_expire_time.tv_nsec = ts->tv_nsec;
	snprintf(data->str, DATA_STR_LEN, "Data for key: %d, TTL: %d", key, ttl);
	return data;
}

/* Called with RCU read-side lock held. */
static struct object_data *object_get_data(struct global_object *obj, int key)
{
	struct object_data *data, *new_data;
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		abort();

	data = rcu_dereference(obj->data);
	if (!data)
		goto expired;

	if (ts.tv_sec < data->ttl_expire_time.tv_sec)
		goto ttl_ok;
	if (ts.tv_sec > data->ttl_expire_time.tv_sec)
		goto expired;
	if (ts.tv_nsec < data->ttl_expire_time.tv_nsec)
		goto ttl_ok;
expired:
	pthread_mutex_lock(&ttl_heap_lock);
	data = obj->data;
	if (data) {
		if (ts.tv_sec < data->ttl_expire_time.tv_sec)
			goto ttl_ok_unlock;
		if (ts.tv_sec > data->ttl_expire_time.tv_sec)
			goto expired_locked;
		if (ts.tv_nsec < data->ttl_expire_time.tv_nsec)
			goto ttl_ok_unlock;
	}
expired_locked:
	new_data = populate_data(key, &ts);
	rcu_set_pointer(&obj->data, new_data);
	if (data) {
		if (bt_heap_cherrypick(&ttl_heap, obj) != obj)
			abort();
	}
	if (bt_heap_insert(&ttl_heap, obj))
		abort();
	pthread_mutex_unlock(&ttl_heap_lock);
	if (data)
		urcu_memb_call_rcu(&data->rcu_head, reclaim_data);
	data = new_data;
ttl_ok:
	return data;

ttl_ok_unlock:
	pthread_mutex_unlock(&ttl_heap_lock);
	return data;
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
		struct object_data *obj_data;
		struct global_object *obj;
		int key;

		key = rand_r(&randseed) % KEYSPACE;
		urcu_memb_read_lock();
		obj = obj_lookup(key);
		if (!obj || !(obj = object_access(obj)))
			obj = object_create(key);

		obj_data = object_get_data(obj, key);
		if (!obj_data)
			abort();

		printf("Access object key=%d, data=\"%s\"\n",
			obj->key, obj_data->str);

		urcu_memb_read_unlock();
		(void) poll(NULL, 0, 500);	/* wait 500ms */
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

	printf("Free %d oldest items (globally sorted)\n", nr_items);
	/* Remove oldest elements from "global" LRU in sorted order. */
	for (;;) {
		struct percpu_lru_head *cpu_lru_head;
		struct percpu_lru_node *cpu_lru_node;

		cpu_lru_head = (struct percpu_lru_head *) bt_heap_remove(&heap);
		if (!cpu_lru_head)
			break;
		pthread_mutex_lock(&cpu_lru_head->lock);
		cpu_lru_node = cds_list_first_entry(&cpu_lru_head->head, struct percpu_lru_node, node);
		printf("Obj reference put. key=%d, cpu=%d, obj=%p, last_access_time=%10jd.%09ld\n",
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

static void *lru_manager_thread(void *arg __attribute__((unused)))
{
	urcu_memb_register_thread();
	while (!__atomic_load_n(&stop, __ATOMIC_RELAXED)) {
		free_items(NR_FREE_ITEMS);
		(void) poll(NULL, 0, 1000);	/* wait 1s */
	}
	urcu_memb_unregister_thread();
	return NULL;
}

static int refresh_expired_ttl(int max_refresh)
{
	int nr_refresh = 0;

	for (;;) {
		struct global_object *obj;
		struct object_data *data = NULL, *new_data;
		struct timespec ts;
		bool expired = false;

		pthread_mutex_lock(&ttl_heap_lock);

		obj = (struct global_object *) bt_heap_remove(&ttl_heap);
		if (!obj)
			goto unlock;

		if (clock_gettime(CLOCK_MONOTONIC, &ts))
			abort();

		data = obj->data;
		if (!data)
			goto expired;

		if (ts.tv_sec < data->ttl_expire_time.tv_sec)
			goto ttl_ok;
		if (ts.tv_sec > data->ttl_expire_time.tv_sec)
			goto expired;
		if (ts.tv_nsec < data->ttl_expire_time.tv_nsec)
			goto ttl_ok;
	expired:
		expired = true;
		new_data = populate_data(obj->key, &ts);
		rcu_set_pointer(&obj->data, new_data);
	ttl_ok:
		if (bt_heap_insert(&ttl_heap, obj))
			abort();
	unlock:
		pthread_mutex_unlock(&ttl_heap_lock);
		if (expired && data)
			urcu_memb_call_rcu(&data->rcu_head, reclaim_data);
		/*
		 * Stop when all expired data has been refreshed, up to
		 * a maximum count.
		 */
		if (!obj || !expired || nr_refresh++ > max_refresh)
			break;
	}
	return nr_refresh;
}

static void *ttl_manager_thread(void *arg __attribute__((unused)))
{
	urcu_memb_register_thread();
	while (!__atomic_load_n(&stop, __ATOMIC_RELAXED)) {
		int nr_refresh;

		nr_refresh = refresh_expired_ttl(10);
		printf("Refreshed %d records\n", nr_refresh);
		(void) poll(NULL, 0, 3000);	/* wait 3s */
	}
	urcu_memb_unregister_thread();
	return NULL;
}

int main(void)
{
	pthread_t listener_id[NR_LISTENERS];
	pthread_t lru_manager_id, ttl_manager_id;
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

	if (bt_heap_init(&ttl_heap, 128, compare_ttl_lt))
		abort();

	err = pthread_create(&lru_manager_id, NULL, lru_manager_thread, NULL);
	if (err != 0)
		exit(1);
	err = pthread_create(&ttl_manager_id, NULL, ttl_manager_thread, NULL);
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
	err = pthread_join(lru_manager_id, &tret);
	if (err != 0)
		exit(1);
	err = pthread_join(ttl_manager_id, &tret);
	if (err != 0)
		exit(1);

	printf("Free unsorted (finalize)\n");
	/* Free all remaining items (in any global order). */
	for (cpu = 0; cpu < nr_possible_cpus; cpu++) {
		struct percpu_lru_head *cpu_lru_head = rseq_percpu_ptr(percpu_lru_head, cpu);
		struct percpu_lru_node *cpu_lru_node, *tmp;

		cds_list_for_each_entry_safe(cpu_lru_node, tmp, &cpu_lru_head->head, node) {
			printf("Obj reference put. key=%d, cpu=%d, obj=%p, last_access_time=%10jd.%09ld\n",
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

	bt_heap_free(&ttl_heap);

	rseq_mempool_percpu_free(percpu_lru_head);

	if (rseq_mempool_destroy(pool_node))
		abort();
	if (rseq_mempool_destroy(pool_head))
		abort();

	exit(exit_status());
}
