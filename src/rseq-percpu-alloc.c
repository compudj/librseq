// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>

#include <rseq/percpu-alloc.h>
#include <sys/mman.h>
#include <assert.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <rseq/compiler.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#ifdef HAVE_LIBNUMA
# include <numa.h>
# include <numaif.h>
#endif

#include "rseq-alloc-utils.h"

/*
 * rseq-percpu-alloc.c: rseq CPU-Local Storage (CLS) memory allocator.
 *
 * The rseq per-CPU memory allocator allows the application the request
 * memory pools of CPU-Local memory each of containing objects of a
 * given size (rounded to next power of 2), a given virtual address size
 * per CPU, for a given maximum number of CPUs.
 *
 * The per-CPU memory allocator is analogous to TLS (Thread-Local
 * Storage) memory: TLS is Thread-Local Storage, whereas the per-CPU
 * memory allocator provides CPU-Local Storage.
 */

/*
 * Use high bits of per-CPU addresses to index the pool.
 * This leaves the low bits of available to the application for pointer
 * tagging (based on next power of 2 alignment of the allocations).
 */
#if RSEQ_BITS_PER_LONG == 64
# define POOL_INDEX_BITS	16
#else
# define POOL_INDEX_BITS	8
#endif
#define MAX_NR_POOLS		(1UL << POOL_INDEX_BITS)
#define POOL_INDEX_SHIFT	(RSEQ_BITS_PER_LONG - POOL_INDEX_BITS)
#define MAX_POOL_LEN		(1UL << POOL_INDEX_SHIFT)
#define MAX_POOL_LEN_MASK	(MAX_POOL_LEN - 1)

#define POOL_SET_NR_ENTRIES	POOL_INDEX_SHIFT

/*
 * Smallest allocation should hold enough space for a free list pointer.
 */
#if RSEQ_BITS_PER_LONG == 64
# define POOL_SET_MIN_ENTRY	3	/* Smallest item_len=8 */
#else
# define POOL_SET_MIN_ENTRY	2	/* Smallest item_len=4 */
#endif

struct free_list_node;

struct free_list_node {
	struct free_list_node *next;
};

/* This lock protects pool create/destroy. */
static pthread_mutex_t pool_lock = PTHREAD_MUTEX_INITIALIZER;

struct rseq_percpu_pool {
	void *base;
	unsigned int index;
	size_t item_len;
	size_t percpu_len;
	int item_order;
	int max_nr_cpus;

	/*
	 * The free list chains freed items on the CPU 0 address range.
	 * We should rethink this decision if false sharing between
	 * malloc/free from other CPUs and data accesses from CPU 0
	 * becomes an issue. This is a NULL-terminated singly-linked
	 * list.
	 */
	struct free_list_node *free_list_head;
	size_t next_unused;
	/* This lock protects allocation/free within the pool. */
	pthread_mutex_t lock;
};

//TODO: the array of pools should grow dynamically on create.
static struct rseq_percpu_pool rseq_percpu_pool[MAX_NR_POOLS];

/*
 * Pool set entries are indexed by item_len rounded to the next power of
 * 2. A pool set can contain NULL pool entries, in which case the next
 * large enough entry will be used for allocation.
 */
struct rseq_percpu_pool_set {
	/* This lock protects add vs malloc/zmalloc within the pool set. */
	pthread_mutex_t lock;
	struct rseq_percpu_pool *entries[POOL_SET_NR_ENTRIES];
};

static
void *__rseq_pool_percpu_ptr(struct rseq_percpu_pool *pool, int cpu, uintptr_t item_offset)
{
	return pool->base + (pool->percpu_len * cpu) + item_offset;
}

void *__rseq_percpu_ptr(void *_ptr, int cpu)
{
	uintptr_t ptr = (uintptr_t) _ptr;
	uintptr_t item_offset = ptr & MAX_POOL_LEN_MASK;
	uintptr_t pool_index = ptr >> POOL_INDEX_SHIFT;
	struct rseq_percpu_pool *pool = &rseq_percpu_pool[pool_index];

	assert(cpu >= 0);
	return __rseq_pool_percpu_ptr(pool, cpu, item_offset);
}

static
void rseq_percpu_zero_item(struct rseq_percpu_pool *pool, uintptr_t item_offset)
{
	int i;

	for (i = 0; i < pool->max_nr_cpus; i++) {
		char *p = __rseq_pool_percpu_ptr(pool, i, item_offset);
		memset(p, 0, pool->item_len);
	}
}

#ifdef HAVE_LIBNUMA
static
void rseq_percpu_pool_init_numa(struct rseq_percpu_pool *pool,
		int numa_flags)
{
	unsigned long nr_pages, page;
	long ret, page_len;
	int cpu;

	if (!numa_flags)
		return;
	page_len = rseq_get_page_len();
	nr_pages = pool->percpu_len >> rseq_get_count_order_ulong(page_len);
	for (cpu = 0; cpu < pool->max_nr_cpus; cpu++) {
		int node = numa_node_of_cpu(cpu);

		/* TODO: batch move_pages() call with an array of pages. */
		for (page = 0; page < nr_pages; page++) {
			void *pageptr = __rseq_pool_percpu_ptr(pool, cpu, page * page_len);
			int status = -EPERM;

			ret = move_pages(0, 1, &pageptr, &node, &status, numa_flags);
			if (ret) {
				perror("move_pages");
				abort();
			}
		}
	}
}
#else
static
void rseq_percpu_pool_init_numa(struct rseq_percpu_pool *pool __attribute__((unused)),
		int numa_flags __attribute__((unused)))
{
}
#endif

/*
 * Expected numa_flags:
 *   0:                do not move pages to specific numa nodes (use for e.g. mm_cid indexing).
 *   MPOL_MF_MOVE:     move process-private pages to cpu-specific numa nodes.
 *   MPOL_MF_MOVE_ALL: move shared pages to cpu-specific numa nodes (requires CAP_SYS_NICE).
 */
struct rseq_percpu_pool *rseq_percpu_pool_create(size_t item_len,
		size_t percpu_len, int max_nr_cpus,
		int mmap_prot, int mmap_flags, int mmap_fd,
		off_t mmap_offset, int numa_flags)
{
	struct rseq_percpu_pool *pool;
	void *base;
	unsigned int i;
	int order;

	/* Make sure each item is large enough to contain free list pointers. */
	if (item_len < sizeof(void *))
		item_len = sizeof(void *);

	/* Align item_len on next power of two. */
	order = rseq_get_count_order_ulong(item_len);
	if (order < 0) {
		errno = EINVAL;
		return NULL;
	}
	item_len = 1UL << order;

	/* Align percpu_len on page size. */
	percpu_len = rseq_align(percpu_len, rseq_get_page_len());

	if (max_nr_cpus < 0 || item_len > percpu_len ||
			percpu_len > (UINTPTR_MAX >> POOL_INDEX_BITS)) {
		errno = EINVAL;
		return NULL;
	}

	pthread_mutex_lock(&pool_lock);
	/* Linear scan in array of pools to find empty spot. */
	for (i = 0; i < MAX_NR_POOLS; i++) {
		pool = &rseq_percpu_pool[i];
		if (!pool->base)
			goto found_empty;
	}
	errno = ENOMEM;
	pool = NULL;
	goto end;

found_empty:
	base = mmap(NULL, percpu_len * max_nr_cpus, mmap_prot,
			mmap_flags, mmap_fd, mmap_offset);
	if (base == MAP_FAILED) {
		pool = NULL;
		goto end;
	}
	rseq_percpu_pool_init_numa(pool, numa_flags);
	pthread_mutex_init(&pool->lock, NULL);
	pool->base = base;
	pool->percpu_len = percpu_len;
	pool->max_nr_cpus = max_nr_cpus;
	pool->index = i;
	pool->item_len = item_len;
	pool->item_order = order;
end:
	pthread_mutex_unlock(&pool_lock);
	return pool;
}

int rseq_percpu_pool_destroy(struct rseq_percpu_pool *pool)
{
	int ret;

	pthread_mutex_lock(&pool_lock);
	if (!pool->base) {
		errno = ENOENT;
		ret = -1;
		goto end;
	}
	ret = munmap(pool->base, pool->percpu_len * pool->max_nr_cpus);
	if (ret)
		goto end;
	pthread_mutex_destroy(&pool->lock);
	memset(pool, 0, sizeof(*pool));
end:
	pthread_mutex_unlock(&pool_lock);
	return 0;
}

static
void *__rseq_percpu_malloc(struct rseq_percpu_pool *pool, bool zeroed)
{
	struct free_list_node *node;
	uintptr_t item_offset;
	void *addr;

	pthread_mutex_lock(&pool->lock);
	/* Get first entry from free list. */
	node = pool->free_list_head;
	if (node != NULL) {
		/* Remove node from free list (update head). */
		pool->free_list_head = node->next;
		item_offset = (uintptr_t) ((void *) node - pool->base);
		addr = (void *) (((uintptr_t) pool->index << POOL_INDEX_SHIFT) | item_offset);
		goto end;
	}
	if (pool->next_unused + pool->item_len > pool->percpu_len) {
		addr = NULL;
		goto end;
	}
	item_offset = pool->next_unused;
	addr = (void *) (((uintptr_t) pool->index << POOL_INDEX_SHIFT) | item_offset);
	pool->next_unused += pool->item_len;
end:
	pthread_mutex_unlock(&pool->lock);
	if (zeroed && addr)
		rseq_percpu_zero_item(pool, item_offset);
	return addr;
}

void *rseq_percpu_malloc(struct rseq_percpu_pool *pool)
{
	return __rseq_percpu_malloc(pool, false);
}

void *rseq_percpu_zmalloc(struct rseq_percpu_pool *pool)
{
	return __rseq_percpu_malloc(pool, true);
}

void rseq_percpu_free(void *_ptr)
{
	uintptr_t ptr = (uintptr_t) _ptr;
	uintptr_t item_offset = ptr & MAX_POOL_LEN_MASK;
	uintptr_t pool_index = ptr >> POOL_INDEX_SHIFT;
	struct rseq_percpu_pool *pool = &rseq_percpu_pool[pool_index];
	struct free_list_node *head, *item;

	pthread_mutex_lock(&pool->lock);
	/* Add ptr to head of free list */
	head = pool->free_list_head;
	/* Free-list is in CPU 0 range. */
	item = (struct free_list_node *)__rseq_pool_percpu_ptr(pool, 0, item_offset);
	item->next = head;
	pool->free_list_head = item;
	pthread_mutex_unlock(&pool->lock);
}

struct rseq_percpu_pool_set *rseq_percpu_pool_set_create(void)
{
	struct rseq_percpu_pool_set *pool_set;

	pool_set = calloc(1, sizeof(struct rseq_percpu_pool_set));
	if (!pool_set)
		return NULL;
	pthread_mutex_init(&pool_set->lock, NULL);
	return pool_set;
}

int rseq_percpu_pool_set_destroy(struct rseq_percpu_pool_set *pool_set)
{
	int order, ret;

	for (order = POOL_SET_MIN_ENTRY; order < POOL_SET_NR_ENTRIES; order++) {
		struct rseq_percpu_pool *pool = pool_set->entries[order];

		if (!pool)
			continue;
		ret = rseq_percpu_pool_destroy(pool);
		if (ret)
			return ret;
		pool_set->entries[order] = NULL;
	}
	pthread_mutex_destroy(&pool_set->lock);
	free(pool_set);
	return 0;
}

/* Ownership of pool is handed over to pool set on success. */
int rseq_percpu_pool_set_add_pool(struct rseq_percpu_pool_set *pool_set, struct rseq_percpu_pool *pool)
{
	size_t item_order = pool->item_order;
	int ret = 0;

	pthread_mutex_lock(&pool_set->lock);
	if (pool_set->entries[item_order]) {
		errno = EBUSY;
		ret = -1;
		goto end;
	}
	pool_set->entries[pool->item_order] = pool;
end:
	pthread_mutex_unlock(&pool_set->lock);
	return ret;
}

static
void *__rseq_percpu_pool_set_malloc(struct rseq_percpu_pool_set *pool_set, size_t len, bool zeroed)
{
	int order, min_order = POOL_SET_MIN_ENTRY;
	struct rseq_percpu_pool *pool;
	void *addr;

again:
	pthread_mutex_lock(&pool_set->lock);
	/* First smallest present pool where @len fits. */
	for (order = min_order; order < POOL_SET_NR_ENTRIES; order++) {
		pool = pool_set->entries[order];

		if (!pool)
			continue;
		if (pool->item_len >= len)
			goto found;
	}
	pool = NULL;
found:
	pthread_mutex_unlock(&pool_set->lock);
	if (pool) {
		addr = __rseq_percpu_malloc(pool, zeroed);
		if (addr == NULL && errno == ENOMEM) {
			/*
			 * If the allocation failed, try again with a
			 * larger pool.
			 */
			min_order = order + 1;
			goto again;
		}
	} else {
		/* Not found. */
		errno = ENOMEM;
		addr = NULL;
	}
	return addr;
}

void *rseq_percpu_pool_set_malloc(struct rseq_percpu_pool_set *pool_set, size_t len)
{
	return __rseq_percpu_pool_set_malloc(pool_set, len, false);
}

void *rseq_percpu_pool_set_zmalloc(struct rseq_percpu_pool_set *pool_set, size_t len)
{
	return __rseq_percpu_pool_set_malloc(pool_set, len, true);
}
