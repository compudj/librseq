// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>

#include <rseq/mempool.h>
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

#include "rseq-utils.h"

/*
 * rseq-mempool.c: rseq CPU-Local Storage (CLS) memory allocator.
 *
 * The rseq per-CPU memory allocator allows the application the request
 * memory pools of CPU-Local memory each of containing objects of a
 * given size (rounded to next power of 2), reserving a given virtual
 * address size per CPU, for a given maximum number of CPUs.
 *
 * The per-CPU memory allocator is analogous to TLS (Thread-Local
 * Storage) memory: TLS is Thread-Local Storage, whereas the per-CPU
 * memory allocator provides CPU-Local Storage.
 */

#define POOL_SET_NR_ENTRIES	RSEQ_BITS_PER_LONG

/*
 * Smallest allocation should hold enough space for a free list pointer.
 */
#if RSEQ_BITS_PER_LONG == 64
# define POOL_SET_MIN_ENTRY	3	/* Smallest item_len=8 */
#else
# define POOL_SET_MIN_ENTRY	2	/* Smallest item_len=4 */
#endif

/*
 * Skip pool index 0 to ensure allocated entries at index 0 do not match
 * a NULL pointer.
 */
#define FIRST_POOL		1

#define BIT_PER_ULONG		(8 * sizeof(unsigned long))

#define MOVE_PAGES_BATCH_SIZE	4096

#define RANGE_HEADER_OFFSET	sizeof(struct rseq_mempool_range)

struct free_list_node;

struct free_list_node {
	struct free_list_node *next;
};

struct rseq_mempool_attr {
	bool mmap_set;
	void *(*mmap_func)(void *priv, size_t len);
	int (*munmap_func)(void *priv, void *ptr, size_t len);
	void *mmap_priv;

	bool robust_set;
};

struct rseq_mempool_range;

struct rseq_mempool_range {
	struct rseq_mempool_range *next;
	struct rseq_mempool *pool;	/* Backward ref. to container pool. */
	void *header;
	void *base;
	size_t next_unused;
	/* Track alloc/free. */
	unsigned long *alloc_bitmap;
};

struct rseq_mempool {
	/* Linked-list of ranges. */
	struct rseq_mempool_range *ranges;

	size_t item_len;
	size_t percpu_stride;
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

	/* This lock protects allocation/free within the pool. */
	pthread_mutex_t lock;

	struct rseq_mempool_attr attr;
	char *name;
};

/*
 * Pool set entries are indexed by item_len rounded to the next power of
 * 2. A pool set can contain NULL pool entries, in which case the next
 * large enough entry will be used for allocation.
 */
struct rseq_mempool_set {
	/* This lock protects add vs malloc/zmalloc within the pool set. */
	pthread_mutex_t lock;
	struct rseq_mempool *entries[POOL_SET_NR_ENTRIES];
};

static
void *__rseq_pool_percpu_ptr(struct rseq_mempool *pool, int cpu,
		uintptr_t item_offset, size_t stride)
{
	/* TODO: Implement multi-ranges support. */
	return pool->ranges->base + (stride * cpu) + item_offset;
}

static
void rseq_percpu_zero_item(struct rseq_mempool *pool, uintptr_t item_offset)
{
	int i;

	for (i = 0; i < pool->max_nr_cpus; i++) {
		char *p = __rseq_pool_percpu_ptr(pool, i,
				item_offset, pool->percpu_stride);
		memset(p, 0, pool->item_len);
	}
}

//TODO: this will need to be reimplemented for ranges,
//which cannot use __rseq_pool_percpu_ptr.
#if 0 //#ifdef HAVE_LIBNUMA
static
int rseq_mempool_range_init_numa(struct rseq_mempool *pool, struct rseq_mempool_range *range, int numa_flags)
{
	unsigned long nr_pages, page_len;
	long ret;
	int cpu;

	if (!numa_flags)
		return 0;
	page_len = rseq_get_page_len();
	nr_pages = pool->percpu_stride >> rseq_get_count_order_ulong(page_len);
	for (cpu = 0; cpu < pool->max_nr_cpus; cpu++) {

		int status[MOVE_PAGES_BATCH_SIZE];
		int nodes[MOVE_PAGES_BATCH_SIZE];
		void *pages[MOVE_PAGES_BATCH_SIZE];

		nodes[0] = numa_node_of_cpu(cpu);
		for (size_t k = 1; k < RSEQ_ARRAY_SIZE(nodes); ++k) {
			nodes[k] = nodes[0];
		}

		for (unsigned long page = 0; page < nr_pages;) {

			size_t max_k = RSEQ_ARRAY_SIZE(pages);
			size_t left = nr_pages - page;

			if (left < max_k) {
				max_k = left;
			}

			for (size_t k = 0; k < max_k; ++k, ++page) {
				pages[k] = __rseq_pool_percpu_ptr(pool, cpu, page * page_len);
				status[k] = -EPERM;
			}

			ret = move_pages(0, max_k, pages, nodes, status, numa_flags);

			if (ret < 0)
				return ret;

			if (ret > 0) {
				fprintf(stderr, "%lu pages were not migrated\n", ret);
				for (size_t k = 0; k < max_k; ++k) {
					if (status[k] < 0)
						fprintf(stderr,
							"Error while moving page %p to numa node %d: %u\n",
							pages[k], nodes[k], -status[k]);
				}
			}
		}
	}
	return 0;
}

int rseq_mempool_init_numa(struct rseq_mempool *pool, int numa_flags)
{
	struct rseq_mempool_range *range;
	int ret;

	if (!numa_flags)
		return 0;
	for (range = pool->ranges; range; range = range->next) {
		ret = rseq_mempool_range_init_numa(pool, range, numa_flags);
		if (ret)
			return ret;
	}
	return 0;
}
#else
int rseq_mempool_init_numa(struct rseq_mempool *pool __attribute__((unused)),
		int numa_flags __attribute__((unused)))
{
	return 0;
}
#endif

static
void *default_mmap_func(void *priv __attribute__((unused)), size_t len)
{
	void *base;

	base = mmap(NULL, len, PROT_READ | PROT_WRITE,
			MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (base == MAP_FAILED)
		return NULL;
	return base;
}

static
int default_munmap_func(void *priv __attribute__((unused)), void *ptr, size_t len)
{
	return munmap(ptr, len);
}

static
int create_alloc_bitmap(struct rseq_mempool *pool, struct rseq_mempool_range *range)
{
	size_t count;

	count = ((pool->percpu_stride >> pool->item_order) + BIT_PER_ULONG - 1) / BIT_PER_ULONG;

	/*
	 * Not being able to create the validation bitmap is an error
	 * that needs to be reported.
	 */
	range->alloc_bitmap = calloc(count, sizeof(unsigned long));
	if (!range->alloc_bitmap)
		return -1;
	return 0;
}

static
const char *get_pool_name(const struct rseq_mempool *pool)
{
	return pool->name ? : "<anonymous>";
}

static
bool addr_in_pool(const struct rseq_mempool *pool, void *addr)
{
	struct rseq_mempool_range *range;

	for (range = pool->ranges; range; range = range->next) {
		if (addr >= range->base && addr < range->base + range->next_unused)
			return true;
	}
	return false;
}

/* Always inline for __builtin_return_address(0). */
static inline __attribute__((always_inline))
void check_free_list(const struct rseq_mempool *pool)
{
	size_t total_item = 0, total_never_allocated = 0, total_freed = 0,
		max_list_traversal = 0, traversal_iteration = 0;
	struct rseq_mempool_range *range;

	if (!pool->attr.robust_set)
		return;

	for (range = pool->ranges; range; range = range->next) {
		total_item += pool->percpu_stride >> pool->item_order;
		total_never_allocated += (pool->percpu_stride - range->next_unused) >> pool->item_order;
	}
	max_list_traversal = total_item - total_never_allocated;

	for (struct free_list_node *node = pool->free_list_head, *prev = NULL;
	     node;
	     prev = node,
	     node = node->next) {

		void *node_addr = node;

		if (traversal_iteration >= max_list_traversal) {
			fprintf(stderr, "%s: Corrupted free-list; Possibly infinite loop in pool \"%s\" (%p), caller %p.\n",
				__func__, get_pool_name(pool), pool, __builtin_return_address(0));
			abort();
		}

		/* Node is out of range. */
		if (!addr_in_pool(pool, node_addr)) {
			if (prev)
				fprintf(stderr, "%s: Corrupted free-list node %p -> [out-of-range %p] in pool \"%s\" (%p), caller %p.\n",
					__func__, prev, node, get_pool_name(pool), pool, __builtin_return_address(0));
			else
				fprintf(stderr, "%s: Corrupted free-list node [out-of-range %p] in pool \"%s\" (%p), caller %p.\n",
					__func__, node, get_pool_name(pool), pool, __builtin_return_address(0));
			abort();
		}

		traversal_iteration++;
		total_freed++;
	}

	if (total_never_allocated + total_freed != total_item) {
		fprintf(stderr, "%s: Corrupted free-list in pool \"%s\" (%p); total-item: %zu total-never-used: %zu total-freed: %zu, caller %p.\n",
			__func__, get_pool_name(pool), pool, total_item, total_never_allocated, total_freed, __builtin_return_address(0));
		abort();
	}
}

/* Always inline for __builtin_return_address(0). */
static inline __attribute__((always_inline))
void destroy_alloc_bitmap(struct rseq_mempool *pool, struct rseq_mempool_range *range)
{
	unsigned long *bitmap = range->alloc_bitmap;
	size_t count, total_leaks = 0;

	if (!bitmap)
		return;

	count = ((pool->percpu_stride >> pool->item_order) + BIT_PER_ULONG - 1) / BIT_PER_ULONG;

	/* Assert that all items in the pool were freed. */
	for (size_t k = 0; k < count; ++k)
		total_leaks += rseq_hweight_ulong(bitmap[k]);
	if (total_leaks) {
		fprintf(stderr, "%s: Pool \"%s\" (%p) has %zu leaked items on destroy, caller: %p.\n",
			__func__, get_pool_name(pool), pool, total_leaks, (void *) __builtin_return_address(0));
		abort();
	}

	free(bitmap);
}

/* Always inline for __builtin_return_address(0). */
static inline __attribute__((always_inline))
int rseq_mempool_range_destroy(struct rseq_mempool *pool,
		struct rseq_mempool_range *range)
{
	destroy_alloc_bitmap(pool, range);
	/* range is a header located one page before the aligned mapping. */
	return pool->attr.munmap_func(pool->attr.mmap_priv, range->header,
			(pool->percpu_stride * pool->max_nr_cpus) + rseq_get_page_len());
}

/*
 * Allocate a memory mapping aligned on @alignment, with an optional
 * @pre_header before the mapping.
 */
static
void *aligned_mmap_anonymous(struct rseq_mempool *pool,
		size_t page_size, size_t len, size_t alignment,
		void **pre_header, size_t pre_header_len)
{
	size_t minimum_page_count, page_count, extra, total_allocate = 0;
	int page_order;
	void *ptr;

	if (len < page_size || alignment < page_size ||
			!is_pow2(len) || !is_pow2(alignment)) {
		errno = EINVAL;
		return NULL;
	}
	page_order = rseq_get_count_order_ulong(page_size);
	if (page_order < 0) {
		errno = EINVAL;
		return NULL;
	}
	if (pre_header_len && (pre_header_len & (page_size - 1))) {
		errno = EINVAL;
		return NULL;
	}

	minimum_page_count = (pre_header_len + len) >> page_order;
	page_count = (pre_header_len + len + alignment - page_size) >> page_order;

	assert(page_count >= minimum_page_count);

	ptr = pool->attr.mmap_func(pool->attr.mmap_priv, page_count << page_order);
	if (!ptr)
		goto alloc_error;

	total_allocate = page_count << page_order;

	if (!(((uintptr_t) ptr + pre_header_len) & (alignment - 1))) {
		/* Pointer is already aligned. ptr points to pre_header. */
		goto out;
	}

	/* Unmap extra before. */
	extra = offset_align((uintptr_t) ptr + pre_header_len, alignment);
	assert(!(extra & (page_size - 1)));
	if (pool->attr.munmap_func(pool->attr.mmap_priv, ptr, extra)) {
		perror("munmap");
		abort();
	}
	total_allocate -= extra;
	ptr += extra;	/* ptr points to pre_header */
	page_count -= extra >> page_order;
out:
	assert(page_count >= minimum_page_count);

	if (page_count > minimum_page_count) {
		void *extra_ptr;

		/* Unmap extra after. */
		extra_ptr = ptr + (minimum_page_count << page_order);
		extra = (page_count - minimum_page_count) << page_order;
		if (pool->attr.munmap_func(pool->attr.mmap_priv, extra_ptr, extra)) {
			perror("munmap");
			abort();
		}
		total_allocate -= extra;
	}

	assert(!(((uintptr_t)ptr + pre_header_len) & (alignment - 1)));
	assert(total_allocate == len + pre_header_len);

alloc_error:
	if (ptr) {
		if (pre_header)
			*pre_header = ptr;
		ptr += pre_header_len;
	}
	return ptr;
}

static
struct rseq_mempool_range *rseq_mempool_range_create(struct rseq_mempool *pool)
{
	struct rseq_mempool_range *range;
	unsigned long page_size;
	void *header;
	void *base;

	page_size = rseq_get_page_len();

	base = aligned_mmap_anonymous(pool, page_size,
			pool->percpu_stride * pool->max_nr_cpus,
			pool->percpu_stride,
			&header, page_size);
	if (!base)
		return NULL;
	range = (struct rseq_mempool_range *) (base - RANGE_HEADER_OFFSET);
	range->pool = pool;
	range->base = base;
	range->header = header;
	if (pool->attr.robust_set) {
		if (create_alloc_bitmap(pool, range))
			goto error_alloc;
	}
	return range;

error_alloc:
	(void) rseq_mempool_range_destroy(pool, range);
	return NULL;
}

int rseq_mempool_destroy(struct rseq_mempool *pool)
{
	struct rseq_mempool_range *range, *next_range;
	int ret = 0;

	if (!pool)
		return 0;
	check_free_list(pool);
	/* Iteration safe against removal. */
	for (range = pool->ranges; range && (next_range = range->next, 1); range = next_range) {
		if (rseq_mempool_range_destroy(pool, range))
			goto end;
		/* Update list head to keep list coherent in case of partial failure. */
		pool->ranges = next_range;
	}
	pthread_mutex_destroy(&pool->lock);
	free(pool->name);
	memset(pool, 0, sizeof(*pool));
end:
	return ret;
}

struct rseq_mempool *rseq_mempool_create(const char *pool_name,
		size_t item_len, size_t percpu_stride, int max_nr_cpus,
		const struct rseq_mempool_attr *_attr)
{
	struct rseq_mempool *pool;
	struct rseq_mempool_attr attr = {};
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

	if (!percpu_stride)
		percpu_stride = RSEQ_PERCPU_STRIDE;	/* Use default */

	if (max_nr_cpus < 0 || item_len > percpu_stride ||
			percpu_stride < (size_t) rseq_get_page_len() ||
			!is_pow2(percpu_stride)) {
		errno = EINVAL;
		return NULL;
	}

	if (_attr)
		memcpy(&attr, _attr, sizeof(attr));
	if (!attr.mmap_set) {
		attr.mmap_func = default_mmap_func;
		attr.munmap_func = default_munmap_func;
		attr.mmap_priv = NULL;
	}

	pool = calloc(1, sizeof(struct rseq_mempool));
	if (!pool)
		return NULL;

	memcpy(&pool->attr, &attr, sizeof(attr));
	pthread_mutex_init(&pool->lock, NULL);
	pool->percpu_stride = percpu_stride;
	pool->max_nr_cpus = max_nr_cpus;
	pool->item_len = item_len;
	pool->item_order = order;

	//TODO: implement multi-range support.
	pool->ranges = rseq_mempool_range_create(pool);
	if (!pool->ranges)
		goto error_alloc;

	if (pool_name) {
		pool->name = strdup(pool_name);
		if (!pool->name)
			goto error_alloc;
	}
	return pool;

error_alloc:
	rseq_mempool_destroy(pool);
	errno = ENOMEM;
	return NULL;
}

/* Always inline for __builtin_return_address(0). */
static inline __attribute__((always_inline))
void set_alloc_slot(struct rseq_mempool *pool, size_t item_offset)
{
	unsigned long *bitmap = pool->ranges->alloc_bitmap;
	size_t item_index = item_offset >> pool->item_order;
	unsigned long mask;
	size_t k;

	if (!bitmap)
		return;

	k = item_index / BIT_PER_ULONG;
	mask = 1ULL << (item_index % BIT_PER_ULONG);

	/* Print error if bit is already set. */
	if (bitmap[k] & mask) {
		fprintf(stderr, "%s: Allocator corruption detected for pool: \"%s\" (%p), item offset: %zu, caller: %p.\n",
			__func__, get_pool_name(pool), pool, item_offset, (void *) __builtin_return_address(0));
		abort();
	}
	bitmap[k] |= mask;
}

static
void __rseq_percpu *__rseq_percpu_malloc(struct rseq_mempool *pool, bool zeroed)
{
	struct free_list_node *node;
	uintptr_t item_offset;
	void __rseq_percpu *addr;

	pthread_mutex_lock(&pool->lock);
	/* Get first entry from free list. */
	node = pool->free_list_head;
	if (node != NULL) {
		/* Remove node from free list (update head). */
		pool->free_list_head = node->next;
		item_offset = (uintptr_t) ((void *) node - pool->ranges->base);
		addr = (void __rseq_percpu *) (pool->ranges->base + item_offset);
		goto end;
	}
	if (pool->ranges->next_unused + pool->item_len > pool->percpu_stride) {
		errno = ENOMEM;
		addr = NULL;
		goto end;
	}
	item_offset = pool->ranges->next_unused;
	addr = (void __rseq_percpu *) (pool->ranges->base + item_offset);
	pool->ranges->next_unused += pool->item_len;
end:
	if (addr)
		set_alloc_slot(pool, item_offset);
	pthread_mutex_unlock(&pool->lock);
	if (zeroed && addr)
		rseq_percpu_zero_item(pool, item_offset);
	return addr;
}

void __rseq_percpu *rseq_percpu_malloc(struct rseq_mempool *pool)
{
	return __rseq_percpu_malloc(pool, false);
}

void __rseq_percpu *rseq_percpu_zmalloc(struct rseq_mempool *pool)
{
	return __rseq_percpu_malloc(pool, true);
}

/* Always inline for __builtin_return_address(0). */
static inline __attribute__((always_inline))
void clear_alloc_slot(struct rseq_mempool *pool, size_t item_offset)
{
	unsigned long *bitmap = pool->ranges->alloc_bitmap;
	size_t item_index = item_offset >> pool->item_order;
	unsigned long mask;
	size_t k;

	if (!bitmap)
		return;

	k = item_index / BIT_PER_ULONG;
	mask = 1ULL << (item_index % BIT_PER_ULONG);

	/* Print error if bit is not set. */
	if (!(bitmap[k] & mask)) {
		fprintf(stderr, "%s: Double-free detected for pool: \"%s\" (%p), item offset: %zu, caller: %p.\n",
			__func__, get_pool_name(pool), pool, item_offset,
			(void *) __builtin_return_address(0));
		abort();
	}
	bitmap[k] &= ~mask;
}

void __rseq_percpu_free(void __rseq_percpu *_ptr, size_t percpu_stride)
{
	uintptr_t ptr = (uintptr_t) _ptr;
	void *range_base = (void *) (ptr & (~(percpu_stride - 1)));
	struct rseq_mempool_range *range = (struct rseq_mempool_range *) (range_base - RANGE_HEADER_OFFSET);
	struct rseq_mempool *pool = range->pool;
	uintptr_t item_offset = ptr & (percpu_stride - 1);
	struct free_list_node *head, *item;

	pthread_mutex_lock(&pool->lock);
	clear_alloc_slot(pool, item_offset);
	/* Add ptr to head of free list */
	head = pool->free_list_head;
	/* Free-list is in CPU 0 range. */
	item = (struct free_list_node *) ptr;
	item->next = head;
	pool->free_list_head = item;
	pthread_mutex_unlock(&pool->lock);
}

struct rseq_mempool_set *rseq_mempool_set_create(void)
{
	struct rseq_mempool_set *pool_set;

	pool_set = calloc(1, sizeof(struct rseq_mempool_set));
	if (!pool_set)
		return NULL;
	pthread_mutex_init(&pool_set->lock, NULL);
	return pool_set;
}

int rseq_mempool_set_destroy(struct rseq_mempool_set *pool_set)
{
	int order, ret;

	for (order = POOL_SET_MIN_ENTRY; order < POOL_SET_NR_ENTRIES; order++) {
		struct rseq_mempool *pool = pool_set->entries[order];

		if (!pool)
			continue;
		ret = rseq_mempool_destroy(pool);
		if (ret)
			return ret;
		pool_set->entries[order] = NULL;
	}
	pthread_mutex_destroy(&pool_set->lock);
	free(pool_set);
	return 0;
}

/* Ownership of pool is handed over to pool set on success. */
int rseq_mempool_set_add_pool(struct rseq_mempool_set *pool_set, struct rseq_mempool *pool)
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
void __rseq_percpu *__rseq_mempool_set_malloc(struct rseq_mempool_set *pool_set, size_t len, bool zeroed)
{
	int order, min_order = POOL_SET_MIN_ENTRY;
	struct rseq_mempool *pool;
	void __rseq_percpu *addr;

	order = rseq_get_count_order_ulong(len);
	if (order > POOL_SET_MIN_ENTRY)
		min_order = order;
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

void __rseq_percpu *rseq_percpu_mempool_set_malloc(struct rseq_mempool_set *pool_set, size_t len)
{
	return __rseq_mempool_set_malloc(pool_set, len, false);
}

void __rseq_percpu *rseq_percpu_mempool_set_zmalloc(struct rseq_mempool_set *pool_set, size_t len)
{
	return __rseq_mempool_set_malloc(pool_set, len, true);
}

struct rseq_mempool_attr *rseq_mempool_attr_create(void)
{
	return calloc(1, sizeof(struct rseq_mempool_attr));
}

void rseq_mempool_attr_destroy(struct rseq_mempool_attr *attr)
{
	free(attr);
}

int rseq_mempool_attr_set_mmap(struct rseq_mempool_attr *attr,
		void *(*mmap_func)(void *priv, size_t len),
		int (*munmap_func)(void *priv, void *ptr, size_t len),
		void *mmap_priv)
{
	if (!attr) {
		errno = EINVAL;
		return -1;
	}
	attr->mmap_set = true;
	attr->mmap_func = mmap_func;
	attr->munmap_func = munmap_func;
	attr->mmap_priv = mmap_priv;
	return 0;
}

int rseq_mempool_attr_set_robust(struct rseq_mempool_attr *attr)
{
	if (!attr) {
		errno = EINVAL;
		return -1;
	}
	attr->robust_set = true;
	return 0;
}
