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
#include <fcntl.h>

#ifdef HAVE_LIBNUMA
# include <numa.h>
# include <numaif.h>
#endif

#include "rseq-utils.h"
#include <rseq/rseq.h>

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

#define BIT_PER_ULONG		(8 * sizeof(unsigned long))

#define MOVE_PAGES_BATCH_SIZE	4096

#define RANGE_HEADER_OFFSET	sizeof(struct rseq_mempool_range)

#if RSEQ_BITS_PER_LONG == 64
# define DEFAULT_POISON_VALUE	0x5555555555555555ULL
#else
# define DEFAULT_POISON_VALUE	0x55555555UL
#endif

struct free_list_node;

struct free_list_node {
	struct free_list_node *next;
};

enum mempool_type {
	MEMPOOL_TYPE_GLOBAL = 0,	/* Default */
	MEMPOOL_TYPE_PERCPU = 1,
};

struct rseq_mempool_attr {
	bool mmap_set;
	void *(*mmap_func)(void *priv, size_t len);
	int (*munmap_func)(void *priv, void *ptr, size_t len);
	void *mmap_priv;

	bool init_set;
	int (*init_func)(void *priv, void *addr, size_t len, int cpu);
	void *init_priv;

	bool robust_set;

	enum mempool_type type;
	size_t stride;
	int max_nr_cpus;

	unsigned long max_nr_ranges;

	bool poison_set;
	uintptr_t poison;

	enum rseq_mempool_populate_policy populate_policy;
};

struct rseq_mempool_range;

struct rseq_mempool_range {
	struct rseq_mempool_range *next;	/* Linked list of ranges. */
	struct rseq_mempool *pool;		/* Backward reference to container pool. */

	/*
	 * Memory layout of a mempool range:
	 * - Header page (contains struct rseq_mempool_range at the very end),
	 * - Base of the per-cpu data, starting with CPU 0,
	 * - CPU 1,
	 * ...
	 * - CPU max_nr_cpus - 1
	 * - init values (unpopulated for RSEQ_MEMPOOL_POPULATE_ALL).
	 */
	void *header;
	void *base;
	/*
	 * The init values contains malloc_init/zmalloc values.
	 * Pointer is NULL for RSEQ_MEMPOOL_POPULATE_ALL.
	 */
	void *init;
	size_t next_unused;

	/* Pool range mmap/munmap */
	void *mmap_addr;
	size_t mmap_len;

	/* Track alloc/free. */
	unsigned long *alloc_bitmap;
};

struct rseq_mempool {
	/* Head of ranges linked-list. */
	struct rseq_mempool_range *range_list;
	unsigned long nr_ranges;

	size_t item_len;
	int item_order;

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

/*
 * This memfd is used to implement the user COW behavior for the page
 * protection scheme. memfd is a sparse virtual file. Its layout (in
 * offset from beginning of file) matches the process address space
 * (pointers directly converted to file offsets).
 */
struct rseq_memfd {
	pthread_mutex_t lock;
	size_t reserved_size;
	unsigned int refcount;
	int fd;
};

static struct rseq_memfd memfd = {
	.lock = PTHREAD_MUTEX_INITIALIZER,
	.reserved_size = 0,
	.refcount = 0,
	.fd = -1,
};

static
const char *get_pool_name(const struct rseq_mempool *pool)
{
	return pool->name ? : "<anonymous>";
}

static
void *__rseq_pool_range_percpu_ptr(const struct rseq_mempool_range *range, int cpu,
		uintptr_t item_offset, size_t stride)
{
	return range->base + (stride * cpu) + item_offset;
}

static
void *__rseq_pool_range_init_ptr(const struct rseq_mempool_range *range,
		uintptr_t item_offset)
{
	if (!range->init)
		return NULL;
	return range->init + item_offset;
}

static
void __rseq_percpu *__rseq_free_list_to_percpu_ptr(const struct rseq_mempool *pool,
		struct free_list_node *node)
{
	void __rseq_percpu *p = (void __rseq_percpu *) node;

	if (pool->attr.populate_policy != RSEQ_MEMPOOL_POPULATE_ALL)
		p -= pool->attr.max_nr_cpus * pool->attr.stride;
	return p;
}

static
struct free_list_node *__rseq_percpu_to_free_list_ptr(const struct rseq_mempool *pool,
		void __rseq_percpu *p)
{
	if (pool->attr.populate_policy != RSEQ_MEMPOOL_POPULATE_ALL)
		p += pool->attr.max_nr_cpus * pool->attr.stride;
	return (struct free_list_node *) p;
}

static
int memcmpbyte(const char *s, int c, size_t n)
{
	int res = 0;

	while (n-- > 0)
		if ((res = *(s++) - c) != 0)
			break;
	return res;
}

static
void rseq_percpu_zero_item(struct rseq_mempool *pool,
		struct rseq_mempool_range *range, uintptr_t item_offset)
{
	char *init_p = NULL;
	int i;

	init_p = __rseq_pool_range_init_ptr(range, item_offset);
	if (init_p)
		memset(init_p, 0, pool->item_len);
	for (i = 0; i < pool->attr.max_nr_cpus; i++) {
		char *p = __rseq_pool_range_percpu_ptr(range, i,
				item_offset, pool->attr.stride);

		/* Update propagated */
		if (init_p && !memcmpbyte(p, 0, pool->item_len))
			continue;
		memset(p, 0, pool->item_len);
	}
}

static
void rseq_percpu_init_item(struct rseq_mempool *pool,
		struct rseq_mempool_range *range, uintptr_t item_offset,
		void *init_ptr, size_t init_len)
{
	char *init_p = NULL;
	int i;

	init_p = __rseq_pool_range_init_ptr(range, item_offset);
	if (init_p)
		memcpy(init_p, init_ptr, init_len);
	for (i = 0; i < pool->attr.max_nr_cpus; i++) {
		char *p = __rseq_pool_range_percpu_ptr(range, i,
				item_offset, pool->attr.stride);

		/* Update propagated */
		if (init_p && !memcmp(init_p, p, init_len))
			continue;
		memcpy(p, init_ptr, init_len);
	}
}

static
void rseq_poison_item(void *p, size_t item_len, uintptr_t poison)
{
	size_t offset;

	for (offset = 0; offset < item_len; offset += sizeof(uintptr_t))
		*((uintptr_t *) (p + offset)) = poison;
}

static
void rseq_percpu_poison_item(struct rseq_mempool *pool,
		struct rseq_mempool_range *range, uintptr_t item_offset)
{
	uintptr_t poison = pool->attr.poison;
	char *init_p = NULL;
	int i;

	init_p = __rseq_pool_range_init_ptr(range, item_offset);
	if (init_p)
		rseq_poison_item(init_p, pool->item_len, poison);
	for (i = 0; i < pool->attr.max_nr_cpus; i++) {
		char *p = __rseq_pool_range_percpu_ptr(range, i,
				item_offset, pool->attr.stride);

		/* Update propagated */
		if (init_p && !memcmp(init_p, p, pool->item_len))
			continue;
		rseq_poison_item(p, pool->item_len, poison);
	}
}

/* Always inline for __builtin_return_address(0). */
static inline __attribute__((always_inline))
void rseq_check_poison_item(const struct rseq_mempool *pool, uintptr_t item_offset,
		void *p, size_t item_len, uintptr_t poison, bool skip_freelist_ptr)
{
	size_t offset;

	for (offset = 0; offset < item_len; offset += sizeof(uintptr_t)) {
		uintptr_t v;

		/* Skip poison check for free-list pointer. */
		if (skip_freelist_ptr && offset == 0)
			continue;
		v = *((uintptr_t *) (p + offset));
		if (v != poison) {
			fprintf(stderr, "%s: Poison corruption detected (0x%lx) for pool: \"%s\" (%p), item offset: %zu, caller: %p.\n",
				__func__, (unsigned long) v, get_pool_name(pool), pool, item_offset, (void *) __builtin_return_address(0));
			abort();
		}
	}
}

/* Always inline for __builtin_return_address(0). */
static inline __attribute__((always_inline))
void rseq_percpu_check_poison_item(const struct rseq_mempool *pool,
		const struct rseq_mempool_range *range, uintptr_t item_offset)
{
	uintptr_t poison = pool->attr.poison;
	char *init_p;
	int i;

	if (!pool->attr.robust_set)
		return;
	init_p = __rseq_pool_range_init_ptr(range, item_offset);
	if (init_p)
		rseq_check_poison_item(pool, item_offset, init_p, pool->item_len, poison, true);
	for (i = 0; i < pool->attr.max_nr_cpus; i++) {
		char *p = __rseq_pool_range_percpu_ptr(range, i,
				item_offset, pool->attr.stride);
		/*
		 * When the free list is embedded in the init values
		 * memory (populate none), it is visible from the init
		 * values memory mapping as well as per-cpu private
		 * mappings before they COW.
		 *
		 * When the free list is embedded in CPU 0 mapping
		 * (populate all), only this CPU must skip the free list
		 * nodes when checking poison.
		 */
		rseq_check_poison_item(pool, item_offset, p, pool->item_len, poison,
			init_p == NULL ? (i == 0) : true);
	}
}

#ifdef HAVE_LIBNUMA
int rseq_mempool_range_init_numa(void *addr, size_t len, int cpu, int numa_flags)
{
	unsigned long nr_pages, page_len;
	int status[MOVE_PAGES_BATCH_SIZE];
	int nodes[MOVE_PAGES_BATCH_SIZE];
	void *pages[MOVE_PAGES_BATCH_SIZE];
	long ret;

	if (!numa_flags) {
		errno = EINVAL;
		return -1;
	}
	page_len = rseq_get_page_len();
	nr_pages = len >> rseq_get_count_order_ulong(page_len);

	nodes[0] = numa_node_of_cpu(cpu);
	if (nodes[0] < 0)
		return -1;

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
			pages[k] = addr + (page * page_len);
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
	return 0;
}
#else
int rseq_mempool_range_init_numa(void *addr __attribute__((unused)),
		size_t len __attribute__((unused)),
		int cpu __attribute__((unused)),
		int numa_flags __attribute__((unused)))
{
	errno = ENOSYS;
	return -1;
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

	count = ((pool->attr.stride >> pool->item_order) + BIT_PER_ULONG - 1) / BIT_PER_ULONG;

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
bool percpu_addr_in_pool(const struct rseq_mempool *pool, void __rseq_percpu *_addr)
{
	struct rseq_mempool_range *range;
	void *addr = (void *) _addr;

	for (range = pool->range_list; range; range = range->next) {
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

	for (range = pool->range_list; range; range = range->next) {
		total_item += pool->attr.stride >> pool->item_order;
		total_never_allocated += (pool->attr.stride - range->next_unused) >> pool->item_order;
	}
	max_list_traversal = total_item - total_never_allocated;

	for (struct free_list_node *node = pool->free_list_head, *prev = NULL;
	     node;
	     prev = node,
	     node = node->next) {

		if (traversal_iteration >= max_list_traversal) {
			fprintf(stderr, "%s: Corrupted free-list; Possibly infinite loop in pool \"%s\" (%p), caller %p.\n",
				__func__, get_pool_name(pool), pool, __builtin_return_address(0));
			abort();
		}

		/* Node is out of range. */
		if (!percpu_addr_in_pool(pool, __rseq_free_list_to_percpu_ptr(pool, node))) {
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
void check_range_poison(const struct rseq_mempool *pool,
		const struct rseq_mempool_range *range)
{
	size_t item_offset;

	for (item_offset = 0; item_offset < range->next_unused;
			item_offset += pool->item_len)
		rseq_percpu_check_poison_item(pool, range, item_offset);
}

/* Always inline for __builtin_return_address(0). */
static inline __attribute__((always_inline))
void check_pool_poison(const struct rseq_mempool *pool)
{
	struct rseq_mempool_range *range;

	if (!pool->attr.robust_set)
		return;
	for (range = pool->range_list; range; range = range->next)
		check_range_poison(pool, range);
}

/* Always inline for __builtin_return_address(0). */
static inline __attribute__((always_inline))
void destroy_alloc_bitmap(struct rseq_mempool *pool, struct rseq_mempool_range *range)
{
	unsigned long *bitmap = range->alloc_bitmap;
	size_t count, total_leaks = 0;

	if (!bitmap)
		return;

	count = ((pool->attr.stride >> pool->item_order) + BIT_PER_ULONG - 1) / BIT_PER_ULONG;

	/* Assert that all items in the pool were freed. */
	for (size_t k = 0; k < count; ++k)
		total_leaks += rseq_hweight_ulong(bitmap[k]);
	if (total_leaks) {
		fprintf(stderr, "%s: Pool \"%s\" (%p) has %zu leaked items on destroy, caller: %p.\n",
			__func__, get_pool_name(pool), pool, total_leaks, (void *) __builtin_return_address(0));
		abort();
	}

	free(bitmap);
	range->alloc_bitmap = NULL;
}

/* Always inline for __builtin_return_address(0). */
static inline __attribute__((always_inline))
int rseq_mempool_range_destroy(struct rseq_mempool *pool,
		struct rseq_mempool_range *range)
{
	int ret = 0;

	destroy_alloc_bitmap(pool, range);

	/*
	 * Punch a hole into memfd where the init values used to be.
	 */
	if (range->init) {
		ret = fallocate(memfd.fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
			(off_t) range->init, pool->attr.stride);
		if (ret)
			return ret;
		range->init = NULL;
	}

	/* range is a header located one page before the aligned mapping. */
	return pool->attr.munmap_func(pool->attr.mmap_priv, range->mmap_addr, range->mmap_len);
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
			!is_pow2(alignment) || (len & (alignment - 1))) {
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
int rseq_memfd_reserve_init(void *init, size_t init_len)
{
	int ret = 0;
	size_t reserve_len;

	pthread_mutex_lock(&memfd.lock);
	reserve_len = (size_t) init + init_len;
	if (reserve_len > memfd.reserved_size) {
		if (ftruncate(memfd.fd, (off_t) reserve_len)) {
			ret = -1;
			goto unlock;
		}
		memfd.reserved_size = reserve_len;
	}
unlock:
	pthread_mutex_unlock(&memfd.lock);
	return ret;
}

static
struct rseq_mempool_range *rseq_mempool_range_create(struct rseq_mempool *pool)
{
	struct rseq_mempool_range *range;
	unsigned long page_size;
	void *header;
	void *base;
	size_t range_len;	/* Range len excludes header. */

	if (pool->attr.max_nr_ranges &&
			pool->nr_ranges >= pool->attr.max_nr_ranges) {
		errno = ENOMEM;
		return NULL;
	}
	page_size = rseq_get_page_len();

	range_len = pool->attr.stride * pool->attr.max_nr_cpus;
	if (pool->attr.populate_policy != RSEQ_MEMPOOL_POPULATE_ALL)
		range_len += pool->attr.stride;	/* init values */
	base = aligned_mmap_anonymous(pool, page_size,
			range_len,
			pool->attr.stride,
			&header, page_size);
	if (!base)
		return NULL;
	range = (struct rseq_mempool_range *) (base - RANGE_HEADER_OFFSET);
	range->pool = pool;
	range->header = header;
	range->base = base;
	range->mmap_addr = header;
	range->mmap_len = page_size + range_len;

	if (pool->attr.populate_policy != RSEQ_MEMPOOL_POPULATE_ALL) {
		range->init = base + (pool->attr.stride * pool->attr.max_nr_cpus);
		/* Populate init values pages from memfd */
		if (rseq_memfd_reserve_init(range->init, pool->attr.stride))
			goto error_alloc;
		if (mmap(range->init, pool->attr.stride, PROT_READ | PROT_WRITE,
				MAP_SHARED | MAP_FIXED, memfd.fd,
				(off_t) range->init) != (void *) range->init) {
			goto error_alloc;
		}
		assert(pool->attr.type == MEMPOOL_TYPE_PERCPU);
		/*
		 * Map per-cpu memory as private COW mappings of init values.
		 */
		{
			int cpu;

			for (cpu = 0; cpu < pool->attr.max_nr_cpus; cpu++) {
				void *p = base + (pool->attr.stride * cpu);
				size_t len = pool->attr.stride;

				if (mmap(p, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED,
						memfd.fd, (off_t) range->init) != (void *) p) {
					goto error_alloc;
				}
			}
		}
	}

	if (pool->attr.robust_set) {
		if (create_alloc_bitmap(pool, range))
			goto error_alloc;
	}
	if (pool->attr.init_set) {
		switch (pool->attr.type) {
		case MEMPOOL_TYPE_GLOBAL:
			if (pool->attr.init_func(pool->attr.init_priv,
					base, pool->attr.stride, -1)) {
				goto error_alloc;
			}
			break;
		case MEMPOOL_TYPE_PERCPU:
		{
			int cpu;
			for (cpu = 0; cpu < pool->attr.max_nr_cpus; cpu++) {
				if (pool->attr.init_func(pool->attr.init_priv,
						base + (pool->attr.stride * cpu),
						pool->attr.stride, cpu)) {
					goto error_alloc;
				}
			}
			break;
		}
		default:
			abort();
		}
	}
	pool->nr_ranges++;
	return range;

error_alloc:
	(void) rseq_mempool_range_destroy(pool, range);
	return NULL;
}

static
int rseq_mempool_memfd_ref(struct rseq_mempool *pool)
{
	int ret = 0;

	if (pool->attr.populate_policy == RSEQ_MEMPOOL_POPULATE_ALL)
		return 0;

	pthread_mutex_lock(&memfd.lock);
	if (memfd.refcount == 0) {
		memfd.fd = memfd_create("mempool", MFD_CLOEXEC);
		if (memfd.fd < 0) {
			perror("memfd_create");
			ret = -1;
			goto unlock;
		}
	}
	memfd.refcount++;
unlock:
	pthread_mutex_unlock(&memfd.lock);
	return ret;
}

static
void rseq_mempool_memfd_unref(struct rseq_mempool *pool)
{
	if (pool->attr.populate_policy == RSEQ_MEMPOOL_POPULATE_ALL)
		return;

	pthread_mutex_lock(&memfd.lock);
	if (memfd.refcount == 1) {
		if (close(memfd.fd)) {
			perror("close");
			abort();
		}
		memfd.fd = -1;
		memfd.reserved_size = 0;
	}
	memfd.refcount--;
	pthread_mutex_unlock(&memfd.lock);
}

int rseq_mempool_destroy(struct rseq_mempool *pool)
{
	struct rseq_mempool_range *range, *next_range;
	int ret = 0;

	if (!pool)
		return 0;
	check_free_list(pool);
	check_pool_poison(pool);
	/* Iteration safe against removal. */
	for (range = pool->range_list; range && (next_range = range->next, 1); range = next_range) {
		if (rseq_mempool_range_destroy(pool, range))
			goto end;
		/* Update list head to keep list coherent in case of partial failure. */
		pool->range_list = next_range;
	}
	rseq_mempool_memfd_unref(pool);
	pthread_mutex_destroy(&pool->lock);
	free(pool->name);
	free(pool);
end:
	return ret;
}

struct rseq_mempool *rseq_mempool_create(const char *pool_name,
		size_t item_len, const struct rseq_mempool_attr *_attr)
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

	if (_attr)
		memcpy(&attr, _attr, sizeof(attr));
	if (!attr.mmap_set) {
		attr.mmap_func = default_mmap_func;
		attr.munmap_func = default_munmap_func;
		attr.mmap_priv = NULL;
	}

	switch (attr.type) {
	case MEMPOOL_TYPE_PERCPU:
		if (attr.max_nr_cpus < 0) {
			errno = EINVAL;
			return NULL;
		}
		if (attr.max_nr_cpus == 0) {
			/* Auto-detect */
			attr.max_nr_cpus = rseq_get_max_nr_cpus();
			if (attr.max_nr_cpus == 0) {
				errno = EINVAL;
				return NULL;
			}
		}
		break;
	case MEMPOOL_TYPE_GLOBAL:
		/* Override populate policy for global type. */
		attr.populate_policy = RSEQ_MEMPOOL_POPULATE_ALL;
		/* Use a 1-cpu pool for global mempool type. */
		attr.max_nr_cpus = 1;
		break;
	}
	if (!attr.stride)
		attr.stride = RSEQ_MEMPOOL_STRIDE;	/* Use default */
	if (attr.robust_set && !attr.poison_set) {
		attr.poison_set = true;
		attr.poison = DEFAULT_POISON_VALUE;
	}
	if (item_len > attr.stride || attr.stride < (size_t) rseq_get_page_len() ||
			!is_pow2(attr.stride)) {
		errno = EINVAL;
		return NULL;
	}

	pool = calloc(1, sizeof(struct rseq_mempool));
	if (!pool)
		return NULL;

	memcpy(&pool->attr, &attr, sizeof(attr));
	pthread_mutex_init(&pool->lock, NULL);
	pool->item_len = item_len;
	pool->item_order = order;

	if (rseq_mempool_memfd_ref(pool))
		goto error_alloc;

	pool->range_list = rseq_mempool_range_create(pool);
	if (!pool->range_list)
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
void set_alloc_slot(struct rseq_mempool *pool, struct rseq_mempool_range *range, size_t item_offset)
{
	unsigned long *bitmap = range->alloc_bitmap;
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
void __rseq_percpu *__rseq_percpu_malloc(struct rseq_mempool *pool,
		bool zeroed, void *init_ptr, size_t init_len)
{
	struct rseq_mempool_range *range;
	struct free_list_node *node;
	uintptr_t item_offset;
	void __rseq_percpu *addr;

	if (init_len > pool->item_len) {
		errno = EINVAL;
		return NULL;
	}
	pthread_mutex_lock(&pool->lock);
	/* Get first entry from free list. */
	node = pool->free_list_head;
	if (node != NULL) {
		void *range_base, *ptr;

		ptr = __rseq_free_list_to_percpu_ptr(pool, node);
		range_base = (void *) ((uintptr_t) ptr & (~(pool->attr.stride - 1)));
		range = (struct rseq_mempool_range *) (range_base - RANGE_HEADER_OFFSET);
		/* Remove node from free list (update head). */
		pool->free_list_head = node->next;
		item_offset = (uintptr_t) (ptr - range_base);
		rseq_percpu_check_poison_item(pool, range, item_offset);
		addr = __rseq_free_list_to_percpu_ptr(pool, node);
		goto end;
	}
	/*
	 * If the most recent range (first in list) does not have any
	 * room left, create a new range and prepend it to the list
	 * head.
	 */
	range = pool->range_list;
	if (range->next_unused + pool->item_len > pool->attr.stride) {
		range = rseq_mempool_range_create(pool);
		if (!range) {
			errno = ENOMEM;
			addr = NULL;
			goto end;
		}
		/* Add range to head of list. */
		range->next = pool->range_list;
		pool->range_list = range;
	}
	/* First range in list has room left. */
	item_offset = range->next_unused;
	addr = (void __rseq_percpu *) (range->base + item_offset);
	range->next_unused += pool->item_len;
end:
	if (addr)
		set_alloc_slot(pool, range, item_offset);
	pthread_mutex_unlock(&pool->lock);
	if (addr) {
		if (zeroed)
			rseq_percpu_zero_item(pool, range, item_offset);
		else if (init_ptr) {
			rseq_percpu_init_item(pool, range, item_offset,
					init_ptr, init_len);
		}
	}
	return addr;
}

void __rseq_percpu *rseq_mempool_percpu_malloc(struct rseq_mempool *pool)
{
	return __rseq_percpu_malloc(pool, false, NULL, 0);
}

void __rseq_percpu *rseq_mempool_percpu_zmalloc(struct rseq_mempool *pool)
{
	return __rseq_percpu_malloc(pool, true, NULL, 0);
}

void __rseq_percpu *rseq_mempool_percpu_malloc_init(struct rseq_mempool *pool,
		void *init_ptr, size_t len)
{
	return __rseq_percpu_malloc(pool, false, init_ptr, len);
}

/* Always inline for __builtin_return_address(0). */
static inline __attribute__((always_inline))
void clear_alloc_slot(struct rseq_mempool *pool, struct rseq_mempool_range *range, size_t item_offset)
{
	unsigned long *bitmap = range->alloc_bitmap;
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

void librseq_mempool_percpu_free(void __rseq_percpu *_ptr, size_t stride)
{
	uintptr_t ptr = (uintptr_t) _ptr;
	void *range_base = (void *) (ptr & (~(stride - 1)));
	struct rseq_mempool_range *range = (struct rseq_mempool_range *) (range_base - RANGE_HEADER_OFFSET);
	struct rseq_mempool *pool = range->pool;
	uintptr_t item_offset = ptr & (stride - 1);
	struct free_list_node *head, *item;

	pthread_mutex_lock(&pool->lock);
	clear_alloc_slot(pool, range, item_offset);
	/* Add ptr to head of free list */
	head = pool->free_list_head;
	if (pool->attr.poison_set)
		rseq_percpu_poison_item(pool, range, item_offset);
	item = __rseq_percpu_to_free_list_ptr(pool, _ptr);
	/*
	 * Setting the next pointer will overwrite the first uintptr_t
	 * poison for either CPU 0 (populate all) or init data (populate
	 * none).
	 */
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
void __rseq_percpu *__rseq_mempool_set_malloc(struct rseq_mempool_set *pool_set,
		void *init_ptr, size_t len, bool zeroed)
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
		addr = __rseq_percpu_malloc(pool, zeroed, init_ptr, len);
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

void __rseq_percpu *rseq_mempool_set_percpu_malloc(struct rseq_mempool_set *pool_set, size_t len)
{
	return __rseq_mempool_set_malloc(pool_set, NULL, len, false);
}

void __rseq_percpu *rseq_mempool_set_percpu_zmalloc(struct rseq_mempool_set *pool_set, size_t len)
{
	return __rseq_mempool_set_malloc(pool_set, NULL, len, true);
}

void __rseq_percpu *rseq_mempool_set_percpu_malloc_init(struct rseq_mempool_set *pool_set,
		void *init_ptr, size_t len)
{
	return __rseq_mempool_set_malloc(pool_set, init_ptr, len, true);
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

int rseq_mempool_attr_set_init(struct rseq_mempool_attr *attr,
		int (*init_func)(void *priv, void *addr, size_t len, int cpu),
		void *init_priv)
{
	if (!attr) {
		errno = EINVAL;
		return -1;
	}
	attr->init_set = true;
	attr->init_func = init_func;
	attr->init_priv = init_priv;
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

int rseq_mempool_attr_set_percpu(struct rseq_mempool_attr *attr,
		size_t stride, int max_nr_cpus)
{
	if (!attr) {
		errno = EINVAL;
		return -1;
	}
	attr->type = MEMPOOL_TYPE_PERCPU;
	attr->stride = stride;
	attr->max_nr_cpus = max_nr_cpus;
	return 0;
}

int rseq_mempool_attr_set_global(struct rseq_mempool_attr *attr,
		size_t stride)
{
	if (!attr) {
		errno = EINVAL;
		return -1;
	}
	attr->type = MEMPOOL_TYPE_GLOBAL;
	attr->stride = stride;
	attr->max_nr_cpus = 0;
	return 0;
}

int rseq_mempool_attr_set_max_nr_ranges(struct rseq_mempool_attr *attr,
		unsigned long max_nr_ranges)
{
	if (!attr) {
		errno = EINVAL;
		return -1;
	}
	attr->max_nr_ranges = max_nr_ranges;
	return 0;
}

int rseq_mempool_attr_set_poison(struct rseq_mempool_attr *attr,
		uintptr_t poison)
{
	if (!attr) {
		errno = EINVAL;
		return -1;
	}
	attr->poison_set = true;
	attr->poison = poison;
	return 0;
}

int rseq_mempool_attr_set_populate_policy(struct rseq_mempool_attr *attr,
		enum rseq_mempool_populate_policy policy)
{
	if (!attr) {
		errno = EINVAL;
		return -1;
	}
	attr->populate_policy = policy;
	return 0;
}

int rseq_mempool_get_max_nr_cpus(struct rseq_mempool *mempool)
{
	if (!mempool || mempool->attr.type != MEMPOOL_TYPE_PERCPU) {
		errno = EINVAL;
		return -1;
	}
	return mempool->attr.max_nr_cpus;
}
