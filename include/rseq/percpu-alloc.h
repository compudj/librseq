/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: 2024 Mathieu Desnoyers <mathieu.desnoyers@efficios.com> */

#ifndef _RSEQ_PERCPU_ALLOC_H
#define _RSEQ_PERCPU_ALLOC_H

#include <stddef.h>
#include <sys/types.h>
#include <sys/mman.h>

/*
 * rseq/percpu-alloc.h: rseq CPU-Local Storage (CLS) memory allocator.
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

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Tag pointers returned by:
 * - rseq_percpu_malloc(),
 * - rseq_percpu_zmalloc(),
 * - rseq_percpu_pool_set_malloc(),
 * - rseq_percpu_pool_set_zmalloc().
 *
 * and passed as parameter to:
 * - rseq_percpu_ptr(),
 * - rseq_percpu_free().
 *
 * with __rseq_percpu for use by static analyzers.
 */
#define __rseq_percpu

struct rseq_percpu_pool;

/*
 * rseq_percpu_pool_create: Create a per-cpu memory pool.
 *
 * Create a per-cpu memory pool for items of size @item_len (rounded to
 * next power of two). The reserved allocation size is @percpu_len, and
 * the maximum CPU value expected is (@max_nr_cpus - 1).
 *
 * Arguments @mmap_prot, @mmap_flags, @mmap_fd, @mmap_offset are passed
 * as arguments to mmap(2) when allocating the memory area holding the
 * percpu pool.
 *
 * Argument @numa_flags are passed to move_pages(2). The expected flags
 * are:
 *   0:                do not move pages to specific numa nodes
 *                     (use for e.g. mm_cid indexing).
 *   MPOL_MF_MOVE:     move process-private pages to cpu-specific numa nodes.
 *   MPOL_MF_MOVE_ALL: move shared pages to cpu-specific numa nodes
 *                     (requires CAP_SYS_NICE).
 *
 * Returns a pointer to the created percpu pool. Return NULL on error,
 * with errno set accordingly:
 *   EINVAL: Invalid argument.
 *   ENOMEM: Not enough resources (memory or pool indexes) available to
 *           allocate pool.
 *
 * In addition, if mmap(2) fails, NULL is returned and errno is
 * propagated from mmap(2).
 *
 * This API is MT-safe.
 */
struct rseq_percpu_pool *rseq_percpu_pool_create(size_t item_len,
		size_t percpu_len, int max_nr_cpus,
		int mmap_prot, int mmap_flags, int mmap_fd, off_t mmap_offset,
		int numa_flags);

/*
 * rseq_percpu_pool_destroy: Destroy a per-cpu memory pool.
 *
 * Destroy a per-cpu memory pool, unmapping its memory and removing the
 * pool entry from the global index. No pointers allocated from the
 * pool should be used when it is destroyed. This includes rseq_percpu_ptr().
 *
 * Argument @pool is a pointer to the per-cpu pool to destroy.
 *
 * Return values: 0 on success, -1 on error, with errno set accordingly:
 *   ENOENT: Trying to free a pool which was not allocated.
 *
 * If munmap(2) fails, -1 is returned and errno is propagated from
 * munmap(2).
 *
 * This API is MT-safe.
 */
int rseq_percpu_pool_destroy(struct rseq_percpu_pool *pool);

/*
 * rseq_percpu_malloc: Allocate memory from a per-cpu pool.
 *
 * Allocate an item from a per-cpu @pool. The allocation will reserve
 * an item of the size specified by @item_len (rounded to next power of
 * two) at pool creation. This effectively reserves space for this item
 * on all CPUs.
 *
 * On success, return a "__rseq_percpu" encoded pointer to the pool
 * item. This encoded pointer is meant to be passed to rseq_percpu_ptr()
 * to be decoded to a valid address before being accessed.
 *
 * Return NULL (errno=ENOMEM) if there is not enough space left in the
 * pool to allocate an item.
 *
 * This API is MT-safe.
 */
void __rseq_percpu *rseq_percpu_malloc(struct rseq_percpu_pool *pool);

/*
 * rseq_percpu_zmalloc: Allocated zero-initialized memory from a per-cpu pool.
 *
 * Allocate memory for an item within the pool, and zero-initialize its
 * memory on all CPUs. See rseq_percpu_malloc for details.
 *
 * This API is MT-safe.
 */
void __rseq_percpu *rseq_percpu_zmalloc(struct rseq_percpu_pool *pool);

/*
 * rseq_percpu_free: Free memory from a per-cpu pool.
 *
 * Free an item pointed to by @ptr from its per-cpu pool.
 *
 * The @ptr argument is a __rseq_percpu encoded pointer returned by
 * either:
 *
 * - rseq_percpu_malloc(),
 * - rseq_percpu_zmalloc(),
 * - rseq_percpu_pool_set_malloc(),
 * - rseq_percpu_pool_set_zmalloc().
 *
 * This API is MT-safe.
 */
void rseq_percpu_free(void __rseq_percpu *ptr);

/*
 * rseq_percpu_ptr: Decode a per-cpu pointer.
 *
 * Decode a per-cpu pointer @ptr to get the associated pointer for the
 * given @cpu. The @ptr argument is a __rseq_percpu encoded pointer
 * returned by either:
 *
 * - rseq_percpu_malloc(),
 * - rseq_percpu_zmalloc(),
 * - rseq_percpu_pool_set_malloc(),
 * - rseq_percpu_pool_set_zmalloc().
 *
 * The __rseq_percpu pointer can be decoded with rseq_percpu_ptr() even
 * after it has been freed, as long as its associated pool has not been
 * destroyed. However, memory pointed to by the decoded pointer should
 * not be accessed after the __rseq_percpu pointer has been freed.
 *
 * The macro rseq_percpu_ptr() preserves the type of the @ptr parameter
 * for the returned pointer, but removes the __rseq_percpu annotation.
 *
 * This API is MT-safe.
 */
void *__rseq_percpu_ptr(void __rseq_percpu *ptr, int cpu);
#define rseq_percpu_ptr(ptr, cpu)	((__typeof__(*(ptr)) *) __rseq_percpu_ptr(ptr, cpu))

/*
 * rseq_percpu_pool_cpu_offset: Return the offset from encoded to decoded percpu pointer.
 *
 * Calculate the offset from any __rseq_percpu pointer allocated from
 * the pool to its associated per-cpu data for @cpu.
 *
 * This API is MT-safe.
 */
ptrdiff_t rseq_percpu_pool_ptr_offset(struct rseq_percpu_pool *pool, int cpu);

/*
 * rseq_percpu_pool_set_create: Create a pool set.
 *
 * Create a set of pools. Its purpose is to offer a memory allocator API
 * for variable-length items (e.g. variable length strings). When
 * created, the pool set has no pool. Pools can be created and added to
 * the set. One common approach would be to create pools for each
 * relevant power of two allocation size useful for the application.
 * Only one pool can be added to the pool set for each power of two
 * allocation size.
 *
 * Returns a pool set pointer on success, else returns NULL with
 * errno=ENOMEM (out of memory).
 *
 * This API is MT-safe.
 */
struct rseq_percpu_pool_set *rseq_percpu_pool_set_create(void);

/*
 * rseq_percpu_pool_set_destroy: Destroy a pool set.
 *
 * Destroy a pool set and its associated resources. The pools that were
 * added to the pool set are destroyed as well.
 *
 * Returns 0 on success, -1 on failure (or partial failure), with errno
 * set by rseq_percpu_pool_destroy(). Using a pool set after destroy
 * failure is undefined.
 *
 * This API is MT-safe.
 */
int rseq_percpu_pool_set_destroy(struct rseq_percpu_pool_set *pool_set);

/*
 * rseq_percpu_pool_set_add_pool: Add a pool to a pool set.
 *
 * Add a @pool to the @pool_set. On success, its ownership is handed
 * over to the pool set, so the caller should not destroy it explicitly.
 * Only one pool can be added to the pool set for each power of two
 * allocation size.
 *
 * Returns 0 on success, -1 on error with the following errno:
 * - EBUSY: A pool already exists in the pool set for this power of two
 *          allocation size.
 *
 * This API is MT-safe.
 */
int rseq_percpu_pool_set_add_pool(struct rseq_percpu_pool_set *pool_set,
		struct rseq_percpu_pool *pool);

/*
 * rseq_percpu_pool_set_malloc: Allocate memory from a per-cpu pool set.
 *
 * Allocate an item from a per-cpu @pool. The allocation will reserve
 * an item of the size specified by @len (rounded to next power of
 * two). This effectively reserves space for this item on all CPUs.
 *
 * The space reservation will search for the smallest pool within
 * @pool_set which respects the following conditions:
 *
 * - it has an item size large enough to fit @len,
 * - it has space available.
 *
 * On success, return a "__rseq_percpu" encoded pointer to the pool
 * item. This encoded pointer is meant to be passed to rseq_percpu_ptr()
 * to be decoded to a valid address before being accessed.
 *
 * Return NULL (errno=ENOMEM) if there is not enough space left in the
 * pool to allocate an item.
 *
 * This API is MT-safe.
 */
void __rseq_percpu *rseq_percpu_pool_set_malloc(struct rseq_percpu_pool_set *pool_set, size_t len);

/*
 * rseq_percpu_pool_set_zmalloc: Allocated zero-initialized memory from a per-cpu pool set.
 *
 * Allocate memory for an item within the pool, and zero-initialize its
 * memory on all CPUs. See rseq_percpu_pool_set_malloc for details.
 *
 * This API is MT-safe.
 */
void __rseq_percpu *rseq_percpu_pool_set_zmalloc(struct rseq_percpu_pool_set *pool_set, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* _RSEQ_PERCPU_ALLOC_H */
