/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: 2024 Mathieu Desnoyers <mathieu.desnoyers@efficios.com> */

#ifndef _RSEQ_PERCPU_ALLOC_H
#define _RSEQ_PERCPU_ALLOC_H

#include <stddef.h>
#include <sys/types.h>
#include <sys/mman.h>

/*
 * rseq/percpu-alloc.h
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
 * with __rseq_percpu for use by static analyzers.
 */
#define __rseq_percpu

struct rseq_percpu_pool;

struct rseq_percpu_pool *rseq_percpu_pool_create(size_t item_len,
		size_t percpu_len, int max_nr_cpus,
		int mmap_prot, int mmap_flags, int mmap_fd, off_t mmap_offset,
		int numa_flags);
int rseq_percpu_pool_destroy(struct rseq_percpu_pool *pool);

void __rseq_percpu *rseq_percpu_malloc(struct rseq_percpu_pool *pool);
void __rseq_percpu *rseq_percpu_zmalloc(struct rseq_percpu_pool *pool);
void rseq_percpu_free(void __rseq_percpu *ptr);

void *__rseq_percpu_ptr(void __rseq_percpu *ptr, int cpu);

#define rseq_percpu_ptr(ptr, cpu)	((__typeof__(*(ptr)) *) __rseq_percpu_ptr(ptr, cpu))

struct rseq_percpu_pool_set *rseq_percpu_pool_set_create(void);
int rseq_percpu_pool_set_destroy(struct rseq_percpu_pool_set *pool_set);
int rseq_percpu_pool_set_add_pool(struct rseq_percpu_pool_set *pool_set,
		struct rseq_percpu_pool *pool);

void __rseq_percpu *rseq_percpu_pool_set_malloc(struct rseq_percpu_pool_set *pool_set, size_t len);
void __rseq_percpu *rseq_percpu_pool_set_zmalloc(struct rseq_percpu_pool_set *pool_set, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* _RSEQ_PERCPU_ALLOC_H */
