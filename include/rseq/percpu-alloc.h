/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: 2024 Mathieu Desnoyers <mathieu.desnoyers@efficios.com> */

#ifndef _RSEQ_PERCPU_ALLOC_H
#define _RSEQ_PERCPU_ALLOC_H

#include <stddef.h>
#include <sys/types.h>

/*
 * rseq/percpu-alloc.h
 */

struct rseq_percpu_pool;

struct rseq_percpu_pool *rseq_percpu_pool_create(size_t item_len,
		size_t percpu_len, int max_nr_cpus,
		int prot, int flags, int fd, off_t offset);
int rseq_percpu_pool_destroy(struct rseq_percpu_pool *pool);

void *rseq_percpu_malloc(struct rseq_percpu_pool *pool);
void *rseq_percpu_zmalloc(struct rseq_percpu_pool *pool);
void rseq_percpu_free(void *ptr);

void *__rseq_percpu_ptr(void *ptr, int cpu);

#define rseq_percpu_ptr(ptr, cpu)	((__typeof__(ptr)) __rseq_percpu_ptr(ptr, cpu))

struct rseq_percpu_pool_set *rseq_percpu_pool_set_create(void);
int rseq_percpu_pool_set_destroy(struct rseq_percpu_pool_set *pool_set);
int rseq_percpu_pool_set_add_pool(struct rseq_percpu_pool_set *pool_set,
		struct rseq_percpu_pool *pool);

void *rseq_percpu_pool_set_malloc(struct rseq_percpu_pool_set *pool_set, size_t len);
void *rseq_percpu_pool_set_zmalloc(struct rseq_percpu_pool_set *pool_set, size_t len);

#endif /* _RSEQ_PERCPU_ALLOC_H */
