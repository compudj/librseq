/* SPDX-License-Identifier: LGPL-2.1 OR MIT */
/*
 * percpu-op.h
 *
 * (C) Copyright 2017-2018 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef RSEQ_PERCPU_OP_H
#define RSEQ_PERCPU_OP_H

#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <stdlib.h>
#include <rseq/rseq.h>
#include <rseq/cpu-op.h>

static inline uint32_t percpu_current_cpu(void)
{
	return rseq_current_cpu();
}

static inline __attribute__((always_inline))
int percpu_cmpeqv_storev(intptr_t *v, intptr_t expect, intptr_t newv,
			 int cpu)
{
	int ret;

	ret = rseq_cmpeqv_storev(v, expect, newv, cpu);
	if (rseq_unlikely(ret)) {
		if (ret > 0)
			return ret;
		return cpu_op_cmpeqv_storev(v, expect, newv, cpu);
	}
	return 0;
}

static inline __attribute__((always_inline))
int percpu_cmpnev_storeoffp_load(intptr_t *v, intptr_t expectnot,
			       off_t voffp, intptr_t *load, int cpu)
{
	int ret;

	ret = rseq_cmpnev_storeoffp_load(v, expectnot, voffp, load, cpu);
	if (rseq_unlikely(ret)) {
		if (ret > 0)
			return ret;
		return cpu_op_cmpnev_storeoffp_load(v, expectnot, voffp,
						    load, cpu);
	}
	return 0;
}

static inline __attribute__((always_inline))
int percpu_addv(intptr_t *v, intptr_t count, int cpu)
{
	if (rseq_unlikely(rseq_addv(v, count, cpu)))
		return cpu_op_addv(v, count, cpu);
	return 0;
}

static inline __attribute__((always_inline))
int percpu_cmpeqv_storev_storev(intptr_t *v, intptr_t expect,
				intptr_t *v2, intptr_t newv2,
				intptr_t newv, int cpu)
{
	int ret;

	ret = rseq_cmpeqv_trystorev_storev(v, expect, v2, newv2,
					   newv, cpu);
	if (rseq_unlikely(ret)) {
		if (ret > 0)
			return ret;
		return cpu_op_cmpeqv_storev_storev(v, expect, v2, newv2,
						   newv, cpu);
	}
	return 0;
}

static inline __attribute__((always_inline))
int percpu_cmpeqv_storev_storev_release(intptr_t *v, intptr_t expect,
					intptr_t *v2, intptr_t newv2,
					intptr_t newv, int cpu)
{
	int ret;

	ret = rseq_cmpeqv_trystorev_storev_release(v, expect, v2, newv2,
						   newv, cpu);
	if (rseq_unlikely(ret)) {
		if (ret > 0)
			return ret;
		return cpu_op_cmpeqv_storev_storev_release(v, expect, v2, newv2,
							   newv, cpu);
	}
	return 0;
}

static inline __attribute__((always_inline))
int percpu_cmpeqv_cmpeqv_storev(intptr_t *v, intptr_t expect,
				intptr_t *v2, intptr_t expect2,
				intptr_t newv, int cpu)
{
	int ret;

	ret = rseq_cmpeqv_cmpeqv_storev(v, expect, v2, expect2, newv, cpu);
	if (rseq_unlikely(ret)) {
		if (ret > 0)
			return ret;
		return cpu_op_cmpeqv_cmpeqv_storev(v, expect, v2, expect2,
						   newv, cpu);
	}
	return 0;
}

static inline __attribute__((always_inline))
int percpu_cmpeqv_memcpy_storev(intptr_t *v, intptr_t expect,
				void *dst, void *src, size_t len,
				intptr_t newv, int cpu)
{
	int ret;

	ret = rseq_cmpeqv_trymemcpy_storev(v, expect, dst, src, len,
					   newv, cpu);
	if (rseq_unlikely(ret)) {
		if (ret > 0)
			return ret;
		return cpu_op_cmpeqv_memcpy_storev(v, expect, dst, src, len,
						   newv, cpu);
	}
	return 0;
}

static inline __attribute__((always_inline))
int percpu_cmpeqv_memcpy_storev_release(intptr_t *v, intptr_t expect,
					void *dst, void *src, size_t len,
					intptr_t newv, int cpu)
{
	int ret;

	ret = rseq_cmpeqv_trymemcpy_storev_release(v, expect, dst, src, len,
						   newv, cpu);
	if (rseq_unlikely(ret)) {
		if (ret > 0)
			return ret;
		return cpu_op_cmpeqv_memcpy_storev_release(v, expect, dst, src,
							   len, newv, cpu);
	}
	return 0;
}

static inline __attribute__((always_inline))
int percpu_deref_loadoffp(intptr_t *p, off_t voffp, intptr_t *load, int cpu)
{
	int ret;

	ret = rseq_deref_loadoffp(p, voffp, load, cpu);
	if (rseq_unlikely(ret)) {
		if (ret > 0)
			return ret;
		return cpu_op_deref_loadoffp(p, voffp, load, cpu);
	}
	return 0;
}

#endif  /* RSEQ_PERCPU_OP_H_ */
