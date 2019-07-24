/* SPDX-License-Identifier: LGPL-2.1 OR MIT */
/*
 * cpu-op.h
 *
 * (C) Copyright 2017-2018 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef RSEQ_CPU_OP_H
#define RSEQ_CPU_OP_H

#include <stdlib.h>
#include <stdint.h>
#include <linux/do_on_cpu.h>
#include <linux/bpf.h>

int do_on_cpu(struct bpf_insn *bytecode, uint32_t len, int64_t *result,
	      int cpu, int flags);
int cpu_op_get_current_cpu(void);
int cpu_op_available(void);

int cpu_op_cmpxchg(void *v, void *expect, void *old, void *_new, size_t len,
		   int cpu);
int cpu_op_cmpxchg_relaxed(void *v, void *expect, void *old, void *_new, size_t len,
			   int cpu);
int cpu_op_cmpxchg_acquire(void *v, void *expect, void *old, void *_new, size_t len,
			   int cpu);
int cpu_op_cmpxchg_release(void *v, void *expect, void *old, void *_new, size_t len,
			   int cpu);

int cpu_op_add(void *v, int64_t count, size_t len, int cpu);
int cpu_op_add_relaxed(void *v, int64_t count, size_t len, int cpu);
int cpu_op_add_acquire(void *v, int64_t count, size_t len, int cpu);
int cpu_op_add_release(void *v, int64_t count, size_t len, int cpu);

int cpu_op_cmpeqv_storev(intptr_t *v, intptr_t expect, intptr_t newv, int cpu);
int cpu_op_cmpnev_storeoffp_load(intptr_t *v, intptr_t expectnot,
				 off_t voffp, intptr_t *load, int cpu);
int cpu_op_cmpeqv_storev_storev(intptr_t *v, intptr_t expect,
				intptr_t *v2, intptr_t newv2,
				intptr_t newv, int cpu);
int cpu_op_cmpeqv_storev_storev_release(intptr_t *v, intptr_t expect,
				   intptr_t *v2, intptr_t newv2,
				   intptr_t newv, int cpu);
int cpu_op_cmpeqv_cmpeqv_storev(intptr_t *v, intptr_t expect,
				intptr_t *v2, intptr_t expect2,
				intptr_t newv, int cpu);
int cpu_op_cmpeqv_cmpeqv_storev_release(intptr_t *v, intptr_t expect,
					intptr_t *v2, intptr_t expect2,
					intptr_t newv, int cpu);
int cpu_op_cmpeqv_memcpy_storev(intptr_t *v, intptr_t expect,
				void *dst, void *src, size_t len,
				intptr_t newv, int cpu);
int cpu_op_cmpeqv_memcpy_storev_release(intptr_t *v, intptr_t expect,
				   void *dst, void *src, size_t len,
				   intptr_t newv, int cpu);
int cpu_op_addv(intptr_t *v, int64_t count, int cpu);
int cpu_op_deref_loadoffp(intptr_t *p, off_t voffp, intptr_t *load, int cpu);
int cpu_op_fence(int cpu);

#endif  /* RSEQ_CPU_OP_H_ */
