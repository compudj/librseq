// SPDX-License-Identifier: LGPL-2.1-only
/*
 * cpu-op.c
 *
 * Copyright (C) 2017 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; only
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syscall.h>
#include <assert.h>
#include <signal.h>
#include <rseq/cpu-op.h>

#include "do-on-cpu-insn.h"

#define ARRAY_SIZE(arr)	(sizeof(arr) / sizeof((arr)[0]))

#define ACCESS_ONCE(x)		(*(__volatile__  __typeof__(x) *)&(x))
#define WRITE_ONCE(x, v)	__extension__ ({ ACCESS_ONCE(x) = (v); })
#define READ_ONCE(x)		ACCESS_ONCE(x)

int do_on_cpu(struct bpf_insn *bytecode, uint32_t len, int64_t *result,
	      int cpu, int flags)
{
	return syscall(__NR_do_on_cpu, bytecode, len, result, cpu, flags);
}

int cpu_op_available(void)
{
	int rc;

	rc = do_on_cpu(NULL, 0, NULL, 0, DO_ON_CPU_LEN_MAX_FLAG);
	if (rc >= 0)
		return 1;
	return 0;
}

int cpu_op_get_current_cpu(void)
{
	int cpu;

	cpu = sched_getcpu();
	if (cpu < 0) {
		perror("sched_getcpu()");
		abort();
	}
	return cpu;
}

static
int __cpu_op_cmpxchg(void *v, void *expect, void *old, void *n, size_t len,
		     int cpu, int acquire, int release)
{
	int ret;
	unsigned int bpf_size, ldx_mode, stx_mode;
	int64_t expectv, nv, res;

	switch (len) {
	case 1:	bpf_size = BPF_B;
		expectv = *(int8_t *) expect;
		nv = *(int8_t *) n;
		break;
	case 2: bpf_size = BPF_H;
		expectv = *(int16_t *) expect;
		nv = *(int16_t *) n;
		break;
	case 4:	bpf_size = BPF_W;
		expectv = *(int32_t *) expect;
		nv = *(int32_t *) n;
		break;
	case 8:	bpf_size = BPF_DW;
		expectv = *(int64_t *) expect;
		nv = *(int64_t *) n;
		break;
	default:
		return -EINVAL;
	}

	ldx_mode = acquire ? BPF_MEM_ACQ_REL : BPF_MEM;
	stx_mode = release ? BPF_MEM_ACQ_REL : BPF_MEM;

	enum {
		BPF_LABEL_BRANCH1 = 6,
		BPF_LABEL_FAIL = 9,
	};

	{
		struct bpf_insn bytecode[] = {
			[0] = BPFI_LD_IMM64(BPF_REG_1, BPF_PTR_TO_V(v)),
			[2] = BPFI_LDX_MODE(bpf_size, ldx_mode, BPF_REG_0, BPF_REG_1, 0),
			[3] = BPFI_LD_IMM64(BPF_REG_2, expectv),
			[5] = BPFI_JNE_X(BPF_REG_2, BPF_REG_0,
					 BPF_LABEL_FAIL - BPF_LABEL_BRANCH1),

			[BPF_LABEL_BRANCH1] = BPFI_LD_IMM64(BPF_REG_3, nv),
			[8] = BPFI_STX_MODE(bpf_size, stx_mode, BPF_REG_1, BPF_REG_3, 0),
			[BPF_LABEL_FAIL] = BPFI_EXIT(),	/* r0 contains old */
		};

		do {
			ret = do_on_cpu(bytecode, ARRAY_SIZE(bytecode),
					&res, cpu, 0);
		} while (ret == -1 && errno == EAGAIN);
	}

	if (!ret) {
		switch (len) {
		case 1:	*(int8_t *) old = (int8_t) res;
			break;
		case 2:	*(int16_t *) old = (int16_t) res;
			break;
		case 4:	*(int32_t *) old = (int32_t) res;
			break;
		case 8:	*(int64_t *) old = res;
			break;
		default:
			return -EINVAL;
		}
	}

	return ret;
}

int cpu_op_cmpxchg(void *v, void *expect, void *old, void *n, size_t len,
		   int cpu)
{
	return __cpu_op_cmpxchg(v, expect, old, n, len, cpu, 1, 1);
}

int cpu_op_cmpxchg_relaxed(void *v, void *expect, void *old, void *n, size_t len,
			   int cpu)
{
	return __cpu_op_cmpxchg(v, expect, old, n, len, cpu, 0, 0);
}

int cpu_op_cmpxchg_acquire(void *v, void *expect, void *old, void *n, size_t len,
			   int cpu)
{
	return __cpu_op_cmpxchg(v, expect, old, n, len, cpu, 1, 0);
}

int cpu_op_cmpxchg_release(void *v, void *expect, void *old, void *n, size_t len,
			   int cpu)
{
	return __cpu_op_cmpxchg(v, expect, old, n, len, cpu, 0, 1);
}

static
int __cpu_op_add(void *v, int64_t count, size_t len, int cpu,
		 int acquire, int release)
{
	int ret;
	unsigned int bpf_size, ldx_mode, stx_mode;

	switch (len) {
	case 1:	bpf_size = BPF_B;
		break;
	case 2: bpf_size = BPF_H;
		break;
	case 4:	bpf_size = BPF_W;
		break;
	case 8:	bpf_size = BPF_DW;
		break;
	default:
		return -EINVAL;
	}

	ldx_mode = acquire ? BPF_MEM_ACQ_REL : BPF_MEM;
	stx_mode = release ? BPF_MEM_ACQ_REL : BPF_MEM;

	{
		struct bpf_insn bytecode[] = {
			BPFI_LD_IMM64(BPF_REG_1, BPF_PTR_TO_V(v)),
			BPFI_LDX_MODE(bpf_size, ldx_mode, BPF_REG_0, BPF_REG_1, 0),
			BPFI_LD_IMM64(BPF_REG_2, count),
			BPFI_ADD64_X(BPF_REG_0, BPF_REG_2),
			BPFI_STX_MODE(bpf_size, stx_mode, BPF_REG_1, BPF_REG_0, 0),
		};

		do {
			ret = do_on_cpu(bytecode, ARRAY_SIZE(bytecode),
					NULL, cpu, 0);
		} while (ret == -1 && errno == EAGAIN);
	}
	return ret;
}

int cpu_op_add(void *v, int64_t count, size_t len, int cpu)
{
	return __cpu_op_add(v, count, len, cpu, 1, 1);
}

int cpu_op_add_relaxed(void *v, int64_t count, size_t len, int cpu)
{
	return __cpu_op_add(v, count, len, cpu, 0, 0);
}

int cpu_op_add_acquire(void *v, int64_t count, size_t len, int cpu)
{
	return __cpu_op_add(v, count, len, cpu, 1, 0);
}

int cpu_op_add_release(void *v, int64_t count, size_t len, int cpu)
{
	return __cpu_op_add(v, count, len, cpu, 0, 1);
}

int cpu_op_cmpeqv_storev(intptr_t *v, intptr_t expect, intptr_t newv,
			 int cpu)
{
	intptr_t old;
	int ret;

	ret = cpu_op_cmpxchg_relaxed(v, &expect, &old, &newv, sizeof(*v),
				     cpu);
	if (!ret && old != expect)
		ret = 1;
	return ret;
}

int cpu_op_cmpnev_storeoffp_load(intptr_t *v, intptr_t expectnot,
				 off_t voffp, intptr_t *load, int cpu)
{
	int ret;
	int64_t res;
	unsigned int bpf_size1;
	size_t len1 = sizeof(*v);

	switch (len1) {
	case 1:	bpf_size1 = BPF_B;
		break;
	case 2: bpf_size1 = BPF_H;
		break;
	case 4:	bpf_size1 = BPF_W;
		break;
	case 8:	bpf_size1 = BPF_DW;
		break;
	default:
		return -EINVAL;
	}

	enum {
		BPF_LABEL_BRANCH1 = 6,
		BPF_LABEL_FAIL = 16,
	};

	{
		struct bpf_insn bytecode[] = {
			[0] = BPFI_LD_IMM64(BPF_REG_1, BPF_PTR_TO_V(v)),
			[2] = BPFI_LDX(bpf_size1, BPF_REG_2, BPF_REG_1, 0),
			[3] = BPFI_LD_IMM64(BPF_REG_3, expectnot),
			[5] = BPFI_JEQ_X(BPF_REG_2, BPF_REG_3,
					 BPF_LABEL_FAIL - BPF_LABEL_BRANCH1),

			[BPF_LABEL_BRANCH1] = BPFI_LD_IMM64(BPF_REG_3, BPF_PTR_TO_V(load)),
			[8] = BPFI_STX(bpf_size1, BPF_REG_3, BPF_REG_2, 0),

			[9] = BPFI_MOV_X(BPF_REG_3, BPF_REG_2),
			[10] = BPFI_LD_IMM64(BPF_REG_4, voffp),
			[12] = BPFI_ADD64_X(BPF_REG_3, BPF_REG_4),
			[13] = BPFI_LDX(bpf_size1, BPF_REG_3, BPF_REG_3, 0),
			[14] = BPFI_STX(bpf_size1, BPF_REG_1, BPF_REG_3, 0),
			[15] = BPFI_EXIT(),	/* r0 = 0. */
			[BPF_LABEL_FAIL] = BPFI_LD_IMM32(BPF_REG_0, 1),
			[17] = BPFI_EXIT(),	/* r0 = 1. */
		};

		do {
			ret = do_on_cpu(bytecode, ARRAY_SIZE(bytecode),
					&res, cpu, 0);
		} while (ret == -1 && errno == EAGAIN);
	}
	if (!ret)
		ret = (int) !!res;
	return ret;
}

static
int __cpu_op_cmpeqv_storev_storev(intptr_t *v, intptr_t expect,
				  intptr_t *v2, intptr_t newv2,
				  intptr_t newv, int cpu, int release)
{
	int ret;
	int64_t res;
	unsigned int bpf_size1, bpf_size2, stx_mode;
	size_t len1 = sizeof(*v);
	size_t len2 = sizeof(*v2);

	switch (len1) {
	case 1:	bpf_size1 = BPF_B;
		break;
	case 2: bpf_size1 = BPF_H;
		break;
	case 4:	bpf_size1 = BPF_W;
		break;
	case 8:	bpf_size1 = BPF_DW;
		break;
	default:
		return -EINVAL;
	}

	switch (len2) {
	case 1:	bpf_size2 = BPF_B;
		break;
	case 2: bpf_size2 = BPF_H;
		break;
	case 4:	bpf_size2 = BPF_W;
		break;
	case 8:	bpf_size2 = BPF_DW;
		break;
	default:
		return -EINVAL;
	}

	stx_mode = release ? BPF_MEM_ACQ_REL : BPF_MEM;

	enum {
		BPF_LABEL_BRANCH1 = 7,
		BPF_LABEL_FAIL = 16,
	};

	{
		struct bpf_insn bytecode[] = {
			[0] = BPFI_LD_IMM64(BPF_REG_1, BPF_PTR_TO_V(v)),
			[2] = BPFI_LDX(bpf_size1, BPF_REG_2, BPF_REG_1, 0),
			[3] = BPFI_LD_IMM64(BPF_REG_3, BPF_PTR_TO_V(&expect)),
			[5] = BPFI_LDX(bpf_size1, BPF_REG_3, BPF_REG_3, 0),
			[6] = BPFI_JNE_X(BPF_REG_2, BPF_REG_3,
					 BPF_LABEL_FAIL - BPF_LABEL_BRANCH1),

			[BPF_LABEL_BRANCH1] = BPFI_LD_IMM64(BPF_REG_2, BPF_PTR_TO_V(v2)),
			[9] = BPFI_LD_IMM64(BPF_REG_3, newv2),
			[11] = BPFI_LD_IMM64(BPF_REG_4, newv),
			[13] = BPFI_STX(bpf_size2, BPF_REG_2, BPF_REG_3, 0),
			[14] = BPFI_STX_MODE(bpf_size2, stx_mode, BPF_REG_1, BPF_REG_4, 0),
			[15] = BPFI_EXIT(),	/* r0 = 0. */
			[BPF_LABEL_FAIL] = BPFI_LD_IMM32(BPF_REG_0, 1),
			[17] = BPFI_EXIT(),	/* r0 = 1. */
		};

		do {
			ret = do_on_cpu(bytecode, ARRAY_SIZE(bytecode),
					&res, cpu, 0);
		} while (ret == -1 && errno == EAGAIN);
	}
	if (!ret)
		ret = (int) !!res;
	return ret;
}

int cpu_op_cmpeqv_storev_storev(intptr_t *v, intptr_t expect,
				intptr_t *v2, intptr_t newv2,
				intptr_t newv, int cpu)
{
	return __cpu_op_cmpeqv_storev_storev(v, expect, v2, newv2,
					     newv, cpu, 0);
}

int cpu_op_cmpeqv_storev_storev_release(intptr_t *v, intptr_t expect,
				intptr_t *v2, intptr_t newv2,
				intptr_t newv, int cpu)
{
	return __cpu_op_cmpeqv_storev_storev(v, expect, v2, newv2,
					     newv, cpu, 1);
}

static
int __cpu_op_cmpeqv_cmpeqv_storev(intptr_t *v, intptr_t expect,
				intptr_t *v2, intptr_t expect2,
				intptr_t newv, int cpu, int release)
{
	int ret;
	int64_t res;
	unsigned int bpf_size1, bpf_size2, stx_mode;
	size_t len1 = sizeof(*v);
	size_t len2 = sizeof(*v2);

	switch (len1) {
	case 1:	bpf_size1 = BPF_B;
		break;
	case 2: bpf_size1 = BPF_H;
		break;
	case 4:	bpf_size1 = BPF_W;
		break;
	case 8:	bpf_size1 = BPF_DW;
		break;
	default:
		return -EINVAL;
	}

	switch (len2) {
	case 1:	bpf_size2 = BPF_B;
		break;
	case 2: bpf_size2 = BPF_H;
		break;
	case 4:	bpf_size2 = BPF_W;
		break;
	case 8:	bpf_size2 = BPF_DW;
		break;
	default:
		return -EINVAL;
	}

	stx_mode = release ? BPF_MEM_ACQ_REL : BPF_MEM;

	enum {
		BPF_LABEL_BRANCH1 = 6,
		BPF_LABEL_BRANCH2 = 12,
		BPF_LABEL_FAIL = 16,
	};

	{
		struct bpf_insn bytecode[] = {
			[0] = BPFI_LD_IMM64(BPF_REG_1, BPF_PTR_TO_V(v)),
			[2] = BPFI_LDX(bpf_size1, BPF_REG_2, BPF_REG_1, 0),
			[3] = BPFI_LD_IMM64(BPF_REG_3, expect),
			[5] = BPFI_JNE_X(BPF_REG_2, BPF_REG_3,
					 BPF_LABEL_FAIL - BPF_LABEL_BRANCH1),

			[BPF_LABEL_BRANCH1] = BPFI_LD_IMM64(BPF_REG_2, BPF_PTR_TO_V(v2)),
			[8] = BPFI_LDX(bpf_size1, BPF_REG_2, BPF_REG_2, 0),
			[9] = BPFI_LD_IMM64(BPF_REG_3, expect2),
			[11] = BPFI_JNE_X(BPF_REG_2, BPF_REG_3,
					  BPF_LABEL_FAIL - BPF_LABEL_BRANCH2),

			[BPF_LABEL_BRANCH2] = BPFI_LD_IMM64(BPF_REG_2, newv),
			[14] = BPFI_STX_MODE(bpf_size2, stx_mode, BPF_REG_1, BPF_REG_2, 0),
			[15] = BPFI_EXIT(),	/* r0 = 0. */
			[BPF_LABEL_FAIL] = BPFI_LD_IMM32(BPF_REG_0, 1),
			[17] = BPFI_EXIT(),	/* r0 = 1. */
		};

		do {
			ret = do_on_cpu(bytecode, ARRAY_SIZE(bytecode),
					&res, cpu, 0);
		} while (ret == -1 && errno == EAGAIN);
	}
	if (!ret)
		ret = (int) !!res;
	return ret;

}

int cpu_op_cmpeqv_cmpeqv_storev(intptr_t *v, intptr_t expect,
				intptr_t *v2, intptr_t expect2,
				intptr_t newv, int cpu)
{
	return __cpu_op_cmpeqv_cmpeqv_storev(v, expect, v2, expect2,
					     newv, cpu, 0);
}

int cpu_op_cmpeqv_cmpeqv_storev_release(intptr_t *v, intptr_t expect,
					intptr_t *v2, intptr_t expect2,
					intptr_t newv, int cpu)
{
	return __cpu_op_cmpeqv_cmpeqv_storev(v, expect, v2, expect2,
					     newv, cpu, 1);
}

static
int __cpu_op_cmpeqv_memcpy_storev(intptr_t *v, intptr_t expect,
				  void *dst, void *src, size_t len,
				  intptr_t newv, int cpu, int release)
{
	int ret;
	int64_t res;
	unsigned int bpf_size2, stx_mode;
	unsigned int len2 = sizeof(*v);

	switch (len2) {
	case 1:	bpf_size2 = BPF_B;
		break;
	case 2: bpf_size2 = BPF_H;
		break;
	case 4:	bpf_size2 = BPF_W;
		break;
	case 8:	bpf_size2 = BPF_DW;
		break;
	default:
		return -EINVAL;
	}

	stx_mode = release ? BPF_MEM_ACQ_REL : BPF_MEM;

	enum {
		BPF_LABEL_BRANCH_TEST = 6,
		BPF_LABEL_LOOP8 = 14,
		BPF_LABEL_BRANCH8_1 = 15,
		BPF_LABEL_LOOP1 = 20,
		BPF_LABEL_BRANCH1_1 = 21,
		BPF_LABEL_BRANCH1_2 = 26,
		BPF_LABEL_FAIL = 30,
	};

	{
		struct bpf_insn bytecode[] = {
			/*
			 * r0 is 0
			 * r1 is temporary register,
			 * r2 is expect
			 * r6 is v
			 */
			[0] = BPFI_LD_IMM64(BPF_REG_6, BPF_PTR_TO_V(v)),
			[2] = BPFI_LDX(bpf_size2, BPF_REG_1, BPF_REG_6, 0),
			[3] = BPFI_LD_IMM64(BPF_REG_2, expect),
			[5] = BPFI_JNE_X(BPF_REG_1, BPF_REG_2,
					 BPF_LABEL_FAIL - BPF_LABEL_BRANCH_TEST),

			/*
			 * r0 is 0
			 * r1 is temporary register,
			 * r2 is dst iterator,
			 * r3 is src iterator,
			 * r4 is src + (len & ~7)	// end of 8-byte copy
			 * r5 is src + len		// end of 1-byte copy
			 * r6 is v
			 */
			[BPF_LABEL_BRANCH_TEST] = BPFI_LD_IMM64(BPF_REG_2,
								BPF_PTR_TO_V(dst)),
			[8] = BPFI_LD_IMM64(BPF_REG_3, BPF_PTR_TO_V(src)),
			[10] = BPFI_LD_IMM64(BPF_REG_4, BPF_PTR_TO_V(src) + (len & ~7)),
			[12] = BPFI_LD_IMM64(BPF_REG_5, BPF_PTR_TO_V(src) + len),

			/* 8-byte copy loop target. */
			[BPF_LABEL_LOOP8] = BPFI_JEQ_X(BPF_REG_3, BPF_REG_4,
						       BPF_LABEL_LOOP1 - BPF_LABEL_BRANCH8_1),

			[BPF_LABEL_BRANCH8_1] = BPFI_LDX(BPF_DW, BPF_REG_1, BPF_REG_3, 0),
			[16] = BPFI_STX(BPF_DW, BPF_REG_2, BPF_REG_1, 0),

			[17] = BPFI_ADD64_K(BPF_REG_2, 8),
			[18] = BPFI_ADD64_K(BPF_REG_3, 8),
			[19] = BPFI_JA_K(BPF_LABEL_LOOP8 - BPF_LABEL_LOOP1),

			/* 1-byte copy loop target. */
			[BPF_LABEL_LOOP1] = BPFI_JEQ_X(BPF_REG_3, BPF_REG_5,
						       BPF_LABEL_BRANCH1_2 - BPF_LABEL_BRANCH1_1),

			[BPF_LABEL_BRANCH1_1] = BPFI_LDX(BPF_B, BPF_REG_1, BPF_REG_3, 0),
			[22] = BPFI_STX(BPF_B, BPF_REG_2, BPF_REG_1, 0),

			[23] = BPFI_ADD64_K(BPF_REG_2, 1),
			[24] = BPFI_ADD64_K(BPF_REG_3, 1),
			[25] = BPFI_JA_K(BPF_LABEL_LOOP1 - BPF_LABEL_BRANCH1_2),

			/* Completed, do store. */

			/*
			 * r0 is 0
			 * r2 is newv
			 * r6 is v
			 */
			[BPF_LABEL_BRANCH1_2] = BPFI_LD_IMM64(BPF_REG_2, newv),
			[28] = BPFI_STX_MODE(bpf_size2, stx_mode, BPF_REG_6,
					     BPF_REG_2, 0),

			[29] = BPFI_EXIT(),	/* r0 = 0. */
			[BPF_LABEL_FAIL] = BPFI_LD_IMM32(BPF_REG_0, 1),
			[31] = BPFI_EXIT(),	/* r0 = 1. */
		};

		do {
			ret = do_on_cpu(bytecode, ARRAY_SIZE(bytecode),
					&res, cpu, 0);
		} while (ret == -1 && errno == EAGAIN);
	}
	if (!ret)
		ret = (int) !!res;
	return ret;
}

int cpu_op_cmpeqv_memcpy_storev(intptr_t *v, intptr_t expect,
				  void *dst, void *src, size_t len,
				  intptr_t newv, int cpu)
{
	return __cpu_op_cmpeqv_memcpy_storev(v, expect, dst, src, len,
					     newv, cpu, 0);
}

int cpu_op_cmpeqv_memcpy_storev_release(intptr_t *v, intptr_t expect,
					void *dst, void *src, size_t len,
					intptr_t newv, int cpu)
{
	return __cpu_op_cmpeqv_memcpy_storev(v, expect, dst, src, len,
					     newv, cpu, 1);
}

int cpu_op_addv(intptr_t *v, int64_t count, int cpu)
{
	return cpu_op_add_relaxed(v, count, sizeof(intptr_t), cpu);
}

int cpu_op_deref_loadoffp(intptr_t *p, off_t voffp, intptr_t *load, int cpu)
{
	int ret;
	int64_t res;
	unsigned int bpf_size1, bpf_size2;
	size_t len1 = sizeof(void *), len2 = sizeof(*load);

	switch (len1) {
	case 1:	bpf_size1 = BPF_B;
		break;
	case 2: bpf_size1 = BPF_H;
		break;
	case 4:	bpf_size1 = BPF_W;
		break;
	case 8:	bpf_size1 = BPF_DW;
		break;
	default:
		return -EINVAL;
	}

	switch (len2) {
	case 1:	bpf_size2 = BPF_B;
		break;
	case 2: bpf_size2 = BPF_H;
		break;
	case 4:	bpf_size2 = BPF_W;
		break;
	case 8:	bpf_size2 = BPF_DW;
		break;
	default:
		return -EINVAL;
	}

	{
		struct bpf_insn bytecode[] = {
			[0] = BPFI_LD_IMM64(BPF_REG_1, BPF_PTR_TO_V(p)),
			[2] = BPFI_LDX(bpf_size1, BPF_REG_1, BPF_REG_1, 0),
			[3] = BPFI_LD_IMM64(BPF_REG_2, voffp),
			[5] = BPFI_ADD64_X(BPF_REG_1, BPF_REG_2),
			[6] = BPFI_LDX(bpf_size2, BPF_REG_0, BPF_REG_1, 0),
		};

		do {
			ret = do_on_cpu(bytecode, ARRAY_SIZE(bytecode),
					&res, cpu, 0);
		} while (ret == -1 && errno == EAGAIN);
	}
	if (!ret)
		*load = (intptr_t) res;
	return ret;
}

int cpu_op_fence(int cpu)
{
	int ret;

	do {
		ret = do_on_cpu(NULL, 0, NULL, cpu, 0);
	} while (ret == -1 && errno == EAGAIN);
	return ret;
}
