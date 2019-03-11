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

#define _GNU_SOURCE
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

#define ARRAY_SIZE(arr)	(sizeof(arr) / sizeof((arr)[0]))

#define ACCESS_ONCE(x)		(*(__volatile__  __typeof__(x) *)&(x))
#define WRITE_ONCE(x, v)	__extension__ ({ ACCESS_ONCE(x) = (v); })
#define READ_ONCE(x)		ACCESS_ONCE(x)

int cpu_opv(struct cpu_op *cpu_opv, int cpuopcnt, int cpu, int flags)
{
	return syscall(__NR_cpu_opv, cpu_opv, cpuopcnt, cpu, flags);
}

int cpu_op_available(void)
{
	int rc;

	rc = cpu_opv(NULL, 0, 0, CPU_OP_NR_FLAG);
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

int cpu_op_cmpxchg(void *v, void *expect, void *old, void *n, size_t len,
		   int cpu)
{
	struct cpu_op opvec[] = {
		[0] = {
			.op = CPU_MEMCPY_OP,
			.len = len,
			.u.memcpy_op.dst = (unsigned long)old,
			.u.memcpy_op.src = (unsigned long)v,
			.u.memcpy_op.expect_fault_dst = 0,
			.u.memcpy_op.expect_fault_src = 0,
		},
		[1] = {
			.op = CPU_COMPARE_EQ_OP,
			.len = len,
			.u.compare_op.a = (unsigned long)v,
			.u.compare_op.b = (unsigned long)expect,
			.u.compare_op.expect_fault_a = 0,
			.u.compare_op.expect_fault_b = 0,
		},
		[2] = {
			.op = CPU_MEMCPY_OP,
			.len = len,
			.u.memcpy_op.dst = (unsigned long)v,
			.u.memcpy_op.src = (unsigned long)n,
			.u.memcpy_op.expect_fault_dst = 0,
			.u.memcpy_op.expect_fault_src = 0,
		},
	};

	return cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
}

int cpu_op_add(void *v, int64_t count, size_t len, int cpu)
{
	struct cpu_op opvec[] = {
		[0] = {
			.op = CPU_ADD_OP,
			.len = len,
			.u.arithmetic_op.p = (unsigned long)v,
			.u.arithmetic_op.count = count,
			.u.arithmetic_op.expect_fault_p = 0,
		},
	};

	return cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
}

int cpu_op_cmpeqv_storev(intptr_t *v, intptr_t expect, intptr_t newv,
			 int cpu)
{
	struct cpu_op opvec[] = {
		[0] = {
			.op = CPU_COMPARE_EQ_OP,
			.len = sizeof(intptr_t),
			.u.compare_op.a = (unsigned long)v,
			.u.compare_op.b = (unsigned long)&expect,
			.u.compare_op.expect_fault_a = 0,
			.u.compare_op.expect_fault_b = 0,
		},
		[1] = {
			.op = CPU_MEMCPY_OP,
			.len = sizeof(intptr_t),
			.u.memcpy_op.dst = (unsigned long)v,
			.u.memcpy_op.src = (unsigned long)&newv,
			.u.memcpy_op.expect_fault_dst = 0,
			.u.memcpy_op.expect_fault_src = 0,
		},
	};

	return cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
}

static int cpu_op_cmpeqv_storep_expect_fault(intptr_t *v, intptr_t expect,
					     intptr_t *newp, int cpu)
{
	struct cpu_op opvec[] = {
		[0] = {
			.op = CPU_COMPARE_EQ_OP,
			.len = sizeof(intptr_t),
			.u.compare_op.a = (unsigned long)v,
			.u.compare_op.b = (unsigned long)&expect,
			.u.compare_op.expect_fault_a = 0,
			.u.compare_op.expect_fault_b = 0,
		},
		[1] = {
			.op = CPU_MEMCPY_OP,
			.len = sizeof(intptr_t),
			.u.memcpy_op.dst = (unsigned long)v,
			.u.memcpy_op.src = (unsigned long)newp,
			.u.memcpy_op.expect_fault_dst = 0,
			/* Return EAGAIN on src fault. */
			.u.memcpy_op.expect_fault_src = 1,
		},
	};

	return cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
}

int cpu_op_cmpnev_storeoffp_load(intptr_t *v, intptr_t expectnot,
				 off_t voffp, intptr_t *load, int cpu)
{
	int ret;

	do {
		intptr_t oldv = READ_ONCE(*v);
		intptr_t *newp = (intptr_t *)(oldv + voffp);

		if (oldv == expectnot)
			return 1;
		ret = cpu_op_cmpeqv_storep_expect_fault(v, oldv, newp, cpu);
		if (!ret) {
			*load = oldv;
			return 0;
		}
	} while (ret > 0);

	return -1;
}

int cpu_op_cmpeqv_storev_storev(intptr_t *v, intptr_t expect,
				intptr_t *v2, intptr_t newv2,
				intptr_t newv, int cpu)
{
	struct cpu_op opvec[] = {
		[0] = {
			.op = CPU_COMPARE_EQ_OP,
			.len = sizeof(intptr_t),
			.u.compare_op.a = (unsigned long)v,
			.u.compare_op.b = (unsigned long)&expect,
			.u.compare_op.expect_fault_a = 0,
			.u.compare_op.expect_fault_b = 0,
		},
		[1] = {
			.op = CPU_MEMCPY_OP,
			.len = sizeof(intptr_t),
			.u.memcpy_op.dst = (unsigned long)v2,
			.u.memcpy_op.src = (unsigned long)&newv2,
			.u.memcpy_op.expect_fault_dst = 0,
			.u.memcpy_op.expect_fault_src = 0,
		},
		[2] = {
			.op = CPU_MEMCPY_OP,
			.len = sizeof(intptr_t),
			.u.memcpy_op.dst = (unsigned long)v,
			.u.memcpy_op.src = (unsigned long)&newv,
			.u.memcpy_op.expect_fault_dst = 0,
			.u.memcpy_op.expect_fault_src = 0,
		},
	};

	return cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
}

int cpu_op_cmpeqv_storev_mb_storev(intptr_t *v, intptr_t expect,
				   intptr_t *v2, intptr_t newv2,
				   intptr_t newv, int cpu)
{
	struct cpu_op opvec[] = {
		[0] = {
			.op = CPU_COMPARE_EQ_OP,
			.len = sizeof(intptr_t),
			.u.compare_op.a = (unsigned long)v,
			.u.compare_op.b = (unsigned long)&expect,
			.u.compare_op.expect_fault_a = 0,
			.u.compare_op.expect_fault_b = 0,
		},
		[1] = {
			.op = CPU_MEMCPY_OP,
			.len = sizeof(intptr_t),
			.u.memcpy_op.dst = (unsigned long)v2,
			.u.memcpy_op.src = (unsigned long)&newv2,
			.u.memcpy_op.expect_fault_dst = 0,
			.u.memcpy_op.expect_fault_src = 0,
		},
		[2] = {
			.op = CPU_MEMCPY_RELEASE_OP,
			.len = sizeof(intptr_t),
			.u.memcpy_op.dst = (unsigned long)v,
			.u.memcpy_op.src = (unsigned long)&newv,
			.u.memcpy_op.expect_fault_dst = 0,
			.u.memcpy_op.expect_fault_src = 0,
		},
	};

	return cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
}

int cpu_op_cmpeqv_cmpeqv_storev(intptr_t *v, intptr_t expect,
				intptr_t *v2, intptr_t expect2,
				intptr_t newv, int cpu)
{
	struct cpu_op opvec[] = {
		[0] = {
			.op = CPU_COMPARE_EQ_OP,
			.len = sizeof(intptr_t),
			.u.compare_op.a = (unsigned long)v,
			.u.compare_op.b = (unsigned long)&expect,
			.u.compare_op.expect_fault_a = 0,
			.u.compare_op.expect_fault_b = 0,
		},
		[1] = {
			.op = CPU_COMPARE_EQ_OP,
			.len = sizeof(intptr_t),
			.u.compare_op.a = (unsigned long)v2,
			.u.compare_op.b = (unsigned long)&expect2,
			.u.compare_op.expect_fault_a = 0,
			.u.compare_op.expect_fault_b = 0,
		},
		[2] = {
			.op = CPU_MEMCPY_OP,
			.len = sizeof(intptr_t),
			.u.memcpy_op.dst = (unsigned long)v,
			.u.memcpy_op.src = (unsigned long)&newv,
			.u.memcpy_op.expect_fault_dst = 0,
			.u.memcpy_op.expect_fault_src = 0,
		},
	};

	return cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
}

int cpu_op_cmpeqv_memcpy_storev(intptr_t *v, intptr_t expect,
				void *dst, void *src, size_t len,
				intptr_t newv, int cpu)
{
	struct cpu_op opvec[] = {
		[0] = {
			.op = CPU_COMPARE_EQ_OP,
			.len = sizeof(intptr_t),
			.u.compare_op.a = (unsigned long)v,
			.u.compare_op.b = (unsigned long)&expect,
			.u.compare_op.expect_fault_a = 0,
			.u.compare_op.expect_fault_b = 0,
		},
		[1] = {
			.op = CPU_MEMCPY_OP,
			.len = len,
			.u.memcpy_op.dst = (unsigned long)dst,
			.u.memcpy_op.src = (unsigned long)src,
			.u.memcpy_op.expect_fault_dst = 0,
			.u.memcpy_op.expect_fault_src = 0,
		},
		[2] = {
			.op = CPU_MEMCPY_OP,
			.len = sizeof(intptr_t),
			.u.memcpy_op.dst = (unsigned long)v,
			.u.memcpy_op.src = (unsigned long)&newv,
			.u.memcpy_op.expect_fault_dst = 0,
			.u.memcpy_op.expect_fault_src = 0,
		},
	};

	return cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
}

int cpu_op_cmpeqv_memcpy_mb_storev(intptr_t *v, intptr_t expect,
				   void *dst, void *src, size_t len,
				   intptr_t newv, int cpu)
{
	struct cpu_op opvec[] = {
		[0] = {
			.op = CPU_COMPARE_EQ_OP,
			.len = sizeof(intptr_t),
			.u.compare_op.a = (unsigned long)v,
			.u.compare_op.b = (unsigned long)&expect,
			.u.compare_op.expect_fault_a = 0,
			.u.compare_op.expect_fault_b = 0,
		},
		[1] = {
			.op = CPU_MEMCPY_OP,
			.len = len,
			.u.memcpy_op.dst = (unsigned long)dst,
			.u.memcpy_op.src = (unsigned long)src,
			.u.memcpy_op.expect_fault_dst = 0,
			.u.memcpy_op.expect_fault_src = 0,
		},
		[2] = {
			.op = CPU_MEMCPY_RELEASE_OP,
			.len = sizeof(intptr_t),
			.u.memcpy_op.dst = (unsigned long)v,
			.u.memcpy_op.src = (unsigned long)&newv,
			.u.memcpy_op.expect_fault_dst = 0,
			.u.memcpy_op.expect_fault_src = 0,
		},
	};

	return cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
}

int cpu_op_addv(intptr_t *v, int64_t count, int cpu)
{
	return cpu_op_add(v, count, sizeof(intptr_t), cpu);
}
