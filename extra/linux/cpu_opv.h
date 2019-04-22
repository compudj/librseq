/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_CPU_OPV_H
#define _UAPI_LINUX_CPU_OPV_H

/*
 * linux/cpu_opv.h
 *
 * Per-CPU-atomic operation vector system call API
 *
 * Copyright (c) 2017-2018 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#include <linux/types.h>

/* Maximum size of operation structure within struct cpu_op. */
#define CPU_OP_ARG_LEN_MAX			24
/* Maximum data len for compare and memcpy operations. */
#define CPU_OP_DATA_LEN_MAX			4096
/* Maximum data len for arithmetic operations. */
#define CPU_OP_ARITHMETIC_DATA_LEN_MAX		8

enum cpu_op_flags {
	CPU_OP_NR_FLAG =		(1U << 0),
	CPU_OP_VEC_LEN_MAX_FLAG =	(1U << 1),
};

enum cpu_op_type {
	/* compare */
	CPU_COMPARE_EQ_OP,
	CPU_COMPARE_NE_OP,
	/* memcpy */
	CPU_MEMCPY_OP,
	CPU_MEMCPY_RELEASE_OP,
	/* arithmetic */
	CPU_ADD_OP,
	CPU_ADD_RELEASE_OP,

	NR_CPU_OPS,
};

/* Vector of operations to perform. Limited to 16. */
struct cpu_op {
	/* enum cpu_op_type. */
	__s32 op;
	/* data length, in bytes. */
	__u32 len;
	union {
		struct {
			__u64 a;
			__u64 b;
			__u8 expect_fault_a;
			__u8 expect_fault_b;
		} compare_op;
		struct {
			__u64 dst;
			__u64 src;
			__u8 expect_fault_dst;
			__u8 expect_fault_src;
		} memcpy_op;
		struct {
			__u64 p;
			__s64 count;
			__u8 expect_fault_p;
		} arithmetic_op;
		char __padding[CPU_OP_ARG_LEN_MAX];
	} u;
};

/*
 * Define the rseq system call number if not yet available in
 * the system headers.
 */
#ifdef __x86_64__

#ifndef __NR_cpu_opv
#define __NR_cpu_opv		335
#endif

#elif defined(__i386__)

#ifndef __NR_cpu_opv
#define __NR_cpu_opv		387
#endif

#elif defined(__AARCH64EL__)

#ifndef __NR_cpu_opv
#define __NR_cpu_opv		295
#endif

#elif defined(__ARMEL__)

#ifndef __NR_cpu_opv
#define __NR_cpu_opv		400
#endif

#elif defined(__PPC__)

#ifndef __NR_cpu_opv
#define __NR_cpu_opv		389
#endif

#endif

#endif /* _UAPI_LINUX_CPU_OPV_H */
