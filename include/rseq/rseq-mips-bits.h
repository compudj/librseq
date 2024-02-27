/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: 2018 MIPS Tech LLC */
/* SPDX-FileCopyrightText: 2016-2018 Mathieu Desnoyers <mathieu.desnoyers@efficios.com> */

/*
 * Author: Paul Burton <paul.burton@mips.com>
 */

#include "rseq-bits-template.h"

/*
 * Refer to rseq-pseudocode.h for documentation and pseudo-code of the
 * rseq critical section helpers.
 */
#include "rseq-pseudocode.h"

#if defined(RSEQ_TEMPLATE_MO_RELAXED) && \
	(defined(RSEQ_TEMPLATE_INDEX_CPU_ID) || defined(RSEQ_TEMPLATE_INDEX_MM_CID))

static inline __attribute__((always_inline))
int RSEQ_TEMPLATE_IDENTIFIER(rseq_load_cbne_store__ptr)(intptr_t *v, intptr_t expect, intptr_t newv, int cpu)
{
	RSEQ_INJECT_C(9)

	__asm__ __volatile__ goto (
		RSEQ_ASM_DEFINE_TABLE(9, 1f, 2f, 4f) /* start, commit, abort */
		RSEQ_ASM_DEFINE_EXIT_POINT(1f, %l[ne])
#ifdef RSEQ_COMPARE_TWICE
		RSEQ_ASM_DEFINE_EXIT_POINT(1f, %l[error1])
		RSEQ_ASM_DEFINE_EXIT_POINT(1f, %l[error2])
#endif
		/* Start rseq by storing table entry pointer into rseq_cs. */
		RSEQ_ASM_STORE_RSEQ_CS(1, 3f, rseq_cs)
		RSEQ_ASM_CBNE_CPU_ID(cpu_id, current_cpu_id, 4f)
		RSEQ_INJECT_ASM(3)
		LONG_L " $4, %[v]\n\t"
		"bne $4, %[expect], %l[ne]\n\t"
		RSEQ_INJECT_ASM(4)
#ifdef RSEQ_COMPARE_TWICE
		RSEQ_ASM_CBNE_CPU_ID(cpu_id, current_cpu_id, %l[error1])
		LONG_L " $4, %[v]\n\t"
		"bne $4, %[expect], %l[error2]\n\t"
#endif
		/* final store */
		LONG_S " %[newv], %[v]\n\t"
		"2:\n\t"
		RSEQ_INJECT_ASM(5)
		"b 5f\n\t"
		RSEQ_ASM_DEFINE_ABORT(3, 4, "", abort, 1b, 2b, 4f)
		"5:\n\t"
		: /* gcc asm goto does not allow outputs */
		: [cpu_id]		"r" (cpu),
		  [current_cpu_id]	"m" (rseq_get_abi()->RSEQ_TEMPLATE_INDEX_CPU_ID_FIELD),
		  [rseq_cs]		"m" (rseq_get_abi()->rseq_cs.arch.ptr),
		  [v]			"m" (*v),
		  [expect]		"r" (expect),
		  [newv]		"r" (newv)
		  RSEQ_INJECT_INPUT
		: "$4", "memory"
		  RSEQ_INJECT_CLOBBER
		: abort, ne
#ifdef RSEQ_COMPARE_TWICE
		  , error1, error2
#endif
	);
	return 0;
abort:
	RSEQ_INJECT_FAILED
	return -1;
ne:
	return 1;
#ifdef RSEQ_COMPARE_TWICE
error1:
	rseq_bug("cpu_id comparison failed");
error2:
	rseq_bug("expected value comparison failed");
#endif
}

static inline __attribute__((always_inline))
int RSEQ_TEMPLATE_IDENTIFIER(rseq_load_cbeq_store_add_load_store__ptr)(intptr_t *v, intptr_t expectnot,
			       long voffp, intptr_t *load, int cpu)
{
	RSEQ_INJECT_C(9)

	__asm__ __volatile__ goto (
		RSEQ_ASM_DEFINE_TABLE(9, 1f, 2f, 4f) /* start, commit, abort */
		RSEQ_ASM_DEFINE_EXIT_POINT(1f, %l[eq])
#ifdef RSEQ_COMPARE_TWICE
		RSEQ_ASM_DEFINE_EXIT_POINT(1f, %l[error1])
		RSEQ_ASM_DEFINE_EXIT_POINT(1f, %l[error2])
#endif
		/* Start rseq by storing table entry pointer into rseq_cs. */
		RSEQ_ASM_STORE_RSEQ_CS(1, 3f, rseq_cs)
		RSEQ_ASM_CBNE_CPU_ID(cpu_id, current_cpu_id, 4f)
		RSEQ_INJECT_ASM(3)
		LONG_L " $4, %[v]\n\t"
		"beq $4, %[expectnot], %l[eq]\n\t"
		RSEQ_INJECT_ASM(4)
#ifdef RSEQ_COMPARE_TWICE
		RSEQ_ASM_CBNE_CPU_ID(cpu_id, current_cpu_id, %l[error1])
		LONG_L " $4, %[v]\n\t"
		"beq $4, %[expectnot], %l[error2]\n\t"
#endif
		LONG_S " $4, %[load]\n\t"
		LONG_ADDI " $4, %[voffp]\n\t"
		LONG_L " $4, 0($4)\n\t"
		/* final store */
		LONG_S " $4, %[v]\n\t"
		"2:\n\t"
		RSEQ_INJECT_ASM(5)
		"b 5f\n\t"
		RSEQ_ASM_DEFINE_ABORT(3, 4, "", abort, 1b, 2b, 4f)
		"5:\n\t"
		: /* gcc asm goto does not allow outputs */
		: [cpu_id]		"r" (cpu),
		  [current_cpu_id]	"m" (rseq_get_abi()->RSEQ_TEMPLATE_INDEX_CPU_ID_FIELD),
		  [rseq_cs]		"m" (rseq_get_abi()->rseq_cs.arch.ptr),
		  /* final store input */
		  [v]			"m" (*v),
		  [expectnot]		"r" (expectnot),
		  [voffp]		"Ir" (voffp),
		  [load]		"m" (*load)
		  RSEQ_INJECT_INPUT
		: "$4", "memory"
		  RSEQ_INJECT_CLOBBER
		: abort, eq
#ifdef RSEQ_COMPARE_TWICE
		  , error1, error2
#endif
	);
	return 0;
abort:
	RSEQ_INJECT_FAILED
	return -1;
eq:
	return 1;
#ifdef RSEQ_COMPARE_TWICE
error1:
	rseq_bug("cpu_id comparison failed");
error2:
	rseq_bug("expected value comparison failed");
#endif
}

static inline __attribute__((always_inline))
int RSEQ_TEMPLATE_IDENTIFIER(rseq_load_add_store__ptr)(intptr_t *v, intptr_t count, int cpu)
{
	RSEQ_INJECT_C(9)

	__asm__ __volatile__ goto (
		RSEQ_ASM_DEFINE_TABLE(9, 1f, 2f, 4f) /* start, commit, abort */
#ifdef RSEQ_COMPARE_TWICE
		RSEQ_ASM_DEFINE_EXIT_POINT(1f, %l[error1])
#endif
		/* Start rseq by storing table entry pointer into rseq_cs. */
		RSEQ_ASM_STORE_RSEQ_CS(1, 3f, rseq_cs)
		RSEQ_ASM_CBNE_CPU_ID(cpu_id, current_cpu_id, 4f)
		RSEQ_INJECT_ASM(3)
#ifdef RSEQ_COMPARE_TWICE
		RSEQ_ASM_CBNE_CPU_ID(cpu_id, current_cpu_id, %l[error1])
#endif
		LONG_L " $4, %[v]\n\t"
		LONG_ADDI " $4, %[count]\n\t"
		/* final store */
		LONG_S " $4, %[v]\n\t"
		"2:\n\t"
		RSEQ_INJECT_ASM(4)
		"b 5f\n\t"
		RSEQ_ASM_DEFINE_ABORT(3, 4, "", abort, 1b, 2b, 4f)
		"5:\n\t"
		: /* gcc asm goto does not allow outputs */
		: [cpu_id]		"r" (cpu),
		  [current_cpu_id]	"m" (rseq_get_abi()->RSEQ_TEMPLATE_INDEX_CPU_ID_FIELD),
		  [rseq_cs]		"m" (rseq_get_abi()->rseq_cs.arch.ptr),
		  [v]			"m" (*v),
		  [count]		"Ir" (count)
		  RSEQ_INJECT_INPUT
		: "$4", "memory"
		  RSEQ_INJECT_CLOBBER
		: abort
#ifdef RSEQ_COMPARE_TWICE
		  , error1
#endif
	);
	return 0;
abort:
	RSEQ_INJECT_FAILED
	return -1;
#ifdef RSEQ_COMPARE_TWICE
error1:
	rseq_bug("cpu_id comparison failed");
#endif
}

static inline __attribute__((always_inline))
int RSEQ_TEMPLATE_IDENTIFIER(rseq_load_cbne_load_cbne_store__ptr)(intptr_t *v, intptr_t expect,
			      intptr_t *v2, intptr_t expect2,
			      intptr_t newv, int cpu)
{
	RSEQ_INJECT_C(9)

	__asm__ __volatile__ goto (
		RSEQ_ASM_DEFINE_TABLE(9, 1f, 2f, 4f) /* start, commit, abort */
		RSEQ_ASM_DEFINE_EXIT_POINT(1f, %l[ne])
#ifdef RSEQ_COMPARE_TWICE
		RSEQ_ASM_DEFINE_EXIT_POINT(1f, %l[error1])
		RSEQ_ASM_DEFINE_EXIT_POINT(1f, %l[error2])
		RSEQ_ASM_DEFINE_EXIT_POINT(1f, %l[error3])
#endif
		/* Start rseq by storing table entry pointer into rseq_cs. */
		RSEQ_ASM_STORE_RSEQ_CS(1, 3f, rseq_cs)
		RSEQ_ASM_CBNE_CPU_ID(cpu_id, current_cpu_id, 4f)
		RSEQ_INJECT_ASM(3)
		LONG_L " $4, %[v]\n\t"
		"bne $4, %[expect], %l[ne]\n\t"
		RSEQ_INJECT_ASM(4)
		LONG_L " $4, %[v2]\n\t"
		"bne $4, %[expect2], %l[ne]\n\t"
		RSEQ_INJECT_ASM(5)
#ifdef RSEQ_COMPARE_TWICE
		RSEQ_ASM_CBNE_CPU_ID(cpu_id, current_cpu_id, %l[error1])
		LONG_L " $4, %[v]\n\t"
		"bne $4, %[expect], %l[error2]\n\t"
		LONG_L " $4, %[v2]\n\t"
		"bne $4, %[expect2], %l[error3]\n\t"
#endif
		/* final store */
		LONG_S " %[newv], %[v]\n\t"
		"2:\n\t"
		RSEQ_INJECT_ASM(6)
		"b 5f\n\t"
		RSEQ_ASM_DEFINE_ABORT(3, 4, "", abort, 1b, 2b, 4f)
		"5:\n\t"
		: /* gcc asm goto does not allow outputs */
		: [cpu_id]		"r" (cpu),
		  [current_cpu_id]	"m" (rseq_get_abi()->RSEQ_TEMPLATE_INDEX_CPU_ID_FIELD),
		  [rseq_cs]		"m" (rseq_get_abi()->rseq_cs.arch.ptr),
		  /* cmp2 input */
		  [v2]			"m" (*v2),
		  [expect2]		"r" (expect2),
		  /* final store input */
		  [v]			"m" (*v),
		  [expect]		"r" (expect),
		  [newv]		"r" (newv)
		  RSEQ_INJECT_INPUT
		: "$4", "memory"
		  RSEQ_INJECT_CLOBBER
		: abort, ne
#ifdef RSEQ_COMPARE_TWICE
		  , error1, error2, error3
#endif
	);
	return 0;
abort:
	RSEQ_INJECT_FAILED
	return -1;
ne:
	return 1;
#ifdef RSEQ_COMPARE_TWICE
error1:
	rseq_bug("cpu_id comparison failed");
error2:
	rseq_bug("1st expected value comparison failed");
error3:
	rseq_bug("2nd expected value comparison failed");
#endif
}

#endif /* #if defined(RSEQ_TEMPLATE_MO_RELAXED) &&
	(defined(RSEQ_TEMPLATE_INDEX_CPU_ID) || defined(RSEQ_TEMPLATE_INDEX_MM_CID)) */

#if (defined(RSEQ_TEMPLATE_MO_RELAXED) || defined(RSEQ_TEMPLATE_MO_RELEASE)) && \
	(defined(RSEQ_TEMPLATE_INDEX_CPU_ID) || defined(RSEQ_TEMPLATE_INDEX_MM_CID))

static inline __attribute__((always_inline))
int RSEQ_TEMPLATE_IDENTIFIER(rseq_load_cbne_store_store__ptr)(intptr_t *v, intptr_t expect,
				 intptr_t *v2, intptr_t newv2,
				 intptr_t newv, int cpu)
{
	RSEQ_INJECT_C(9)

	__asm__ __volatile__ goto (
		RSEQ_ASM_DEFINE_TABLE(9, 1f, 2f, 4f) /* start, commit, abort */
		RSEQ_ASM_DEFINE_EXIT_POINT(1f, %l[ne])
#ifdef RSEQ_COMPARE_TWICE
		RSEQ_ASM_DEFINE_EXIT_POINT(1f, %l[error1])
		RSEQ_ASM_DEFINE_EXIT_POINT(1f, %l[error2])
#endif
		/* Start rseq by storing table entry pointer into rseq_cs. */
		RSEQ_ASM_STORE_RSEQ_CS(1, 3f, rseq_cs)
		RSEQ_ASM_CBNE_CPU_ID(cpu_id, current_cpu_id, 4f)
		RSEQ_INJECT_ASM(3)
		LONG_L " $4, %[v]\n\t"
		"bne $4, %[expect], %l[ne]\n\t"
		RSEQ_INJECT_ASM(4)
#ifdef RSEQ_COMPARE_TWICE
		RSEQ_ASM_CBNE_CPU_ID(cpu_id, current_cpu_id, %l[error1])
		LONG_L " $4, %[v]\n\t"
		"bne $4, %[expect], %l[error2]\n\t"
#endif
		/* try store */
		LONG_S " %[newv2], %[v2]\n\t"
		RSEQ_INJECT_ASM(5)
#ifdef RSEQ_TEMPLATE_MO_RELEASE
		"sync\n\t"	/* full sync provides store-release */
#endif
		/* final store */
		LONG_S " %[newv], %[v]\n\t"
		"2:\n\t"
		RSEQ_INJECT_ASM(6)
		"b 5f\n\t"
		RSEQ_ASM_DEFINE_ABORT(3, 4, "", abort, 1b, 2b, 4f)
		"5:\n\t"
		: /* gcc asm goto does not allow outputs */
		: [cpu_id]		"r" (cpu),
		  [current_cpu_id]	"m" (rseq_get_abi()->RSEQ_TEMPLATE_INDEX_CPU_ID_FIELD),
		  [rseq_cs]		"m" (rseq_get_abi()->rseq_cs.arch.ptr),
		  /* try store input */
		  [v2]			"m" (*v2),
		  [newv2]		"r" (newv2),
		  /* final store input */
		  [v]			"m" (*v),
		  [expect]		"r" (expect),
		  [newv]		"r" (newv)
		  RSEQ_INJECT_INPUT
		: "$4", "memory"
		  RSEQ_INJECT_CLOBBER
		: abort, ne
#ifdef RSEQ_COMPARE_TWICE
		  , error1, error2
#endif
	);
	return 0;
abort:
	RSEQ_INJECT_FAILED
	return -1;
ne:
	return 1;
#ifdef RSEQ_COMPARE_TWICE
error1:
	rseq_bug("cpu_id comparison failed");
error2:
	rseq_bug("expected value comparison failed");
#endif
}

static inline __attribute__((always_inline))
int RSEQ_TEMPLATE_IDENTIFIER(rseq_load_cbne_memcpy_store__ptr)(intptr_t *v, intptr_t expect,
				 void *dst, void *src, size_t len,
				 intptr_t newv, int cpu)
{
	uintptr_t rseq_scratch[3];

	RSEQ_INJECT_C(9)

	__asm__ __volatile__ goto (
		RSEQ_ASM_DEFINE_TABLE(9, 1f, 2f, 4f) /* start, commit, abort */
		RSEQ_ASM_DEFINE_EXIT_POINT(1f, %l[ne])
#ifdef RSEQ_COMPARE_TWICE
		RSEQ_ASM_DEFINE_EXIT_POINT(1f, %l[error1])
		RSEQ_ASM_DEFINE_EXIT_POINT(1f, %l[error2])
#endif
		LONG_S " %[src], %[rseq_scratch0]\n\t"
		LONG_S "  %[dst], %[rseq_scratch1]\n\t"
		LONG_S " %[len], %[rseq_scratch2]\n\t"
		/* Start rseq by storing table entry pointer into rseq_cs. */
		RSEQ_ASM_STORE_RSEQ_CS(1, 3f, rseq_cs)
		RSEQ_ASM_CBNE_CPU_ID(cpu_id, current_cpu_id, 4f)
		RSEQ_INJECT_ASM(3)
		LONG_L " $4, %[v]\n\t"
		"bne $4, %[expect], 5f\n\t"
		RSEQ_INJECT_ASM(4)
#ifdef RSEQ_COMPARE_TWICE
		RSEQ_ASM_CBNE_CPU_ID(cpu_id, current_cpu_id, 6f)
		LONG_L " $4, %[v]\n\t"
		"bne $4, %[expect], 7f\n\t"
#endif
		/* try memcpy */
		"beqz %[len], 333f\n\t" \
		"222:\n\t" \
		"lb   $4, 0(%[src])\n\t" \
		"sb   $4, 0(%[dst])\n\t" \
		LONG_ADDI " %[src], 1\n\t" \
		LONG_ADDI " %[dst], 1\n\t" \
		LONG_ADDI " %[len], -1\n\t" \
		"bnez %[len], 222b\n\t" \
		"333:\n\t" \
		RSEQ_INJECT_ASM(5)
#ifdef RSEQ_TEMPLATE_MO_RELEASE
		"sync\n\t"	/* full sync provides store-release */
#endif
		/* final store */
		LONG_S " %[newv], %[v]\n\t"
		"2:\n\t"
		RSEQ_INJECT_ASM(6)
		/* teardown */
		LONG_L " %[len], %[rseq_scratch2]\n\t"
		LONG_L " %[dst], %[rseq_scratch1]\n\t"
		LONG_L " %[src], %[rseq_scratch0]\n\t"
		"b 8f\n\t"
		RSEQ_ASM_DEFINE_ABORT(3, 4,
				      /* teardown */
				      LONG_L " %[len], %[rseq_scratch2]\n\t"
				      LONG_L " %[dst], %[rseq_scratch1]\n\t"
				      LONG_L " %[src], %[rseq_scratch0]\n\t",
				      abort, 1b, 2b, 4f)
		RSEQ_ASM_DEFINE_TEARDOWN(5,
					/* teardown */
					LONG_L " %[len], %[rseq_scratch2]\n\t"
					LONG_L " %[dst], %[rseq_scratch1]\n\t"
					LONG_L " %[src], %[rseq_scratch0]\n\t",
					ne)
#ifdef RSEQ_COMPARE_TWICE
		RSEQ_ASM_DEFINE_TEARDOWN(6,
					/* teardown */
					LONG_L " %[len], %[rseq_scratch2]\n\t"
					LONG_L " %[dst], %[rseq_scratch1]\n\t"
					LONG_L " %[src], %[rseq_scratch0]\n\t",
					error1)
		RSEQ_ASM_DEFINE_TEARDOWN(7,
					/* teardown */
					LONG_L " %[len], %[rseq_scratch2]\n\t"
					LONG_L " %[dst], %[rseq_scratch1]\n\t"
					LONG_L " %[src], %[rseq_scratch0]\n\t",
					error2)
#endif
		"8:\n\t"
		: /* gcc asm goto does not allow outputs */
		: [cpu_id]		"r" (cpu),
		  [current_cpu_id]	"m" (rseq_get_abi()->RSEQ_TEMPLATE_INDEX_CPU_ID_FIELD),
		  [rseq_cs]		"m" (rseq_get_abi()->rseq_cs.arch.ptr),
		  /* final store input */
		  [v]			"m" (*v),
		  [expect]		"r" (expect),
		  [newv]		"r" (newv),
		  /* try memcpy input */
		  [dst]			"r" (dst),
		  [src]			"r" (src),
		  [len]			"r" (len),
		  [rseq_scratch0]	"m" (rseq_scratch[0]),
		  [rseq_scratch1]	"m" (rseq_scratch[1]),
		  [rseq_scratch2]	"m" (rseq_scratch[2])
		  RSEQ_INJECT_INPUT
		: "$4", "memory"
		  RSEQ_INJECT_CLOBBER
		: abort, ne
#ifdef RSEQ_COMPARE_TWICE
		  , error1, error2
#endif
	);
	return 0;
abort:
	RSEQ_INJECT_FAILED
	return -1;
ne:
	return 1;
#ifdef RSEQ_COMPARE_TWICE
error1:
	rseq_bug("cpu_id comparison failed");
error2:
	rseq_bug("expected value comparison failed");
#endif
}

#endif /* #if (defined(RSEQ_TEMPLATE_MO_RELAXED) || defined(RSEQ_TEMPLATE_MO_RELEASE)) &&
	(defined(RSEQ_TEMPLATE_INDEX_CPU_ID) || defined(RSEQ_TEMPLATE_INDEX_MM_CID)) */

#include "rseq-bits-reset.h"
