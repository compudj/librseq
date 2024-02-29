/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: 2016-2024 Mathieu Desnoyers <mathieu.desnoyers@efficios.com> */

/*
 * rseq/arch/x86.h
 */

#ifndef _RSEQ_RSEQ_H
#error "Never use <rseq/arch/x86.h> directly; include <rseq/rseq.h> instead."
#endif

#include <stdint.h>

/*
 * RSEQ_ASM_*() macro helpers are internal to the librseq headers. Those
 * are not part of the public API.
 */

/*
 * RSEQ_SIG is used with the following reserved undefined instructions, which
 * trap in user-space:
 *
 * x86-32:    0f b9 3d 53 30 05 53      ud1    0x53053053,%edi
 * x86-64:    0f b9 3d 53 30 05 53      ud1    0x53053053(%rip),%edi
 */
#define RSEQ_SIG	0x53053053

/*
 * Due to a compiler optimization bug in gcc-8 with asm goto and TLS asm input
 * operands, we cannot use "m" input operands, and rather pass the __rseq_abi
 * address through a "r" input operand.
 */

/*
 * Offset of cpu_id, rseq_cs, and mm_cid fields in struct rseq. Those
 * are defined explicitly as macros to be used from assembly.
 */
#define RSEQ_ASM_CPU_ID_OFFSET		4
#define RSEQ_ASM_CS_OFFSET		8
#define RSEQ_ASM_MM_CID_OFFSET		24

/*
 * Refer to the Linux kernel memory model (LKMM) for documentation of
 * the memory barriers. Expect all x86 hardware to be x86-TSO (Total
 * Store Order).
 */

/* CPU memory barrier. */
#define rseq_smp_mb()	\
	__asm__ __volatile__ ("lock; addl $0,-128(%%rsp)" ::: "memory", "cc")
/* CPU read memory barrier */
#define rseq_smp_rmb()	rseq_barrier()
/* CPU write memory barrier */
#define rseq_smp_wmb()	rseq_barrier()

/* Acquire: One-way permeable barrier. */
#define rseq_smp_load_acquire(p)					\
__extension__ ({							\
	rseq_unqual_scalar_typeof(*(p)) ____p1 = RSEQ_READ_ONCE(*(p));	\
	rseq_barrier();							\
	____p1;								\
})

/* Acquire barrier after control dependency. */
#define rseq_smp_acquire__after_ctrl_dep()	rseq_smp_rmb()

/* Release: One-way permeable barrier. */
#define rseq_smp_store_release(p, v)					\
do {									\
	rseq_barrier();							\
	RSEQ_WRITE_ONCE(*(p), v);					\
} while (0)

/* Segment selector for the thread pointer. */
#ifdef RSEQ_ARCH_AMD64
# define RSEQ_ASM_TP_SEGMENT		%%fs
#else
# define RSEQ_ASM_TP_SEGMENT		%%gs
#endif

/*
 * Helper macro to define a variable of pointer type stored in a 64-bit
 * integer. Only used internally in rseq headers.
 */
#ifdef RSEQ_ARCH_AMD64
# define RSEQ_ASM_U64_PTR(x)		".quad " x
#else
# define RSEQ_ASM_U64_PTR(x)		".long " x ", 0x0"
#endif

/*
 * Store the address of the critical section descriptor structure at
 * @cs_label into the @rseq_cs pointer and emit the label @label, which
 * is the beginning of the sequence of consecutive assembly instructions.
 *
 *  @label:
 *    Local label to the beginning of the sequence of consecutive assembly
 *    instructions.
 *  @cs_label:
 *    Source local label to the critical section descriptor structure.
 *  @rseq_cs:
 *    Destination pointer where to store the address of the critical
 *    section descriptor structure.
 */
#ifdef RSEQ_ARCH_AMD64
#define RSEQ_ASM_STORE_RSEQ_CS(label, cs_label, rseq_cs)		\
		RSEQ_INJECT_ASM(1)					\
		"leaq " __rseq_str(cs_label) "(%%rip), %%rax\n\t"	\
		"movq %%rax, " __rseq_str(rseq_cs) "\n\t"		\
		__rseq_str(label) ":\n\t"
#else
# define RSEQ_ASM_STORE_RSEQ_CS(label, cs_label, rseq_cs)		\
		RSEQ_INJECT_ASM(1)					\
		"movl $" __rseq_str(cs_label) ", " __rseq_str(rseq_cs) "\n\t"	\
		__rseq_str(label) ":\n\t"
#endif

/* Only used in RSEQ_ASM_DEFINE_TABLE. */
#define __RSEQ_ASM_DEFINE_TABLE(label, version, flags,			\
				start_ip, post_commit_offset, abort_ip)	\
		".pushsection __rseq_cs, \"aw\"\n\t"			\
		".balign 32\n\t"					\
		__rseq_str(label) ":\n\t"				\
		".long " __rseq_str(version) ", " __rseq_str(flags) "\n\t" \
		RSEQ_ASM_U64_PTR(__rseq_str(start_ip)) "\n\t"		\
		RSEQ_ASM_U64_PTR(__rseq_str(post_commit_offset)) "\n\t" \
		RSEQ_ASM_U64_PTR(__rseq_str(abort_ip)) "\n\t"		\
		".popsection\n\t"					\
		".pushsection __rseq_cs_ptr_array, \"aw\"\n\t"		\
		RSEQ_ASM_U64_PTR(__rseq_str(label) "b") "\n\t"		\
		".popsection\n\t"

/*
 * Define an rseq critical section structure of version 0 with no flags.
 *
 *  @label:
 *    Local label for the beginning of the critical section descriptor
 *    structure.
 *  @start_ip:
 *    Pointer to the first instruction of the sequence of consecutive assembly
 *    instructions.
 *  @post_commit_ip:
 *    Pointer to the instruction after the last instruction of the sequence of
 *    consecutive assembly instructions.
 *  @abort_ip:
 *    Pointer to the instruction where to move the execution flow in case of
 *    abort of the sequence of consecutive assembly instructions.
 */
#define RSEQ_ASM_DEFINE_TABLE(label, start_ip, post_commit_ip, abort_ip) \
	__RSEQ_ASM_DEFINE_TABLE(label, 0x0, 0x0, start_ip,		\
				(post_commit_ip) - (start_ip), abort_ip)

/*
 * Define the @exit_ip pointer as an exit point for the sequence of consecutive
 * assembly instructions at @start_ip.
 *
 *  @start_ip:
 *    Pointer to the first instruction of the sequence of consecutive assembly
 *    instructions.
 *  @exit_ip:
 *    Pointer to an exit point instruction.
 *
 * Exit points of a rseq critical section consist of all instructions outside
 * of the critical section where a critical section can either branch to or
 * reach through the normal course of its execution. The abort IP and the
 * post-commit IP are already part of the __rseq_cs section and should not be
 * explicitly defined as additional exit points. Knowing all exit points is
 * useful to assist debuggers stepping over the critical section.
 */
#define RSEQ_ASM_DEFINE_EXIT_POINT(start_ip, exit_ip)			\
		".pushsection __rseq_exit_point_array, \"aw\"\n\t"	\
		RSEQ_ASM_U64_PTR(__rseq_str(start_ip)) "\n\t"		\
		RSEQ_ASM_U64_PTR(__rseq_str(exit_ip)) "\n\t"		\
		".popsection\n\t"

/*
 * Define a critical section abort handler.
 *
 *  @label:
 *    Local label to the abort handler.
 *  @teardown:
 *    Sequence of instructions to run on abort.
 *  @abort_label:
 *    C label to jump to at the end of the sequence.
 */
#define RSEQ_ASM_DEFINE_ABORT(label, teardown, abort_label)		\
		".pushsection __rseq_failure, \"ax\"\n\t"		\
		/*							\
		 * Disassembler-friendly signature:			\
		 *   x86-32: ud1 <sig>,%edi				\
		 *   x86-64: ud1 <sig>(%rip),%edi			\
		 */							\
		".byte 0x0f, 0xb9, 0x3d\n\t"				\
		".long " __rseq_str(RSEQ_SIG) "\n\t"			\
		__rseq_str(label) ":\n\t"				\
		teardown						\
		"jmp %l[" __rseq_str(abort_label) "]\n\t"		\
		".popsection\n\t"

/*
 * Define a critical section teardown handler.
 *
 *  @label:
 *    Local label to the teardown handler.
 *  @teardown:
 *    Sequence of instructions to run on teardown.
 *  @target_label:
 *    C label to jump to at the end of the sequence.
 */
#define RSEQ_ASM_DEFINE_TEARDOWN(label, teardown, target_label)		\
		".pushsection __rseq_failure, \"ax\"\n\t"		\
		__rseq_str(label) ":\n\t"				\
		teardown						\
		"jmp %l[" __rseq_str(target_label) "]\n\t"		\
		".popsection\n\t"

/* Jump to local label @label when @cpu_id != @current_cpu_id. */
#define RSEQ_ASM_CBNE_CPU_ID(cpu_id, current_cpu_id, label)		\
		RSEQ_INJECT_ASM(2)					\
		"cmpl %[" __rseq_str(cpu_id) "], " __rseq_str(current_cpu_id) "\n\t" \
		"jnz " __rseq_str(label) "\n\t"

/* Per-cpu-id indexing. */

#define RSEQ_TEMPLATE_INDEX_CPU_ID
#define RSEQ_TEMPLATE_MO_RELAXED
#include "rseq/arch/x86/bits.h"
#undef RSEQ_TEMPLATE_MO_RELAXED

#define RSEQ_TEMPLATE_MO_RELEASE
#include "rseq/arch/x86/bits.h"
#undef RSEQ_TEMPLATE_MO_RELEASE
#undef RSEQ_TEMPLATE_INDEX_CPU_ID

/* Per-mm-cid indexing. */

#define RSEQ_TEMPLATE_INDEX_MM_CID
#define RSEQ_TEMPLATE_MO_RELAXED
#include "rseq/arch/x86/bits.h"
#undef RSEQ_TEMPLATE_MO_RELAXED

#define RSEQ_TEMPLATE_MO_RELEASE
#include "rseq/arch/x86/bits.h"
#undef RSEQ_TEMPLATE_MO_RELEASE
#undef RSEQ_TEMPLATE_INDEX_MM_CID

/* APIs which are not indexed. */

#define RSEQ_TEMPLATE_INDEX_NONE
#define RSEQ_TEMPLATE_MO_RELAXED
#include "rseq/arch/x86/bits.h"
#undef RSEQ_TEMPLATE_MO_RELAXED
#undef RSEQ_TEMPLATE_INDEX_NONE