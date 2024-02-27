/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: 2016-2024 Mathieu Desnoyers <mathieu.desnoyers@efficios.com> */

/*
 * rseq-arm.h
 */

/*
 * RSEQ_ASM_*() macro helpers are internal to the librseq headers. Those
 * are not part of the public API.
 */

/*
 * - ARM little endian
 *
 * RSEQ_SIG uses the udf A32 instruction with an uncommon immediate operand
 * value 0x5de3. This traps if user-space reaches this instruction by mistake,
 * and the uncommon operand ensures the kernel does not move the instruction
 * pointer to attacker-controlled code on rseq abort.
 *
 * The instruction pattern in the A32 instruction set is:
 *
 * e7f5def3    udf    #24035    ; 0x5de3
 *
 * This translates to the following instruction pattern in the T16 instruction
 * set:
 *
 * little endian:
 * def3        udf    #243      ; 0xf3
 * e7f5        b.n    <7f5>
 *
 * - ARMv6+ big endian (BE8):
 *
 * ARMv6+ -mbig-endian generates mixed endianness code vs data: little-endian
 * code and big-endian data. The data value of the signature needs to have its
 * byte order reversed to generate the trap instruction:
 *
 * Data: 0xf3def5e7
 *
 * Translates to this A32 instruction pattern:
 *
 * e7f5def3    udf    #24035    ; 0x5de3
 *
 * Translates to this T16 instruction pattern:
 *
 * def3        udf    #243      ; 0xf3
 * e7f5        b.n    <7f5>
 *
 * - Prior to ARMv6 big endian (BE32):
 *
 * Prior to ARMv6, -mbig-endian generates big-endian code and data
 * (which match), so the endianness of the data representation of the
 * signature should not be reversed. However, the choice between BE32
 * and BE8 is done by the linker, so we cannot know whether code and
 * data endianness will be mixed before the linker is invoked. So rather
 * than try to play tricks with the linker, the rseq signature is simply
 * data (not a trap instruction) prior to ARMv6 on big endian. This is
 * why the signature is expressed as data (.word) rather than as
 * instruction (.inst) in assembler.
 */

#ifdef __ARMEB__
#define RSEQ_SIG    0xf3def5e7      /* udf    #24035    ; 0x5de3 (ARMv6+) */
#else
#define RSEQ_SIG    0xe7f5def3      /* udf    #24035    ; 0x5de3 */
#endif

/*
 * Refer to the Linux kernel memory model (LKMM) for documentation of
 * the memory barriers.
 */

/* CPU memory barrier. */
#define rseq_smp_mb()	__asm__ __volatile__ ("dmb" ::: "memory", "cc")
/* CPU read memory barrier */
#define rseq_smp_rmb()	__asm__ __volatile__ ("dmb" ::: "memory", "cc")
/* CPU write memory barrier */
#define rseq_smp_wmb()	__asm__ __volatile__ ("dmb" ::: "memory", "cc")

/* Acquire: One-way permeable barrier. */
#define rseq_smp_load_acquire(p)					\
__extension__ ({							\
	rseq_unqual_scalar_typeof(*(p)) ____p1 = RSEQ_READ_ONCE(*(p));	\
	rseq_smp_mb();							\
	____p1;								\
})

/* Acquire barrier after control dependency. */
#define rseq_smp_acquire__after_ctrl_dep()	rseq_smp_rmb()

/* Release: One-way permeable barrier. */
#define rseq_smp_store_release(p, v)					\
do {									\
	rseq_smp_mb();							\
	RSEQ_WRITE_ONCE(*(p), v);					\
} while (0)

/* Only used in RSEQ_ASM_DEFINE_TABLE. */
#define __RSEQ_ASM_DEFINE_TABLE(label, version, flags, start_ip,	\
				post_commit_offset, abort_ip)		\
		".pushsection __rseq_cs, \"aw\"\n\t"			\
		".balign 32\n\t"					\
		__rseq_str(label) ":\n\t"				\
		".word " __rseq_str(version) ", " __rseq_str(flags) "\n\t" \
		".word " __rseq_str(start_ip) ", 0x0, " __rseq_str(post_commit_offset) ", 0x0, " __rseq_str(abort_ip) ", 0x0\n\t" \
		".popsection\n\t"					\
		".pushsection __rseq_cs_ptr_array, \"aw\"\n\t"		\
		".word " __rseq_str(label) "b, 0x0\n\t"			\
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
				(post_commit_ip - start_ip), abort_ip)

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
		".word " __rseq_str(start_ip) ", 0x0, " __rseq_str(exit_ip) ", 0x0\n\t" \
		".popsection\n\t"

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
#define RSEQ_ASM_STORE_RSEQ_CS(label, cs_label, rseq_cs)		\
		RSEQ_INJECT_ASM(1)					\
		"adr r0, " __rseq_str(cs_label) "\n\t"			\
		"str r0, %[" __rseq_str(rseq_cs) "]\n\t"		\
		__rseq_str(label) ":\n\t"

/* Only used in RSEQ_ASM_DEFINE_ABORT.  */
#define __RSEQ_ASM_DEFINE_ABORT(table_label, label, teardown,		\
				abort_label, version, flags,		\
				start_ip, post_commit_offset, abort_ip)	\
		".balign 32\n\t"					\
		__rseq_str(table_label) ":\n\t"				\
		".word " __rseq_str(version) ", " __rseq_str(flags) "\n\t" \
		".word " __rseq_str(start_ip) ", 0x0, " __rseq_str(post_commit_offset) ", 0x0, " __rseq_str(abort_ip) ", 0x0\n\t" \
		".word " __rseq_str(RSEQ_SIG) "\n\t"			\
		__rseq_str(label) ":\n\t"				\
		teardown						\
		"b %l[" __rseq_str(abort_label) "]\n\t"

/*
 * Define a critical section abort handler.
 *
 *  @table_label:
 *    Local label to the critical section descriptor copy placed near
 *    the program counter. This is done for performance reasons because
 *    computing this address is faster than accessing the program data.
 *  @label:
 *    Local label to the abort handler.
 *  @teardown:
 *    Sequence of instructions to run on abort.
 *  @abort_label:
 *    C label to jump to at the end of the sequence.
 *
 * The purpose of @start_ip, @post_commit_ip, and @abort_ip are
 * documented in RSEQ_ASM_DEFINE_TABLE.
 */
#define RSEQ_ASM_DEFINE_ABORT(table_label, label, teardown, abort_label, \
			      start_ip, post_commit_ip, abort_ip)	\
	__RSEQ_ASM_DEFINE_ABORT(table_label, label, teardown,		\
				abort_label, 0x0, 0x0, start_ip,	\
				(post_commit_ip - start_ip), abort_ip)

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
		__rseq_str(label) ":\n\t"				\
		teardown						\
		"b %l[" __rseq_str(target_label) "]\n\t"

/* Jump to local label @label when @cpu_id != @current_cpu_id. */
#define RSEQ_ASM_CBNE_CPU_ID(cpu_id, current_cpu_id, label)		\
		RSEQ_INJECT_ASM(2)					\
		"ldr r0, %[" __rseq_str(current_cpu_id) "]\n\t"		\
		"cmp %[" __rseq_str(cpu_id) "], r0\n\t"			\
		"bne " __rseq_str(label) "\n\t"

/* Per-cpu-id indexing. */

#define RSEQ_TEMPLATE_INDEX_CPU_ID
#define RSEQ_TEMPLATE_MO_RELAXED
#include "rseq-arm-bits.h"
#undef RSEQ_TEMPLATE_MO_RELAXED

#define RSEQ_TEMPLATE_MO_RELEASE
#include "rseq-arm-bits.h"
#undef RSEQ_TEMPLATE_MO_RELEASE
#undef RSEQ_TEMPLATE_INDEX_CPU_ID

/* Per-mm-cid indexing. */

#define RSEQ_TEMPLATE_INDEX_MM_CID
#define RSEQ_TEMPLATE_MO_RELAXED
#include "rseq-arm-bits.h"
#undef RSEQ_TEMPLATE_MO_RELAXED

#define RSEQ_TEMPLATE_MO_RELEASE
#include "rseq-arm-bits.h"
#undef RSEQ_TEMPLATE_MO_RELEASE
#undef RSEQ_TEMPLATE_INDEX_MM_CID

/* APIs which are not indexed. */

#define RSEQ_TEMPLATE_INDEX_NONE
#define RSEQ_TEMPLATE_MO_RELAXED
#include "rseq-arm-bits.h"
#undef RSEQ_TEMPLATE_MO_RELAXED
#undef RSEQ_TEMPLATE_INDEX_NONE
