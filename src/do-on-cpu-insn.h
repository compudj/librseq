/* SPDX-License-Identifier: LGPL-2.1 OR MIT */
/*
 * do-on-cpu-insn.h
 *
 * (C) Copyright 2019 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef DO_ON_CPU_INSN_H
#define DO_ON_CPU_INSN_H

#include <linux/bpf.h>

#ifndef BPF_JMP32
#define BPF_JMP32	0x06
#endif

#ifndef BPF_MEM_ACQ_REL
#define BPF_MEM_ACQ_REL	0xe0
#endif

/* ALU */
#ifndef BPF_MB
#define BPF_MB		0xd0
#endif

#define BPF_PTR_TO_V(ptr)	((unsigned long) (ptr))

#define BPFI_LD_IMM64(_reg, _v)					\
		{						\
			.code = BPF_LD | BPF_DW | BPF_IMM,	\
			.dst_reg = (_reg),			\
			.off = 0,				\
			.imm = (__s32) (_v),			\
		},						\
		{						\
			.code = BPF_LD | BPF_W | BPF_IMM,	\
			.dst_reg = 0,				\
			.src_reg = 0,				\
			.off = 0,				\
			.imm = (__s32)(((__s64) (_v)) >> 32),	\
		}

#define BPFI_LD_IMM32(_reg, _v)					\
		{						\
			.code = BPF_LD | BPF_W | BPF_IMM,	\
			.dst_reg = (_reg),			\
			.off = 0,				\
			.imm = (__s32) (_v),			\
		}						\

#define BPFI_LDX(_size, _dst_reg, _src_reg, _off)		\
		{						\
			.code = BPF_LDX | (_size) | BPF_MEM,	\
			.dst_reg = _dst_reg,			\
			.src_reg = _src_reg,			\
			.off = _off,				\
		}

#define BPFI_LDX_ACQUIRE(_size, _dst_reg, _src_reg, _off)	\
		{						\
			.code = BPF_LDX | (_size) | BPF_MEM_ACQ_REL, \
			.dst_reg = _dst_reg,			\
			.src_reg = _src_reg,			\
			.off = _off,				\
		}

#define BPFI_LDX_MODE(_size, _mode, _dst_reg, _src_reg, _off)	\
		{						\
			.code = BPF_LDX | (_size) | (_mode),	\
			.dst_reg = _dst_reg,			\
			.src_reg = _src_reg,			\
			.off = _off,				\
		}

#define BPFI_STX(_size, _dst_reg, _src_reg, _off)		\
		{						\
			.code = BPF_STX | (_size) | BPF_MEM,	\
			.dst_reg = _dst_reg,			\
			.src_reg = _src_reg,			\
			.off = _off,				\
		}

#define BPFI_STX_RELEASE(_size, _dst_reg, _src_reg, _off)	\
		{						\
			.code = BPF_STX | (_size) | BPF_MEM_ACQ_REL, \
			.dst_reg = _dst_reg,			\
			.src_reg = _src_reg,			\
			.off = _off,				\
		}

#define BPFI_STX_MODE(_size, _mode, _dst_reg, _src_reg, _off)	\
		{						\
			.code = BPF_STX | (_size) | (_mode),	\
			.dst_reg = _dst_reg,			\
			.src_reg = _src_reg,			\
			.off = _off,				\
		}

#define BPFI_ADD64_K(_reg, _imm)				\
		{						\
			.code = BPF_ALU64 | BPF_ADD | BPF_K,	\
			.dst_reg = _reg,			\
			.imm = _imm,				\
		}

#define BPFI_SUB64_K(_reg, _imm)				\
		{						\
			.code = BPF_ALU64 | BPF_SUB | BPF_K,	\
			.dst_reg = _reg,			\
			.imm = _imm,				\
		}

#define BPFI_ADD64_X(_dst_reg, _src_reg)			\
		{						\
			.code = BPF_ALU64 | BPF_ADD | BPF_X,	\
			.dst_reg = _dst_reg,			\
			.src_reg = _src_reg,			\
		}

#define BPFI_SUB64_X(_dst_reg, _src_reg)			\
		{						\
			.code = BPF_ALU64 | BPF_SUB | BPF_X,	\
			.dst_reg = _dst_reg,			\
			.src_reg = _src_reg,			\
		}

#define BPFI_MOV_X(_dst_reg, _src_reg)				\
		{						\
			.code = BPF_ALU64 | BPF_MOV | BPF_X,	\
			.dst_reg = _dst_reg,			\
			.src_reg = _src_reg,			\
		}

#define BPFI_MB()						\
		{						\
			.code = BPF_ALU | BPF_MB,		\
		}

#define BPFI_JA_K(_off)						\
		{						\
			.code = BPF_JMP | BPF_JA,		\
			.off = _off,				\
		}


#define BPFI_JEQ_K(_reg, _imm, _off)				\
		{						\
			.code = BPF_JMP | BPF_JEQ | BPF_K,	\
			.dst_reg = _reg,			\
			.imm = _imm,				\
			.off = _off,				\
		}

#define BPFI_JEQ_X(_dst_reg, _src_reg, _off)			\
		{						\
			.code = BPF_JMP | BPF_JEQ | BPF_X,	\
			.dst_reg = _dst_reg,			\
			.src_reg = _src_reg,			\
			.off = _off,				\
		}

#define BPFI_JNE_K(_reg, _imm, _off)				\
		{						\
			.code = BPF_JMP | BPF_JNE | BPF_K,	\
			.dst_reg = _reg,			\
			.imm = _imm,				\
			.off = _off,				\
		}

#define BPFI_JNE_X(_dst_reg, _src_reg, _off)			\
		{						\
			.code = BPF_JMP | BPF_JNE | BPF_X,	\
			.dst_reg = _dst_reg,			\
			.src_reg = _src_reg,			\
			.off = _off,				\
		}

#define BPFI_EXIT()						\
		{						\
			.code = BPF_JMP | BPF_EXIT,		\
		}

#endif /* DO_ON_CPU_INSN_H */
