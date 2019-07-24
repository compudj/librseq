/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_DO_ON_CPU_H
#define _UAPI_LINUX_DO_ON_CPU_H

/*
 * linux/do_on_cpu.h
 *
 * do_on_cpu system call API
 *
 * Copyright (c) 2017-2019 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#include <linux/bpf.h>

enum do_on_cpu_flags {
	DO_ON_CPU_LEN_MAX_FLAG =		(1U << 0),
	DO_ON_CPU_RETIRED_INSN_MAX_FLAG =	(1U << 1),
	DO_ON_CPU_PAGES_MAX_FLAG =		(1U << 2),
};

/*
 * Define the do_on_cpu system call number if not yet available in
 * the system headers. System call numbers allocated starting from
 * kernel 5.1 are the same across all architectures.
 */
#ifndef __NR_do_on_cpu
#define __NR_do_on_cpu           428
#endif

#endif /* _UAPI_LINUX_DO_ON_CPU_H */
