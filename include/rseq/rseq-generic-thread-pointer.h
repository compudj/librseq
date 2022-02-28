/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: 2021 Mathieu Desnoyers <mathieu.desnoyers@efficios.com> */

/*
 * rseq-generic-thread-pointer.h
 */

#ifndef _RSEQ_GENERIC_THREAD_POINTER
#define _RSEQ_GENERIC_THREAD_POINTER

#ifdef __cplusplus
extern "C" {
#endif

/* Use gcc builtin thread pointer. */
static inline void *rseq_thread_pointer(void)
{
	return __builtin_thread_pointer();
}

#ifdef __cplusplus
}
#endif

#endif
