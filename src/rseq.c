// SPDX-License-Identifier: LGPL-2.1-only
/*
 * rseq.c
 *
 * Copyright (C) 2016 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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
#include <limits.h>

#include <rseq/rseq.h>

#define ARRAY_SIZE(arr)	(sizeof(arr) / sizeof((arr)[0]))

__thread struct rseq __rseq_abi = {
	.cpu_id = RSEQ_CPU_ID_UNINITIALIZED,
};

static __thread uint32_t __rseq_refcount;

static int sys_rseq(struct rseq *rseq_abi, uint32_t rseq_len,
		    int flags, uint32_t sig)
{
	return syscall(__NR_rseq, rseq_abi, rseq_len, flags, sig);
}

int rseq_available(void)
{
	int rc;

	rc = sys_rseq(NULL, 0, 0, 0);
	if (rc != -1)
		abort();
	switch (errno) {
	case ENOSYS:
		return 0;
	case EINVAL:
		return 1;
	default:
		abort();
	}
}

static void signal_off_save(sigset_t *oldset)
{
	sigset_t set;
	int ret;

	sigfillset(&set);
	ret = pthread_sigmask(SIG_BLOCK, &set, oldset);
	if (ret)
		abort();
}

static void signal_restore(sigset_t oldset)
{
	int ret;

	ret = pthread_sigmask(SIG_SETMASK, &oldset, NULL);
	if (ret)
		abort();
}

int rseq_register_current_thread(void)
{
	int rc, ret = 0, cpu_id;
	sigset_t oldset;

	signal_off_save(&oldset);
	cpu_id = rseq_current_cpu_raw();
	if (cpu_id == RSEQ_CPU_ID_REGISTRATION_FAILED) {
		errno = EPERM;
		ret = -1;
		goto end;
	}
	/*
	 * If cpu_id >= 0, rseq is already successfully registered either by
	 * libc (__rseq_refcount == 0) or by another user library
	 * (__rseq_refcount > 0) for this thread.
	 */
	if (cpu_id >= 0) {
		/* Treat libc's ownership as a successful registration. */
		if (__rseq_refcount == 0)
			goto end;
		if (__rseq_refcount == UINT_MAX) {
			errno = EOVERFLOW;
			ret = -1;
			goto end;
		}
	} else {
		assert(__rseq_refcount == 0);
		rc = sys_rseq(&__rseq_abi, sizeof(struct rseq), 0, RSEQ_SIG);
		if (rc) {
			assert(errno != EBUSY);
			__rseq_abi.cpu_id = RSEQ_CPU_ID_REGISTRATION_FAILED;
			ret = -1;
			goto end;
		}
		assert(rseq_current_cpu_raw() >= 0);
	}
	__rseq_refcount++;
end:
	signal_restore(oldset);
	return ret;
}

int rseq_unregister_current_thread(void)
{
	int rc, ret = 0, cpu_id;
	sigset_t oldset;

	signal_off_save(&oldset);
	cpu_id = rseq_current_cpu_raw();
	/* cpu_id < 0 means rseq is either uninitialized or registration failed. */
	if (cpu_id < 0) {
		errno = EPERM;
		ret = -1;
		goto end;
	}
	/*
	 * If cpu_id >= 0, rseq is currently successfully registered either by
	 * libc (__rseq_refcount == 0) or by another user library
	 * (__rseq_refcount > 0) for this thread.
	 *
	 * Treat libc's ownership as a successful unregistration.
	 */
	if (__rseq_refcount == 0) {
		goto end;
	}
	if (__rseq_refcount == 1) {
		rc = sys_rseq(&__rseq_abi, sizeof(struct rseq),
			      RSEQ_FLAG_UNREGISTER, RSEQ_SIG);
		if (rc) {
			ret = -1;
			goto end;
		}
	}
	__rseq_refcount--;
end:
	signal_restore(oldset);
	return ret;
}

int32_t rseq_fallback_current_cpu(void)
{
	int32_t cpu;

	cpu = sched_getcpu();
	if (cpu < 0) {
		perror("sched_getcpu()");
		abort();
	}
	return cpu;
}
