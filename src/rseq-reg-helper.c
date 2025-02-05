// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2016 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>

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
#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>

#include <rseq/rseq.h>
#include "rseq-utils.h"

#ifndef AT_RSEQ_FEATURE_SIZE
# define AT_RSEQ_FEATURE_SIZE		27
#endif

#ifndef AT_RSEQ_ALIGN
# define AT_RSEQ_ALIGN			28
#endif

static __attribute__((constructor))
void rseq_reg_helper_init(void);

static pthread_mutex_t init_lock = PTHREAD_MUTEX_INITIALIZER;
static int init_done;
static int rseq_ownership;

/*
 * The alignment on RSEQ_THREAD_AREA_ALLOC_SIZE guarantees that the
 * rseq_abi structure allocated size is at least
 * RSEQ_THREAD_AREA_ALLOC_SIZE bytes to hold extra space for yet unknown
 * kernel rseq extensions.
 */
static
__thread struct rseq_abi __rseq_abi __attribute__((tls_model("initial-exec"), aligned(RSEQ_THREAD_AREA_ALLOC_SIZE))) = {
	.cpu_id = RSEQ_ABI_CPU_ID_UNINITIALIZED,
};

/* The rseq areas need to be at least 32 bytes. */
static
unsigned int get_rseq_min_alloc_size(void)
{
	unsigned int alloc_size = rseq_size;

	if (alloc_size < ORIG_RSEQ_ALLOC_SIZE)
		alloc_size = ORIG_RSEQ_ALLOC_SIZE;
	return alloc_size;
}

int rseq_register_current_thread(void)
{
	int rc;

	rseq_reg_helper_init();

	if (!rseq_ownership) {
		/* Treat libc's ownership as a successful registration. */
		return 0;
	}
	rc = sys_rseq(&__rseq_abi, get_rseq_min_alloc_size(), 0, RSEQ_SIG);
	if (rc) {
		/*
		 * After at least one thread has registered successfully
		 * (rseq_size > 0), the registration of other threads should
		 * never fail.
		 */
		if (RSEQ_READ_ONCE(rseq_size) > 0) {
			/* Incoherent success/failure within process. */
			abort();
		}
		return -1;
	}
	assert(rseq_current_cpu_raw() >= 0);

	/*
	 * The first thread to register sets the rseq_size to mimic the libc
	 * behavior.
	 */
	if (RSEQ_READ_ONCE(rseq_size) == 0) {
		RSEQ_WRITE_ONCE(rseq_size, get_rseq_kernel_feature_size());
	}

	return 0;
}

int rseq_unregister_current_thread(void)
{
	int rc;

	if (!rseq_ownership) {
		/* Treat libc's ownership as a successful unregistration. */
		return 0;
	}
	rc = sys_rseq(&__rseq_abi, get_rseq_min_alloc_size(), RSEQ_ABI_FLAG_UNREGISTER, RSEQ_SIG);
	if (rc)
		return -1;
	return 0;
}

/*
 * Initialize the public symbols for the rseq offset, size, feature size and
 * flags prior to registering threads. If glibc owns the registration, get the
 * values from its public symbols.
 */
static
void rseq_reg_helper_init(void)
{
	/*
	 * Use libc's rseq area if it supports rseq.
	 */
	if (rseq_available(RSEQ_AVAILABLE_QUERY_LIBC))
		return;

	/*
	 * Ensure initialization is only done once. Use load-acquire to
	 * observe the initialization performed by a concurrently
	 * running thread.
	 */
	if (rseq_smp_load_acquire(&init_done))
		return;

	/*
	 * Take the mutex, check the initialization flag again and atomically
	 * set it to ensure we are the only thread doing the initialization.
	 */
	pthread_mutex_lock(&init_lock);
	if (init_done)
		goto unlock;

	/* librseq owns the registration */
	rseq_ownership = 1;

	/* Calculate the offset of the rseq area from the thread pointer. */
	rseq_offset = (uintptr_t)&__rseq_abi - (uintptr_t)rseq_thread_pointer();

	/* rseq flags are deprecated, always set to 0. */
	rseq_flags = 0;

	/*
	 * Set the size to 0 until at least one thread registers to mimic the
	 * libc behavior.
	 */
	rseq_size = 0;

	/*
	 * Set init_done with store-release, to make sure concurrently
	 * running threads observe the initialized state.
	 */
	rseq_smp_store_release(&init_done, 1);
unlock:
	pthread_mutex_unlock(&init_lock);
}

static __attribute__((destructor))
void rseq_reg_helper_exit(void)
{
	if (!rseq_ownership)
		return;
	rseq_offset = 0;
	rseq_size = -1U;
	rseq_ownership = 0;
}
