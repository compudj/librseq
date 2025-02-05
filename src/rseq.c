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
#include <assert.h>
#include <signal.h>
#include <limits.h>
#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/auxv.h>
#include <linux/auxvec.h>

#include <rseq/rseq.h>
#include "smp.h"
#include "rseq-utils.h"

static __attribute__((constructor))
void rseq_init(void);

static pthread_mutex_t init_lock = PTHREAD_MUTEX_INITIALIZER;
static int init_done;

static const ptrdiff_t *libc_rseq_offset_p;
static const unsigned int *libc_rseq_size_p;
static const unsigned int *libc_rseq_flags_p;

static int libc_has_rseq;

/* Offset from the thread pointer to the rseq area. */
ptrdiff_t rseq_offset;

/*
 * Size of the active rseq feature set. 0 if the registration was
 * unsuccessful.
 */
unsigned int rseq_size = -1U;

/* Flags used during rseq registration. */
unsigned int rseq_flags;

bool rseq_available(unsigned int query)
{
	int rc;

	rseq_init();

	switch (query) {
	case RSEQ_AVAILABLE_QUERY_KERNEL:
		rc = sys_rseq(NULL, 0, 0, 0);
		if (rc != -1)
			abort();
		switch (errno) {
		case ENOSYS:
			break;
		case EINVAL:
			return true;
		default:
			abort();
		}
		break;
	case RSEQ_AVAILABLE_QUERY_LIBC:
		if (libc_has_rseq)
			return true;
		break;
	default:
		break;
	}
	return false;
}

/*
 * Initialize the public symbols for the rseq offset, size, feature size and
 * flags prior to registering threads. If glibc owns the registration, get the
 * values from its public symbols.
 */
static
void rseq_init(void)
{
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

	/*
	 * Check for glibc rseq support, if the 3 public symbols are found and
	 * the rseq_size is not zero, glibc owns the registration.
	 */
	libc_rseq_offset_p = dlsym(RTLD_NEXT, "__rseq_offset");
	libc_rseq_size_p = dlsym(RTLD_NEXT, "__rseq_size");
	libc_rseq_flags_p = dlsym(RTLD_NEXT, "__rseq_flags");
	if (libc_rseq_size_p && libc_rseq_offset_p && libc_rseq_flags_p &&
			*libc_rseq_size_p != 0) {
		unsigned int libc_rseq_size;

		/* rseq registration owned by glibc */
		libc_has_rseq = 1;
		rseq_offset = *libc_rseq_offset_p;
		libc_rseq_size = *libc_rseq_size_p;
		rseq_flags = *libc_rseq_flags_p;

		/*
		 * Previous versions of glibc expose the value
		 * 32 even though the kernel only supported 20
		 * bytes initially. Therefore treat 32 as a
		 * special-case. glibc 2.40 exposes a 20 bytes
		 * __rseq_size without using getauxval(3) to
		 * query the supported size, while still allocating a 32
		 * bytes area. Also treat 20 as a special-case.
		 *
		 * Special-cases are handled by using the following
		 * value as active feature set size:
		 *
		 *   rseq_size = min(32, get_rseq_kernel_feature_size())
		 */
		switch (libc_rseq_size) {
		case ORIG_RSEQ_FEATURE_SIZE:	/* Fallthrough. */
		case ORIG_RSEQ_ALLOC_SIZE:
		{
			unsigned int rseq_kernel_feature_size = get_rseq_kernel_feature_size();

			if (rseq_kernel_feature_size < ORIG_RSEQ_ALLOC_SIZE)
				rseq_size = rseq_kernel_feature_size;
			else
				rseq_size = ORIG_RSEQ_ALLOC_SIZE;
			break;
		}
		default:
			/* Otherwise just use the __rseq_size from libc as rseq_size. */
			rseq_size = libc_rseq_size;
			break;
		}
	}

	/*
	 * Set init_done with store-release, to make sure concurrently
	 * running threads observe the initialized state.
	 */
	rseq_smp_store_release(&init_done, 1);
unlock:
	pthread_mutex_unlock(&init_lock);
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

int32_t rseq_fallback_current_node(void)
{
	uint32_t cpu_id, node_id;
	int ret;

	ret = sys_getcpu(&cpu_id, &node_id);
	if (ret) {
		perror("sys_getcpu()");
		return ret;
	}
	return (int32_t) node_id;
}

int rseq_get_max_nr_cpus(void)
{
	return get_possible_cpus_array_len();
}
