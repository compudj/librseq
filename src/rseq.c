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

#include <rseq/rseq.h>

static __attribute__((constructor))
void rseq_init(void);

static pthread_mutex_t init_lock = PTHREAD_MUTEX_INITIALIZER;
static int init_done;

static const ptrdiff_t *libc_rseq_offset_p;
static const unsigned int *libc_rseq_size_p;
static const unsigned int *libc_rseq_flags_p;

/* Offset from the thread pointer to the rseq area.  */
ptrdiff_t rseq_offset;

/* Size of the registered rseq area.  0 if the registration was
   unsuccessful.  */
unsigned int rseq_size = -1U;

/* Flags used during rseq registration.  */
unsigned int rseq_flags;

static int rseq_ownership;

static
__thread struct rseq_abi __rseq_abi __attribute__((tls_model("initial-exec"))) = {
	.cpu_id = RSEQ_ABI_CPU_ID_UNINITIALIZED,
};

static int sys_rseq(struct rseq_abi *rseq_abi, uint32_t rseq_len,
		    int flags, uint32_t sig)
{
	return syscall(__NR_rseq, rseq_abi, rseq_len, flags, sig);
}

bool rseq_available(unsigned int query)
{
	int rc;

	switch (query) {
	case RSEQ_AVAILABLE_QUERY_KERNEL:
		rc = sys_rseq(NULL, 0, 0, 0);
		if (rc != -1)
			abort();
		switch (errno) {
		case ENOSYS:
		default:
			break;
		case EINVAL:
			return true;
		}
		break;
	case RSEQ_AVAILABLE_QUERY_LIBC:
		if (rseq_size && !rseq_ownership)
			return true;
		break;
	default:
		break;
	}
	return false;
}

int rseq_register_current_thread(void)
{
	int rc;

	rseq_init();

	if (!rseq_ownership) {
		/* Treat libc's ownership as a successful registration. */
		return 0;
	}
	rc = sys_rseq(&__rseq_abi, sizeof(struct rseq_abi), 0, RSEQ_SIG);
	if (rc)
		return -1;
	assert(rseq_current_cpu_raw() >= 0);
	return 0;
}

int rseq_unregister_current_thread(void)
{
	int rc;

	if (!rseq_ownership) {
		/* Treat libc's ownership as a successful unregistration. */
		return 0;
	}
	rc = sys_rseq(&__rseq_abi, sizeof(struct rseq_abi), RSEQ_ABI_FLAG_UNREGISTER, RSEQ_SIG);
	if (rc)
		return -1;
	return 0;
}

static
void rseq_init(void)
{
	if (RSEQ_READ_ONCE(init_done))
		return;

	pthread_mutex_lock(&init_lock);
	if (init_done)
		goto unlock;
	RSEQ_WRITE_ONCE(init_done, 1);
	libc_rseq_offset_p = dlsym(RTLD_NEXT, "__rseq_offset");
	libc_rseq_size_p = dlsym(RTLD_NEXT, "__rseq_size");
	libc_rseq_flags_p = dlsym(RTLD_NEXT, "__rseq_flags");
	if (libc_rseq_size_p && libc_rseq_offset_p && libc_rseq_flags_p &&
			*libc_rseq_size_p != 0) {
		/* rseq registration owned by glibc */
		rseq_offset = *libc_rseq_offset_p;
		rseq_size = *libc_rseq_size_p;
		rseq_flags = *libc_rseq_flags_p;
		goto unlock;
	}
	if (!rseq_available(RSEQ_AVAILABLE_QUERY_KERNEL))
		goto unlock;
	rseq_ownership = 1;
	rseq_offset = (void *)&__rseq_abi - rseq_thread_pointer();
	rseq_size = sizeof(struct rseq_abi);
	rseq_flags = 0;
unlock:
	pthread_mutex_unlock(&init_lock);
}

static __attribute__((destructor))
void rseq_exit(void)
{
	if (!rseq_ownership)
		return;
	rseq_offset = 0;
	rseq_size = -1U;
	rseq_ownership = 0;
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
