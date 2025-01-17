// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Michael Jeanson <mjeanson@efficios.com>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdint.h>
#include <syscall.h>
#include <unistd.h>

#include <rseq/rseq.h>

#include "tap.h"

#if (RSEQ_BITS_PER_LONG == 64) && (!defined(RSEQ_ARCH_S390))
#define NR_TESTS 8
#define RUN_RSEQ_INVALID_ADDRESS_TEST 1
#else
#define NR_TESTS 7
#endif

static int sys_rseq(void *rseq_abi, uint32_t rseq_len,
		    int flags, uint32_t sig)
{
	return syscall(__NR_rseq, rseq_abi, rseq_len, flags, sig);
}

/*
 * Check the value of errno on some expected failures of the rseq syscall.
 */

int main(void)
{
	struct rseq_abi *global_rseq = rseq_get_abi();
	int ret;
	int errno_copy;

	plan_tests(NR_TESTS);

	if (!rseq_available(RSEQ_AVAILABLE_QUERY_KERNEL)) {
		skip(NR_TESTS, "rseq syscall unavailable");
		goto end;
	}

	/* The current thread is NOT registered. */

	/* EINVAL */
	errno = 0;
	ret = sys_rseq(global_rseq, 32, -1, RSEQ_SIG);
	errno_copy = errno;
	ok(ret != 0 && errno_copy == EINVAL, "Invalid flag set errno to EINVAL (ret = %d, errno = %d)", ret, errno_copy);

	errno = 0;
	ret = sys_rseq((char *) global_rseq + 1, 32, 0, RSEQ_SIG);
	errno_copy = errno;
	ok(ret != 0 && errno_copy == EINVAL, "Unaligned rseq_abi set errno to EINVAL (ret = %d, errno = %d)", ret, errno_copy);

	errno = 0;
	ret = sys_rseq(global_rseq, 31, 0, RSEQ_SIG);
	errno_copy = errno;
	ok(ret != 0 && errno_copy == EINVAL, "Invalid size set errno to EINVAL (ret = %d, errno = %d)", ret, errno_copy);


#if defined(RUN_RSEQ_INVALID_ADDRESS_TEST)
	/*
	 * We haven't found a reliable way to find an invalid address when
	 * running a 32bit userspace on a 64bit kernel, so only run this test
	 * on 64bit builds for the moment.
	 *
	 * Also exclude architectures that select
	 * CONFIG_ALTERNATE_USER_ADDRESS_SPACE where the kernel and userspace
	 * have their own address space and this failure can't happen.
	 */

	/* EFAULT */
	errno = 0;
	ret = sys_rseq((void *) -4096UL, 32, 0, RSEQ_SIG);
	errno_copy = errno;
	ok(ret != 0 && errno_copy == EFAULT, "Invalid address set errno to EFAULT (ret = %d, errno = %d)", ret, errno_copy);
#endif

	errno = 0;
	ret = sys_rseq(global_rseq, 32, 0, RSEQ_SIG);
	errno_copy = errno;
	ok(ret == 0, "Register rseq for the current thread (ret = %d, errno = %d)", ret, errno_copy);

	/* The current thread is registered. */

	/* EBUSY */
	errno = 0;
	ret = sys_rseq(global_rseq, 32, 0, RSEQ_SIG);
	errno_copy = errno;
	ok(ret != 0 && errno_copy == EBUSY, "Same registration set errno to EBUSY (ret = %d, errno = %d)", ret, errno_copy);

	/* EPERM */
	errno = 0;
	ret = sys_rseq(global_rseq, 32, RSEQ_ABI_FLAG_UNREGISTER, RSEQ_SIG + 1);
	errno_copy = errno;
	ok(ret != 0 && errno_copy == EPERM, "Unregistration with wrong RSEQ_SIG set errno to EPERM (ret = %d, errno = %d)", ret, errno_copy);

	errno = 0;
	ret = sys_rseq(global_rseq, 32, RSEQ_ABI_FLAG_UNREGISTER, RSEQ_SIG);
	errno_copy = errno;
	ok(ret == 0, "Unregister rseq for the current thread (ret = %d, errno = %d)", ret, errno_copy);

end:
	exit(exit_status());
}
