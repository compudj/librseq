// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Michael Jeanson <mjeanson@efficios.com>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdint.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <syscall.h>
#include <unistd.h>

#include <rseq/rseq.h>

#include "tap.h"

#define NR_TESTS 4

/*
 * Check that a registration from a parent is still active in the child.
 */

static int sys_rseq(void *rseq_abi, uint32_t rseq_len,
		    int flags, uint32_t sig)
{
	return syscall(__NR_rseq, rseq_abi, rseq_len, flags, sig);
}

static
int test_child(void)
{
	int ret, errno_copy;
	struct rseq_abi *global_rseq = rseq_get_abi();

	/* The registration from the parent should survive in the child. */

	ret = sys_rseq(global_rseq, 32, 0, RSEQ_SIG);
	errno_copy = errno;
	ok(ret != 0 && errno_copy == EBUSY, "Registration is still active in the child");

	ok((int32_t) global_rseq->cpu_id >= 0,
			"rseq->cpu_id after registration is 0 or greater (%d)",
			(int32_t) global_rseq->cpu_id);

	return exit_status();
}

int main(void)
{
	pid_t pid;
	int ret, wstatus;
	struct rseq_abi *global_rseq = rseq_get_abi();

	/*
	 * Skip all tests if the rseq syscall is unavailable
	 */
	if (!rseq_available(RSEQ_AVAILABLE_QUERY_KERNEL)) {
		plan_skip_all("The rseq syscall is unavailable");
	}

	plan_tests(NR_TESTS);

	ret = rseq_register_current_thread();
	ok(ret == 0, "Registered rseq in the parent");

	ok((int32_t) global_rseq->cpu_id >= 0,
			"rseq->cpu_id after registration is 0 or greater (%d)",
			(int32_t) global_rseq->cpu_id);

	pid = fork();
	switch (pid) {
	case -1:
		perror("fork");
		ret = EXIT_FAILURE;
		break;
	case 0:
		/* Child */
		ret = test_child();
		break;
	default:
		/* Parent */
		ret = waitpid(pid, &wstatus, 0);
		if (ret < 0) {
			ret = EXIT_FAILURE;
		} else {
			/* Let the child handle the tap cleanup. */
			disable_cleanup();

			ret = WEXITSTATUS(wstatus);
		}
		break;
	}

	return ret;
}
