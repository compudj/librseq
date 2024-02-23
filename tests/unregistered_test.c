// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Michael Jeanson <mjeanson@efficios.com>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdint.h>

#include <rseq/rseq.h>

#include "tap.h"

#define NR_TESTS 5

/*
 * Check the state of the public symbols when the rseq syscall is available but
 * no thread has registered.
 */

int main(void)
{
	struct rseq_abi *rseq_abi;

	plan_tests(NR_TESTS);

	if (!rseq_available(RSEQ_AVAILABLE_QUERY_KERNEL)) {
		skip(NR_TESTS, "rseq syscall unavailable");
		goto end;
	}

	/* The syscall is available but the current thread is not registered. */

	ok(rseq_flags == 0, "rseq_flags prior to registration is 0 (%d)", rseq_flags);
	ok(rseq_size >= 32, "rseq_size prior to registration is 32 or greater (%d)", rseq_size);
	ok(rseq_feature_size >= 20, "rseq_feature_size prior to registration is 20 or greater (%d)", rseq_feature_size);
	ok(rseq_offset != 0, "rseq_offset prior to registration is not 0 (%td)", rseq_offset);

	rseq_abi = rseq_get_abi();
	ok((int32_t) rseq_abi->cpu_id == RSEQ_ABI_CPU_ID_UNINITIALIZED,
			"rseq->cpu_id is set to RSEQ_ABI_CPU_ID_UNINITIALIZED (%d)",
			(int32_t) rseq_abi->cpu_id);

end:
	exit(exit_status());
}
