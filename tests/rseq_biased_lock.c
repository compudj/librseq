// SPDX-License-Identifier: LGPL-2.1

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <poll.h>
#include <syscall.h>
#include <linux/version.h>
#include <linux/membarrier.h>

#include <rseq/rseq.h>

#include "rseq_biased_lock.h"

/*
 * Biased locks with RSEQ
 *
 * A single thread is designed as the "biased fast" thread. As long as
 * only this thread accesses the lock, it can acquire and release the
 * lock with loads and stores (no barriers, no atomics, no
 * acquire/release). As soon as other threads need to touch this lock,
 * they go through a state-machine which ensures that at least one
 * membarrier RSEQ-fence is issued before attempting to acquire the lock
 * with a CAS. The fast thread grabs the lock within a RSEQ critical
 * section to check whether multi-threaded synchronization is required.
*/

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,10,0)
enum {
	MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ			= (1 << 7),
	MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ		= (1 << 8),
};

enum {
	MEMBARRIER_CMD_FLAG_CPU		= (1 << 0),
};
#endif

int sys_membarrier(int cmd, int flags, int cpu_id)
{
	return syscall(__NR_membarrier, cmd, flags, cpu_id);
}

bool membarrier_private_expedited_rseq_available(void)
{
	int status = sys_membarrier(MEMBARRIER_CMD_QUERY, 0, 0);

	if (status < 0) {
		perror("membarrier");
		return false;
	}
	if (!(status & MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ))
		return false;
	return true;
}

/*
 * Membarrier does not currently support targeting a mm_cid, so
 * issue the barrier on all cpus.
 */
int rseq_membarrier_expedited(__attribute__ ((unused)) int cpu)
{
	return sys_membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ,
			      0, 0);
}

/*
 * Try to set lock fast thread to current thread.
 * Return NULL on success, else return current fast thread pointer on
 * failure.
 */
intptr_t rseq_biased_lock_try_set_fast_thread(struct rseq_biased_lock *lock)
{
	intptr_t expected = 0;
	intptr_t self = (intptr_t) rseq_thread_pointer();

	if (!__atomic_compare_exchange_n(&lock->st_tp, &expected, self, false,
					__ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
		return expected;	/* Failure. Return st-user tp. */
	return 0;			/* Success. */
}

/*
 * Try to clear lock fast thread if it belongs to the current thread.
 * Return NULL on success, else return current fast thread pointer on
 * failure.
 */
intptr_t rseq_biased_lock_try_clear_fast_thread(struct rseq_biased_lock *lock)
{
	intptr_t expected = (intptr_t) rseq_thread_pointer();

	if (!__atomic_compare_exchange_n(&lock->st_tp, &expected, 0, false,
					__ATOMIC_RELEASE, __ATOMIC_RELAXED))
		return expected;	/* Failure. Return st-user tp. */
	return 0;			/* Success. */
}

void rseq_biased_lock_mt_slowpath(struct rseq_biased_lock *lock)
{
	int i = 0;

	for (;;) {
		intptr_t expected = 0;

		if (__atomic_compare_exchange_n(&lock->owner, &expected, 1, false,
						__ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
			break;
		if (i < RSEQ_MUTEX_MAX_BUSY_LOOP) {
			rseq_barrier();			/* busy-wait, e.g. cpu_relax(). */
			i++;
		} else {
			//TODO: Enqueue waiter in a wait-queue, and integrate
			//with sys_futex rather than waiting for 10ms.
			(void) poll(NULL, 0, 10);	/* wait 10ms */
		}
	}
}

void rseq_biased_lock_mt_ready_slowpath(struct rseq_biased_lock *lock, intptr_t biased_lock_state)
{
	switch (biased_lock_state) {
	case RSEQ_BIASED_LOCK_STATE_ST:
		(void) __atomic_compare_exchange_n(&lock->state, &biased_lock_state,
						   RSEQ_BIASED_LOCK_STATE_MT_STARTED,
						   false, __ATOMIC_RELAXED, __ATOMIC_RELAXED);
		if (biased_lock_state == RSEQ_BIASED_LOCK_STATE_MT_READY)
			break;
		/* Fallthrough */
	case RSEQ_BIASED_LOCK_STATE_MT_STARTED:
		if (rseq_membarrier_expedited(-1)) {
			perror("sys_membarrier");
			abort();
		}
		__atomic_store_n(&lock->state, RSEQ_BIASED_LOCK_STATE_MT_READY,
				 __ATOMIC_RELAXED);
		/* All threads can now be considered as slow path. */
		__atomic_store_n(&lock->st_tp, 0, __ATOMIC_RELAXED);
		break;
	case RSEQ_BIASED_LOCK_STATE_MT_READY:
		break;
	}
}

