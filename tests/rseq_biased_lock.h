// SPDX-License-Identifier: LGPL-2.1

#ifndef _RSEQ_BIASED_LOCK_H
#define _RSEQ_BIASED_LOCK_H

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

#define RSEQ_MUTEX_MAX_BUSY_LOOP	100

enum rseq_biased_lock_state {
	RSEQ_BIASED_LOCK_STATE_ST = 0,		/* Single thread user. */
	RSEQ_BIASED_LOCK_STATE_MT_STARTED = 1,	/* Transition to multi-threads users. */
	RSEQ_BIASED_LOCK_STATE_MT_READY = 2,	/* Multi-threads users. */
};

struct rseq_biased_lock {
	intptr_t owner;	/* thread_pointer of thread holding the lock. */
	intptr_t state;	/* enum rseq_biased_lock_state */
	intptr_t st_tp;	/* thread_pointer of single-thread user. */
	intptr_t nest;	/* nesting level (recursive lock). */
};

int sys_membarrier(int cmd, int flags, int cpu_id);
bool membarrier_private_expedited_rseq_available(void);
int rseq_membarrier_expedited(__attribute__ ((unused)) int cpu);
intptr_t rseq_biased_lock_try_set_fast_thread(struct rseq_biased_lock *lock);
intptr_t rseq_biased_lock_try_clear_fast_thread(struct rseq_biased_lock *lock);
void rseq_biased_lock_mt_slowpath(struct rseq_biased_lock *lock, intptr_t tp);
void rseq_biased_lock_mt_ready_slowpath(struct rseq_biased_lock *lock,
			intptr_t biased_lock_state);

#define DEFINE_RSEQ_BIASED_LOCK(_lock) \
	struct rseq_biased_lock _lock = { \
		.owner = 0, \
		.state = RSEQ_BIASED_LOCK_STATE_ST, \
		.st_tp = 0, \
		.nest = 0, \
	}

static inline
void rseq_biased_lock_init(struct rseq_biased_lock *lock)
{
	lock->owner = 0;
	lock->state = RSEQ_BIASED_LOCK_STATE_ST;
	lock->st_tp = 0;
	lock->nest = 0;
}

static inline
void rseq_biased_lock_mt(struct rseq_biased_lock *lock, intptr_t tp)
{
	intptr_t expected = 0;

	if (__atomic_compare_exchange_n(&lock->owner, &expected, tp, false,
					__ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
		return;
	rseq_biased_lock_mt_slowpath(lock, tp);
}

static inline
void rseq_biased_lock_mt_remote(struct rseq_biased_lock *lock, intptr_t tp)
{
	intptr_t biased_lock_state;

	biased_lock_state = __atomic_load_n(&lock->state, __ATOMIC_RELAXED);
	if (biased_lock_state != RSEQ_BIASED_LOCK_STATE_MT_READY)
		rseq_biased_lock_mt_ready_slowpath(lock, biased_lock_state);
	rseq_biased_lock_mt(lock, tp);
}

static inline
void rseq_biased_lock_fast(struct rseq_biased_lock *lock, intptr_t tp)
{
	int ret;

retry:
	ret = rseq_cmpeqv1_storev2(RSEQ_MO_RELAXED, &lock->state,
				   RSEQ_BIASED_LOCK_STATE_ST,
				   &lock->owner, tp);
	switch (ret) {
	case 0:	/*
		 * Success. Enter lock critical section without acquire
		 * semantic.
		 */
		return;
	case 1:		/* state != RSEQ_BIASED_LOCK_STATE_ST */
		rseq_biased_lock_mt(lock, tp);
		return;
	case -1:
		goto retry;
	}
}

static inline
intptr_t rseq_biased_lock_get_fast_thread(struct rseq_biased_lock *lock)
{
	return __atomic_load_n(&lock->st_tp, __ATOMIC_RELAXED);
}

static inline
void rseq_biased_lock(struct rseq_biased_lock *lock)
{
	intptr_t tp = (intptr_t) rseq_thread_pointer();

	if (__atomic_load_n(&lock->owner, __ATOMIC_RELAXED) == tp) {
		lock->nest++;
		return;
	}
	if (rseq_biased_lock_get_fast_thread(lock) == tp)
		rseq_biased_lock_fast(lock, tp);
	else
		rseq_biased_lock_mt_remote(lock, tp);
}

static inline
void rseq_biased_unlock_store_release(struct rseq_biased_lock *lock)
{
	__atomic_store_n(&lock->owner, 0, __ATOMIC_RELEASE);
}

#ifdef RSEQ_ARCH_TSO
/*
 * TSO store-release is a store. Use it as a fast-path.
 */
static inline
void rseq_biased_unlock(struct rseq_biased_lock *lock)
{
	rseq_biased_unlock_store_release(lock);
}
#else	/* #ifdef RSEQ_ARCH_TSO */
static inline
void rseq_biased_unlock_fast(struct rseq_biased_lock *lock)
{
	int ret;

retry:
	ret = rseq_cmpeqv1_storev2(RSEQ_MO_RELAXED, &lock->state,
				   RSEQ_BIASED_LOCK_STATE_ST,
				   &lock->owner, 0);
	switch (ret) {
	case 0:	/*
		 * Success. Exit critical section without release
		 * semantic.
		 */
		return;
	case 1:		/* state != RSEQ_BIASED_LOCK_STATE_ST */
		rseq_biased_unlock_store_release(lock);
		return;
	case -1:
		goto retry;
	}
}

//TODO: integrate with sys_futex and wakeup oldest waiter.
static inline
void rseq_biased_unlock(struct rseq_biased_lock *lock)
{
	intptr_t tp = (intptr_t) rseq_thread_pointer();

	assert(lock->owner == tp);
	if (lock->nest > 0) {
		lock->nest--;
		return;
	}
	if (rseq_biased_lock_get_fast_thread(lock) == tp)
		rseq_biased_unlock_fast(lock);
	else
		rseq_biased_unlock_store_release(lock);
}
#endif	/* #else #ifdef RSEQ_ARCH_TSO */

#endif /* _RSEQ_BIASED_LOCK_H */
