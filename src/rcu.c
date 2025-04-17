// SPDX-License-Identifier: MIT
/*
 * Copyright 2022 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#include <sched.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <stdbool.h>
#include <poll.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <linux/membarrier.h>

#include "rcu.h"
#include "smp.h"

/*
 * If both rseq (with glibc support) and membarrier system calls are
 * available, use them to replace barriers and atomics on the fast-path.
 */
unsigned int rseq_rcu_rseq_membarrier_available;

static int
membarrier(int cmd, unsigned int flags, int cpu_id)
{
	return syscall(__NR_membarrier, cmd, flags, cpu_id);
}

/*
 * Wait/wakeup scheme with single waiter/many wakers.
 */
static
void wait_gp_prepare(struct rseq_rcu_gp_state *gp_state)
{
	__atomic_store_n(&gp_state->futex, -1, __ATOMIC_RELAXED);
	/*
	 * This memory barrier (H) pairs with memory barrier (F). It
	 * orders store to futex before load of RCU reader's counter
	 * state, thus ensuring that load of RCU reader's counters does
	 * not leak outside of futex state=-1.
	 */
	if (rseq_rcu_rseq_membarrier_available) {
		if (membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0, 0)) {
			perror("membarrier");
			abort();
		}
	} else {
		__atomic_thread_fence(__ATOMIC_SEQ_CST);
	}
}

static
void wait_gp_end(struct rseq_rcu_gp_state *gp_state)
{
	/*
	 * This memory barrier (G) pairs with memory barrier (F). It
	 * orders load of RCU reader's counter state before storing the
	 * futex value, thus ensuring that load of RCU reader's counters
	 * does not leak outside of futex state=-1.
	 */
	if (rseq_rcu_rseq_membarrier_available) {
		if (membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0, 0)) {
			perror("membarrier");
			abort();
		}
	} else {
		__atomic_thread_fence(__ATOMIC_SEQ_CST);
	}
	__atomic_store_n(&gp_state->futex, 0, __ATOMIC_RELAXED);
}

static
void wait_gp(struct rseq_rcu_gp_state *gp_state)
{
	/*
	 * This memory barrier (G) pairs with memory barrier (F). It
	 * orders load of RCU reader's counter state before loading the
	 * futex value.
	 */
	if (rseq_rcu_rseq_membarrier_available) {
		if (membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0, 0)) {
			perror("membarrier");
			abort();
		}
	} else {
		__atomic_thread_fence(__ATOMIC_SEQ_CST);
	}
	while (__atomic_load_n(&gp_state->futex, __ATOMIC_RELAXED) == -1) {
		if (!futex(&gp_state->futex, FUTEX_WAIT, -1, NULL, NULL, 0)) {
			/*
			 * May be awakened by either spurious wake up or
			 * because the state is now as expected.
			 */
			continue;
		}
		switch (errno) {
		case EWOULDBLOCK:
			/* Value already changed. */
			return;
		case EINTR:
			/* Retry if interrupted by signal. */
			break;	/* Get out of switch. */
		default:
			/* Unexpected error. */
			abort();
		}
	}
	return;
}

/* active_readers is an input/output parameter. */
static
void check_active_readers(struct rseq_rcu_gp_state *gp_state, bool *active_readers)
{
	uintptr_t sum[2] = { 0, 0 };	/* begin - end */
	int i;

	for (i = 0; i < gp_state->nr_cpus; i++) {
		struct rseq_rcu_cpu_gp_state *cpu_state = &gp_state->percpu_state[i];

		if (active_readers[0]) {
			sum[0] -= __atomic_load_n(&cpu_state->count[0].end, __ATOMIC_RELAXED);
			sum[0] -= __atomic_load_n(&cpu_state->count[0].rseq_end, __ATOMIC_RELAXED);
		}
		if (active_readers[1]) {
			sum[1] -= __atomic_load_n(&cpu_state->count[1].end, __ATOMIC_RELAXED);
			sum[1] -= __atomic_load_n(&cpu_state->count[1].rseq_end, __ATOMIC_RELAXED);
		}
	}

	/*
	 * This memory barrier (C) pairs with either of memory barriers
	 * (A) or (B) (one is sufficient).
	 *
	 * Read end counts before begin counts. Reading "end" before
	 * "begin" counts ensures we never see an "end" without having
	 * seen its associated "begin", because "begin" is always
	 * incremented before "end", as guaranteed by memory barriers
	 * (A) or (B).
	 */
	if (rseq_rcu_rseq_membarrier_available) {
		if (membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0, 0)) {
			perror("membarrier");
			abort();
		}
	} else {
		__atomic_thread_fence(__ATOMIC_SEQ_CST);
	}

	for (i = 0; i < gp_state->nr_cpus; i++) {
		struct rseq_rcu_cpu_gp_state *cpu_state = &gp_state->percpu_state[i];

		if (active_readers[0]) {
			sum[0] += __atomic_load_n(&cpu_state->count[0].begin, __ATOMIC_RELAXED);
			sum[0] += __atomic_load_n(&cpu_state->count[0].rseq_begin, __ATOMIC_RELAXED);
		}
		if (active_readers[1]) {
			sum[1] += __atomic_load_n(&cpu_state->count[1].begin, __ATOMIC_RELAXED);
			sum[1] += __atomic_load_n(&cpu_state->count[1].rseq_begin, __ATOMIC_RELAXED);
		}
	}
	if (active_readers[0])
		active_readers[0] = sum[0];
	if (active_readers[1])
		active_readers[1] = sum[1];
}

/*
 * Wait for previous period to have no active readers.
 *
 * active_readers is an input/output parameter.
 */
static
void wait_for_prev_period_readers(struct rseq_rcu_gp_state *gp_state, bool *active_readers)
{
	unsigned int prev_period = gp_state->period ^ 1;

	/*
	 * If a prior active readers scan already observed that no
	 * readers are present for the previous period, there is no need
	 * to scan again.
	 */
	if (!active_readers[prev_period])
		return;
	/*
	 * Wait for the sum of CPU begin/end counts to match for the
	 * previous period.
	 */
	for (;;) {
		wait_gp_prepare(gp_state);
		check_active_readers(gp_state, active_readers);
		if (!active_readers[prev_period]) {
			wait_gp_end(gp_state);
			break;
		}
		wait_gp(gp_state);
	}
}

/*
 * The grace period completes when it observes that there are no active
 * readers within each of the periods.
 *
 * The active_readers state is initially true for each period, until the
 * grace period observes that no readers are present for each given
 * period, at which point the active_readers state becomes false.
 */
void rseq_rcu_wait_grace_period(struct rseq_rcu_gp_state *gp_state)
{
	bool active_readers[2] = { true, true };

	/*
	 * This memory barrier (D) pairs with memory barriers (A) and
	 * (B) on the read-side.
	 *
	 * It orders prior loads and stores before the "end"/"begin"
	 * reader state loads. In other words, it orders prior loads and
	 * stores before observation of active readers quiescence,
	 * effectively ensuring that read-side critical sections which
	 * exist after the grace period completes are ordered after
	 * loads and stores performed before the grace period.
	 */
	if (rseq_rcu_rseq_membarrier_available) {
		if (membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0, 0)) {
			perror("membarrier");
			abort();
		}
	} else {
		__atomic_thread_fence(__ATOMIC_SEQ_CST);
	}

	/*
	 * First scan through all cpus, for both period. If no readers
	 * are accounted for, we have observed quiescence and can
	 * complete the grace period immediately.
	 */
	check_active_readers(gp_state, active_readers);
	if (!active_readers[0] && !active_readers[1])
		goto end;

	pthread_mutex_lock(&gp_state->gp_lock);

	wait_for_prev_period_readers(gp_state, active_readers);
	/*
	 * If the reader scan detected that there are no readers in the
	 * current period as well, we can complete the grace period
	 * immediately.
	 */
	if (!active_readers[gp_state->period])
		goto unlock;

	/* Flip period: 0 -> 1, 1 -> 0. */
	(void) __atomic_xor_fetch(&gp_state->period, 1, __ATOMIC_RELAXED);

	wait_for_prev_period_readers(gp_state, active_readers);
unlock:
	pthread_mutex_unlock(&gp_state->gp_lock);
end:
	/*
	 * This memory barrier (E) pairs with memory barriers (A) and
	 * (B) on the read-side.
	 *
	 * It orders the "end"/"begin" reader state loads before
	 * following loads and stores. In other words, it orders
	 * observation of active readers quiescence before following
	 * loads and stores, effectively ensuring that read-side
	 * critical sections which existed prior to the grace period
	 * are ordered before loads and stores performed after the grace
	 * period.
	 */
	if (rseq_rcu_rseq_membarrier_available) {
		if (membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0, 0)) {
			perror("membarrier");
			abort();
		}
	} else {
		__atomic_thread_fence(__ATOMIC_SEQ_CST);
	}
}

void rseq_rcu_gp_init(struct rseq_rcu_gp_state *rcu_gp)
{
	bool has_membarrier = false, has_rseq = false;

	memset(rcu_gp, 0, sizeof(*rcu_gp));
	rcu_gp->nr_cpus = get_possible_cpus_array_len();
	if (!rcu_gp->nr_cpus)
		abort();
	pthread_mutex_init(&rcu_gp->gp_lock, NULL);
	rcu_gp->percpu_state = (struct rseq_rcu_cpu_gp_state *)
		calloc(rcu_gp->nr_cpus, sizeof(struct rseq_rcu_cpu_gp_state));
	if (!rcu_gp->percpu_state)
		abort();
	if (!membarrier(MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED, 0, 0))
		has_membarrier = true;
	if (rseq_available(RSEQ_AVAILABLE_QUERY_LIBC))
		has_rseq = true;
	if (has_membarrier && has_rseq)
		rseq_rcu_rseq_membarrier_available = 1;
}

void rseq_rcu_gp_exit(struct rseq_rcu_gp_state *rcu_gp)
{
	rseq_prepare_unload();
	pthread_mutex_destroy(&rcu_gp->gp_lock);
	free(rcu_gp->percpu_state);
}
