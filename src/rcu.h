// SPDX-License-Identifier: MIT
/*
 * Copyright 2022 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef _RSEQ_RCU_H
#define _RSEQ_RCU_H

#include <sched.h>
#include <stdint.h>
#include <pthread.h>
#include <stdbool.h>
#include <poll.h>
#include <rseq/rseq.h>
#include <linux/futex.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/syscall.h>

#define RSEQ_CACHE_LINE_SIZE		256

struct rseq_rcu_percpu_count {
	uintptr_t begin;
	uintptr_t rseq_begin;
	uintptr_t end;
	uintptr_t rseq_end;
};

struct rseq_rcu_cpu_gp_state {
	struct rseq_rcu_percpu_count count[2];
} __attribute__((__aligned__(RSEQ_CACHE_LINE_SIZE)));

struct rseq_rcu_gp_state {
	struct rseq_rcu_cpu_gp_state *percpu_state;
	int nr_cpus;
	int32_t futex;
	unsigned int period;
	pthread_mutex_t gp_lock;
};

struct rseq_rcu_read_state {
	struct rseq_rcu_percpu_count *percpu_count;
};

extern unsigned int rseq_rcu_rseq_membarrier_available __attribute__((visibility("hidden")));

static inline
int futex(int32_t *uaddr, int op, int32_t val,
	const struct timespec *timeout, int32_t *uaddr2, int32_t val3)
{
	return syscall(__NR_futex, uaddr, op, val, timeout, uaddr2, val3);
}

/*
 * Wake-up rseq_rcu_wait_grace_period. Called concurrently from many
 * threads.
 */
static inline
void rseq_rcu_wake_up_gp(struct rseq_rcu_gp_state *gp_state)
{
	if (rseq_unlikely(__atomic_load_n(&gp_state->futex, __ATOMIC_RELAXED) == -1)) {
		__atomic_store_n(&gp_state->futex, 0, __ATOMIC_RELAXED);
		/* TODO: handle futex return values. */
		(void) futex(&gp_state->futex, FUTEX_WAKE, 1, NULL, NULL, 0);
	}
}

static inline
void rseq_rcu_read_begin(struct rseq_rcu_gp_state *gp_state, struct rseq_rcu_read_state *read_state)
{
	struct rseq_rcu_percpu_count *begin_cpu_count;
	struct rseq_rcu_cpu_gp_state *cpu_gp_state;
	unsigned int period;
	int cpu;

	period = __atomic_load_n(&gp_state->period, __ATOMIC_RELAXED);
	cpu_gp_state = &gp_state->percpu_state[0];
	read_state->percpu_count = begin_cpu_count = &cpu_gp_state->count[period];
	if (rseq_likely(rseq_rcu_rseq_membarrier_available &&
			!rseq_stride_inc__ptr(RSEQ_MO_RELAXED, RSEQ_PERCPU_CPU_ID,
					(intptr_t *)&begin_cpu_count->rseq_begin, sizeof(struct rseq_rcu_cpu_gp_state)))) {
		/*
		 * This compiler barrier (A) is paired with membarrier() at (C),
		 * (D), (E). It effectively upgrades this compiler barrier to a
		 * SEQ_CST fence with respect to the paired barriers.
		 *
		 * This barrier (A) ensures that the contents of the read-side
		 * critical section does not leak before the "begin" counter
		 * increment. It pairs with memory barriers (D) and (E).
		 *
		 * This barrier (A) also ensures that the "begin" increment is
		 * before the "end" increment. It pairs with memory barrier (C).
		 * It is redundant with barrier (B) for that purpose.
		 */
		rseq_barrier();
		return;
	}
	/* Fallback to atomic increment and SEQ_CST. */
	cpu = sched_getcpu();
	if (rseq_unlikely(cpu < 0))
		cpu = 0;
	cpu_gp_state = &gp_state->percpu_state[cpu];
	begin_cpu_count = &cpu_gp_state->count[period];
	(void) __atomic_add_fetch(&begin_cpu_count->begin, 1, __ATOMIC_SEQ_CST);
}

static inline
void rseq_rcu_read_end(struct rseq_rcu_gp_state *gp_state, struct rseq_rcu_read_state *read_state)
{
	struct rseq_rcu_percpu_count *begin_cpu_count = read_state->percpu_count;
	int cpu;

	/*
	 * This compiler barrier (B) is paired with membarrier() at (C),
	 * (D), (E). It effectively upgrades this compiler barrier to a
	 * SEQ_CST fence with respect to the paired barriers.
	 *
	 * This barrier (B) ensures that the contents of the read-side
	 * critical section does not leak after the "end" counter
	 * increment. It pairs with memory barriers (D) and (E).
	 *
	 * This barrier (B) also ensures that the "begin" increment is
	 * before the "end" increment. It pairs with memory barrier (C).
	 * It is redundant with barrier (A) for that purpose.
	 */
	rseq_barrier();
	if (rseq_likely(rseq_rcu_rseq_membarrier_available &&
			!rseq_stride_inc__ptr(RSEQ_MO_RELAXED, RSEQ_PERCPU_CPU_ID,
				(intptr_t *)&begin_cpu_count->rseq_end, sizeof(struct rseq_rcu_cpu_gp_state)))) {
		/*
		 * This barrier (F) is paired with membarrier()
		 * at (G). It orders increment of the begin/end
		 * counters before load/store to the futex.
		 */
		rseq_barrier();
		goto end;
	}
	/*
	 * Fallback to atomic increment and SEQ_CST.
	 * This barrier (F) implied by SEQ_CST is paired with SEQ_CST
	 * barrier or membarrier() at (G). It orders increment of the
	 * begin/end counters before load/store to the futex.
	 */
	/* Fallback to atomic increment and SEQ_CST. */
	cpu = sched_getcpu();
	if (rseq_unlikely(cpu < 0))
		cpu = 0;
	begin_cpu_count = (struct rseq_rcu_percpu_count *)((uintptr_t)begin_cpu_count + (cpu * sizeof(struct rseq_rcu_cpu_gp_state)));
	(void) __atomic_add_fetch(&begin_cpu_count->end, 1, __ATOMIC_SEQ_CST);
end:
	rseq_rcu_wake_up_gp(gp_state);
}

#define rseq_rcu_dereference(p) \
	__extension__ \
	({ \
		__typeof__(p) _____rseq_v = __atomic_load_n(&(p), __ATOMIC_CONSUME); \
		(_____rseq_v); \
	})

#define rseq_rcu_assign_pointer(p, v)	__atomic_store_n(&(p), v, __ATOMIC_RELEASE);

void rseq_rcu_wait_grace_period(struct rseq_rcu_gp_state *gp_state) __attribute__((visibility("hidden")));
void rseq_rcu_gp_init(struct rseq_rcu_gp_state *rcu_gp) __attribute__((visibility("hidden")));
void rseq_rcu_gp_exit(struct rseq_rcu_gp_state *rcu_gp) __attribute__((visibility("hidden")));

#endif /* _RSEQ_RCU_H */
