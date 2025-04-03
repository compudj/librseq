/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: 2025 Mathieu Desnoyers <mathieu.desnoyers@efficios.com> */

#ifndef _RSEQ_PERCPU_COUNTER_H
#define _RSEQ_PERCPU_COUNTER_H

#include <stdbool.h>

#include <rseq/mempool.h>
#include <rseq/rseq.h>
#include <urcu/arch.h>
#include <urcu/uatomic.h>

struct percpu_counter_level_item {
	unsigned long count;
} __attribute__((__aligned__(CAA_CACHE_LINE_SIZE)));

struct percpu_counter {
	unsigned long level0_bit_mask;
	uintptr_t __rseq_percpu *level0;

	unsigned int nr_levels;
	unsigned int nr_cpus;
	unsigned long batch_size;
	struct percpu_counter_level_item *items;
	unsigned long inaccuracy;	/* approximation imprecise within ± inaccuracy */
	long bias;			/* bias for counter_set */
};

# ifdef __cplusplus
extern "C" {
# endif

#ifdef COUNTER_DEBUG
#define counter_dbg_printf(...)		printf(__VA_ARGS__)
#else
#define counter_dbg_printf(...)
#endif

int counter_init(struct percpu_counter *counter, unsigned long batch_size);
void counter_destroy(struct percpu_counter *counter);
void counter_add_slowpath(struct percpu_counter *counter, long inc, int cpu);
long counter_precise_sum_unbiased(struct percpu_counter *counter);
long counter_precise_sum(struct percpu_counter *counter);
int counter_approximate_compare(struct percpu_counter *counter, long v);
int counter_precise_compare(struct percpu_counter *counter, long v);
void counter_set_bias(struct percpu_counter *counter, long bias);
void counter_set(struct percpu_counter *counter, long v);
unsigned long counter_inaccuracy(struct percpu_counter *counter);

/* Fast paths */

static inline
long counter_carry(long orig, long res, long inc, unsigned long bit_mask)
{
	if (inc < 0) {
		inc = -(-inc & ~(bit_mask - 1));
		/*
		 * xor bit_mask: underflow.
		 *
		 * If inc has bit set, decrement an additional bit if
		 * there is _no_ bit transition between orig and res.
		 * Else, inc has bit cleared, decrement an additional
		 * bit if there is a bit transition between orig and
		 * res.
		 */
		if ((inc ^ orig ^ res) & bit_mask)
			inc -= bit_mask;
	} else {
		inc &= ~(bit_mask - 1);
		/*
		 * xor bit_mask: overflow.
		 *
		 * If inc has bit set, increment an additional bit if
		 * there is _no_ bit transition between orig and res.
		 * Else, inc has bit cleared, increment an additional
		 * bit if there is a bit transition between orig and
		 * res.
		 */
		if ((inc ^ orig ^ res) & bit_mask)
			inc += bit_mask;
	}
	return inc;
}

static inline
void counter_add(struct percpu_counter *counter, long inc)
{
	unsigned long bit_mask = counter->level0_bit_mask;
	uintptr_t orig, res;
	int ret, cpu;

	if (!inc)
		return;
	do {
		cpu = rseq_cpu_start();
		orig = *rseq_percpu_ptr(counter->level0, cpu);
		ret = rseq_load_cbne_store__ptr(RSEQ_MO_RELAXED, RSEQ_PERCPU_CPU_ID,
				(intptr_t *)rseq_percpu_ptr(counter->level0, cpu),
				(intptr_t)orig, (intptr_t)(orig + inc), cpu);
	} while (ret);
	res = orig + inc;
	counter_dbg_printf("counter_add: inc: %ld, bit_mask: %lu, orig %lu, res %lu\n",
			   inc, bit_mask, (unsigned long)orig, (unsigned long)res);
	inc = counter_carry(orig, res, inc, bit_mask);
        if (inc)
		counter_add_slowpath(counter, inc, cpu);
}

static inline
long counter_approx_sum(struct percpu_counter *counter)
{
	return (long) (uatomic_load(&counter->items[counter->nr_cpus - 2].count, CMM_RELAXED) +
		uatomic_load(&counter->bias, CMM_RELAXED));
}

#ifdef __cplusplus
}
#endif

#endif  /* _RSEQ_PERCPU_COUNTER_H */
