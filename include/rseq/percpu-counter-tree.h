/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: 2025 Mathieu Desnoyers <mathieu.desnoyers@efficios.com> */

#ifndef _RSEQ_PERCPU_COUNTER_TREE_H
#define _RSEQ_PERCPU_COUNTER_TREE_H

#include <stdbool.h>

#include <rseq/mempool.h>
#include <rseq/rseq.h>

struct percpu_counter_tree {
	/* Fast-path fields. */
	uintptr_t __rseq_percpu *level0;
	unsigned long level0_bit_mask;
	union {
		uintptr_t *p;
		unsigned long *l;
	} approx_sum;
	long bias;			/* bias for counter_set */

	/* Slow-path fields. */
	unsigned long __rseq_percpu *items;
	unsigned long batch_size;
	unsigned long inaccuracy;	/* approximation imprecise within ± inaccuracy */
};

# ifdef __cplusplus
extern "C" {
# endif

#ifdef COUNTER_DEBUG
#define percpu_counter_tree_dbg_printf(...)		printf(__VA_ARGS__)
#else
#define percpu_counter_tree_dbg_printf(...)
#endif

int percpu_counter_tree_init(struct percpu_counter_tree *counter, unsigned long batch_size);
void percpu_counter_tree_destroy(struct percpu_counter_tree *counter);
void percpu_counter_tree_add_slowpath(struct percpu_counter_tree *counter, long inc, int cpu);
long percpu_counter_tree_precise_sum(struct percpu_counter_tree *counter);
int percpu_counter_tree_approximate_compare(struct percpu_counter_tree *a, struct percpu_counter_tree *b);
int percpu_counter_tree_approximate_compare_value(struct percpu_counter_tree *counter, long v);
int percpu_counter_tree_precise_compare(struct percpu_counter_tree *a, struct percpu_counter_tree *b);
int percpu_counter_tree_precise_compare_value(struct percpu_counter_tree *counter, long v);
void percpu_counter_tree_set_bias(struct percpu_counter_tree *counter, long bias);
void percpu_counter_tree_set(struct percpu_counter_tree *counter, long v);
unsigned long percpu_counter_tree_inaccuracy(struct percpu_counter_tree *counter);
unsigned int percpu_counter_get_depth(struct percpu_counter_tree *counter);

/* Fast paths */

static inline
long percpu_counter_tree_carry(long orig, long res, long inc, unsigned long bit_mask)
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
void percpu_counter_tree_add(struct percpu_counter_tree *counter, long inc)
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
	percpu_counter_tree_dbg_printf("%s: inc: %ld, bit_mask: %lu, orig %lu, res %lu\n",
			__func__, inc, bit_mask, (unsigned long)orig, (unsigned long)res);
	inc = percpu_counter_tree_carry(orig, res, inc, bit_mask);
        if (!inc)
		return;
	percpu_counter_tree_add_slowpath(counter, inc, cpu);
}

static inline
long percpu_counter_tree_approximate_sum(struct percpu_counter_tree *counter)
{
	unsigned long v;

	if (!counter->level0_bit_mask)
		v = (unsigned long)RSEQ_READ_ONCE(*counter->approx_sum.p);
	else
		v = __atomic_load_n(counter->approx_sum.l, __ATOMIC_RELAXED);
	return (long) (v + (unsigned long)__atomic_load_n(&counter->bias, __ATOMIC_RELAXED));
}

#ifdef __cplusplus
}
#endif

#endif  /* _RSEQ_PERCPU_COUNTER_TREE_H */
