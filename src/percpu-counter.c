// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2025 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>

/*
 * Split Counters With Binary Tree Approximation Propagation
 *
 * * Propagation diagram when reaching batch size thresholds (± batch size):
 *
 * Example diagram for 8 CPUs:
 *
 * log2(8) = 3 levels
 *
 * At each level, each pair propagates its values to the next level when
 * reaching the batch size thresholds.
 *
 * Counters at levels 0, 1, 2 can be kept on a single byte (±128 range),
 * although it may be relevant to keep them on 32/64-bit counters for
 * simplicity. (complexity vs memory footprint tradeoff)
 *
 * Counter at level 3 can be kept on a 32/64-bit counter.
 *
 * Level 0:  0    1    2    3    4    5    6    7
 *           |   /     |   /     |   /     |   /
 *           |  /      |  /      |  /      |  /
 *           | /       | /       | /       | /
 * Level 1:  0         1         2         3
 *           |       /           |       /
 *           |    /              |    /
 *           | /                 | /
 * Level 2:  0                   1
 *           |               /
 *           |         /
 *           |   /
 * Level 3:  0
 *
 * * Approximation inaccuracy:
 *
 * BATCH(level N): Level N batch size.
 *
 * Example for BATCH(level 0) = 32.
 *
 * BATCH(level 0) =  32
 * BATCH(level 1) =  64
 * BATCH(level 2) = 128
 * BATCH(level N) = BATCH(level 0) * 2^N
 *
 *            per-counter     global
 *            inaccuracy      inaccuracy
 * Level 0:   [ -32 ..  +31]  ±256  (8 * 32)
 * Level 1:   [ -64 ..  +63]  ±256  (4 * 64)
 * Level 2:   [-128 .. +127]  ±256  (2 * 128)
 * Total:      ------         ±768  (log2(nr_cpus) * BATCH(level 0) * nr_cpus)
 *
 * -----
 *
 * Approximate Sum Carry Propagation
 *
 * Let's define a number of counter bits for each level, e.g.:
 *
 * log2(BATCH(level 0)) = log2(32) = 5
 *
 *               nr_bit        value_mask                      range
 * Level 0:      5 bits        v                             0 ..  +31
 * Level 1:      1 bit        (v & ~((1UL << 5) - 1))        0 ..  +63
 * Level 2:      1 bit        (v & ~((1UL << 6) - 1))        0 .. +127
 * Level 3:     57 bits       (v & ~((1UL << 7) - 1))        0 .. 2^64-1
 *
 * Note: Use a full 64-bit per-cpu counter at level 0 to allow precise sum.
 *
 * Note: Use cacheline aligned counters at levels above 0 to prevent false sharing.
 *       If memory footprint is an issue, a specialized allocator could be used
 *       to eliminate padding.
 *
 * Example with expanded values:
 *
 * counter_add(counter, inc):
 *
 *         if (!inc)
 *                 return;
 *
 *         res = percpu_add_return(counter @ Level 0, inc);
 *         orig = res - inc;
 *         if (inc < 0) {
 *                 inc = -(-inc & ~0b00011111);  // Clear used bits
 *                 // xor bit 5: underflow
 *                 if ((inc ^ orig ^ res) & 0b00100000)
 *                         inc -= 0b00100000;
 *         } else {
 *                 inc &= ~0b00011111;           // Clear used bits
 *                 // xor bit 5: overflow
 *                 if ((inc ^ orig ^ res) & 0b00100000)
 *                         inc += 0b00100000;
 *         }
 *         if (!inc)
 *                 return;
 *
 *         res = atomic_add_return(counter @ Level 1, inc);
 *         orig = res - inc;
 *         if (inc < 0) {
 *                 inc = -(-inc & ~0b00111111);  // Clear used bits
 *                 // xor bit 6: underflow
 *                 if ((inc ^ orig ^ res) & 0b01000000)
 *                         inc -= 0b01000000;
 *         } else {
 *                 inc &= ~0b00111111;           // Clear used bits
 *                 // xor bit 6: overflow
 *                 if ((inc ^ orig ^ res) & 0b01000000)
 *                         inc += 0b01000000;
 *         }
 *         if (!inc)
 *                 return;
 *
 *         res = atomic_add_return(counter @ Level 2, inc);
 *         orig = res - inc;
 *         if (inc < 0) {
 *                 inc = -(-inc & ~0b01111111);  // Clear used bits
 *                 // xor bit 7: underflow
 *                 if ((inc ^ orig ^ res) & 0b10000000)
 *                         inc -= 0b10000000;
 *         } else {
 *                 inc &= ~0b01111111;           // Clear used bits
 *                 // xor bit 7: overflow
 *                 if ((inc ^ orig ^ res) & 0b10000000)
 *                         inc += 0b10000000;
 *         }
 *         if (!inc)
 *                 return;
 *
 *         atomic_add(counter @ Level 3, inc);
 */

#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <stdio.h>

#include <rseq/percpu-counter.h>
#include "rseq-utils.h"
#include "smp.h"

static struct rseq_mempool *mempool;

int counter_init(struct percpu_counter *counter, unsigned long batch_size)
{
	int nr_cpus;

	/* Batch size must be power of 2 */
	if (!batch_size || (batch_size & (batch_size - 1)))
		return -EINVAL;
	nr_cpus = get_possible_cpus_array_len();
	if (!nr_cpus)
		return -EINVAL;
	counter->nr_levels = rseq_get_count_order_ulong(nr_cpus);
	counter->nr_cpus = 1UL << counter->nr_levels;
	counter->batch_size = batch_size;
	counter->level0_bit_mask = 1UL << rseq_get_count_order_ulong(batch_size);
	counter->inaccuracy = counter->nr_levels * batch_size * counter->nr_cpus;
	counter->bias = 0;
	counter->level0 = (uintptr_t __rseq_percpu *)rseq_mempool_percpu_zmalloc(mempool);
	if (!counter->level0)
		return -ENOMEM;
	counter->items = calloc(counter->nr_cpus - 1,
				sizeof(struct percpu_counter_level_item));
	if (!counter->items) {
		rseq_mempool_percpu_free(counter->level0);
		return -ENOMEM;
	}
	return 0;
}

void counter_destroy(struct percpu_counter *counter)
{
	rseq_mempool_percpu_free(counter->level0);
	free(counter->items);
}

void counter_add_slowpath(struct percpu_counter *counter, long inc, int cpu)
{
	struct percpu_counter_level_item *item = counter->items;
	unsigned int level_items = counter->nr_cpus >> 1;
	unsigned int level, nr_levels = counter->nr_levels;
	unsigned long bit_mask = counter->level0_bit_mask;

	for (level = 1; level < nr_levels; level++) {
		unsigned long orig, res;
		unsigned long *count = &item[cpu & (level_items - 1)].count;

		bit_mask <<= 1;
		res = uatomic_add_return(count, inc, CMM_RELAXED);
		orig = res - inc;
		counter_dbg_printf("counter_add_slowpath: level %d, inc: %ld, bit_mask: %lu, orig %lu, res %lu\n",
				   level, inc, bit_mask, orig, res);
		inc = counter_carry(orig, res, inc, bit_mask);
		item += level_items;
		level_items >>= 1;
		if (!inc)
			return;
	}
	counter_dbg_printf("counter_add_slowpath: last level add %ld\n", inc);
	uatomic_add(&item->count, inc, CMM_RELAXED);
}

/*
 * Precise sum
 * Keep "long" counters per-cpu, and perform the sum of all per-cpu
 * counters.
 */
long counter_precise_sum_unbiased(struct percpu_counter *counter)
{
	unsigned long sum = 0;
	int nr_cpus, cpu;

	nr_cpus = get_possible_cpus_array_len();
	if (!nr_cpus)
		abort();

	for (cpu = 0; cpu < nr_cpus; cpu++)
		sum += *rseq_percpu_ptr(counter->level0, cpu);
	return (long) sum;
}

long counter_precise_sum(struct percpu_counter *counter)
{
	return counter_precise_sum_unbiased(counter) + uatomic_load(&counter->bias, CMM_RELAXED);
}

/*
 * Do an approximate comparison of a counter against a given value.
 * Return 1 if the value is greater than counter,
 * Return -1 if the value lower than counter,
 * Return 0 if the value is within the inaccuracy range of the counter.
 */
int counter_approximate_compare(struct percpu_counter *counter, long v)
{
	long count = counter_approx_sum(counter);

	if (labs(v - count) <= counter->inaccuracy)
		return 0;
	if (v > count)
		return 1;
	return -1;
}

/*
 * Compare counter against a given value.
 * Return 1 if the value is greater than counter,
 * Return -1 if the value lower than counter,
 * Return 0 if the value is equal to the counter.
 */
int counter_precise_compare(struct percpu_counter *counter, long v)
{
	long count = counter_approx_sum(counter);

	if (labs(v - count) <= counter->inaccuracy)
		count = counter_precise_sum(counter);
	if (v > count)
		return 1;
	if (v < count)
		return -1;
	return 0;
}

void counter_set_bias(struct percpu_counter *counter, long bias)
{
	uatomic_set(&counter->bias, bias, CMM_RELAXED);
}

void counter_set(struct percpu_counter *counter, long v)
{
	counter_set_bias(counter, v - counter_precise_sum_unbiased(counter));
}

unsigned long counter_inaccuracy(struct percpu_counter *counter)
{
	return counter->inaccuracy;
}

static __attribute__((constructor))
void init(void)
{
	struct rseq_mempool_attr *attr;
	int ret;

	attr = rseq_mempool_attr_create();
	if (!attr) {
		perror("rseq_mempool_attr_create");
		abort();
	}
	ret = rseq_mempool_attr_set_percpu(attr, RSEQ_MEMPOOL_STRIDE, 0);
	if (ret) {
		perror("rseq_mempool_attr_set_percpu");
		abort();
	}
	mempool = rseq_mempool_create("percpu_counter", sizeof(long), attr);
	if (!mempool) {
		perror("rseq_mempool_create");
		abort();
	}
	rseq_mempool_attr_destroy(attr);
}

static __attribute__((destructor))
void fini(void)
{
	int ret;

	ret = rseq_mempool_destroy(mempool);
	if (ret) {
		perror("rseq_mempool_destroy");
		abort();
	}
}
