// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2025 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>

/*
 * Split Counters With Tree Approximation Propagation
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
 * Note: Use a full 32/64-bit per-cpu counter at level 0 to allow precise sum.
 *
 * Note: Either use cacheline aligned counters at levels above 0 to
 *       prevent false sharing, or use a strided memory allocator
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

#include <rseq/percpu-counter-tree.h>
#include "rseq-utils.h"
#include "smp.h"

#define MAX_NR_LEVELS 5

struct counter_config {
	unsigned int nr_items;
	unsigned char nr_levels;
	unsigned char n_arity_order[MAX_NR_LEVELS];
};

/*
 * nr_items is the number of items in the tree for levels 1 to and
 * including the final level (approximate sum). It excludes the level 0
 * per-cpu counters.
 */
static const struct counter_config per_nr_cpu_order_config[] = {
	[0] =	{ .nr_items = 1,	.nr_levels = 0,		.n_arity_order = { 0 } },
	[1] =	{ .nr_items = 3,	.nr_levels = 1,		.n_arity_order = { 1 } },
	[2] =	{ .nr_items = 3,	.nr_levels = 2,		.n_arity_order = { 1, 1 } },
	[3] =	{ .nr_items = 7,	.nr_levels = 3,		.n_arity_order = { 1, 1, 1 } },
	[4] =	{ .nr_items = 7,	.nr_levels = 3,		.n_arity_order = { 2, 1, 1 } },
	[5] =	{ .nr_items = 11,	.nr_levels = 3,		.n_arity_order = { 2, 2, 1 } },
	[6] =	{ .nr_items = 21,	.nr_levels = 3,		.n_arity_order = { 2, 2, 2 } },
	[7] =	{ .nr_items = 21,	.nr_levels = 3,		.n_arity_order = { 3, 2, 2 } },
	[8] =	{ .nr_items = 37,	.nr_levels = 3,		.n_arity_order = { 3, 3, 2 } },
	[9] =	{ .nr_items = 73,	.nr_levels = 3,		.n_arity_order = { 3, 3, 3 } },
	[10] =	{ .nr_items = 149,	.nr_levels = 4,		.n_arity_order = { 3, 3, 2, 2 } },
	[11] =	{ .nr_items = 293,	.nr_levels = 4,		.n_arity_order = { 3, 3, 3, 2 } },
	[12] =	{ .nr_items = 585,	.nr_levels = 4,		.n_arity_order = { 3, 3, 3, 3 } },
	[13] =	{ .nr_items = 1173,	.nr_levels = 5,		.n_arity_order = { 3, 3, 3, 2, 2 } },
	[14] =	{ .nr_items = 2341,	.nr_levels = 5,		.n_arity_order = { 3, 3, 3, 3, 2 } },
	[15] =	{ .nr_items = 4681,	.nr_levels = 5,		.n_arity_order = { 3, 3, 3, 3, 3 } },
	[16] =	{ .nr_items = 4681,	.nr_levels = 5,		.n_arity_order = { 4, 3, 3, 3, 3 } },
	[17] =	{ .nr_items = 8777,	.nr_levels = 5,		.n_arity_order = { 4, 4, 3, 3, 3 } },
	[18] =	{ .nr_items = 17481,	.nr_levels = 5,		.n_arity_order = { 4, 4, 4, 3, 3 } },
	[19] =	{ .nr_items = 34953,	.nr_levels = 5,		.n_arity_order = { 4, 4, 4, 4, 3 } },
	[20] =	{ .nr_items = 69905,	.nr_levels = 5,		.n_arity_order = { 4, 4, 4, 4, 4 } },
};

static const struct counter_config *counter_config;

/*
 * The percpu_mempool contains level 0 counters. It is indexed per-cpu.
 *
 * The item_mempool contains intermediate counters for levels 1 to N.
 * It is indexed based on the position within the tree rather than by the
 * cpu number. It is used to prevent false-sharing across counters at
 * different positions of a tree without wasting memory and cache with
 * padding.
 */
static struct rseq_mempool *percpu_mempool, *item_mempool;
static unsigned int nr_cpus_order, inaccuracy_multiplier;

int percpu_counter_tree_init(struct percpu_counter_tree *counter, unsigned long batch_size)
{
	/* Batch size must be power of 2 */
	if (!batch_size || (batch_size & (batch_size - 1)))
		return -EINVAL;
	counter->batch_size = batch_size;
	counter->bias = 0;
	counter->level0 = (uintptr_t __rseq_percpu *)rseq_mempool_percpu_zmalloc(percpu_mempool);
	if (!counter->level0)
		return -ENOMEM;
	if (!nr_cpus_order) {
		counter->items = NULL;
		counter->approx_sum.p = rseq_percpu_ptr(counter->level0, 0);
		counter->level0_bit_mask = 0;
	} else {
		counter->items = (unsigned long __rseq_percpu *)rseq_mempool_percpu_zmalloc(item_mempool);
		if (!counter->items) {
			rseq_mempool_percpu_free(counter->level0);
			return -ENOMEM;
		}
		counter->approx_sum.l = rseq_percpu_ptr(counter->items, counter_config->nr_items - 1);
		counter->level0_bit_mask = 1UL << rseq_get_count_order_ulong(batch_size);
	}
	counter->inaccuracy = batch_size * inaccuracy_multiplier;
	return 0;
}

void percpu_counter_tree_destroy(struct percpu_counter_tree *counter)
{
	if (counter->items)
		rseq_mempool_percpu_free(counter->items);
	rseq_mempool_percpu_free(counter->level0);
}

void percpu_counter_tree_add_slowpath(struct percpu_counter_tree *counter, long inc, int cpu)
{
	unsigned int level_items, item_index = 0, nr_levels = counter_config->nr_levels,
		     level, n_arity_order;
	unsigned long bit_mask;

	if (!nr_cpus_order)
		abort();	/* Should never be called for 1 cpu. */
	n_arity_order = counter_config->n_arity_order[0];
	bit_mask = counter->level0_bit_mask << n_arity_order;
	level_items = 1U << (nr_cpus_order - n_arity_order);

	for (level = 1; level < nr_levels; level++) {
		unsigned long orig, res;
		unsigned long *count;

		count = rseq_percpu_ptr(counter->items,
					item_index + (cpu & (level_items - 1)));
		res = __atomic_add_fetch(count, inc, __ATOMIC_RELAXED);
		orig = res - inc;
		percpu_counter_tree_dbg_printf(
				"%s: level %u, inc: %ld, bit_mask: %lu, orig %lu, res %lu\n",
				__func__, level, inc, bit_mask, orig, res);
		inc = percpu_counter_tree_carry(orig, res, inc, bit_mask);
		if (!inc)
			return;
		item_index += level_items;
		n_arity_order = counter_config->n_arity_order[level];
		level_items >>= n_arity_order;
		bit_mask <<= n_arity_order;
	}
	percpu_counter_tree_dbg_printf("%s: last level add %ld\n", __func__, inc);
	(void)__atomic_add_fetch(counter->approx_sum.l, inc, __ATOMIC_RELAXED);
}

static
long percpu_counter_tree_precise_sum_unbiased(struct percpu_counter_tree *counter)
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

/*
 * Precise sum. Perform the sum of all per-cpu counters.
 */
long percpu_counter_tree_precise_sum(struct percpu_counter_tree *counter)
{
	return percpu_counter_tree_precise_sum_unbiased(counter) +
		__atomic_load_n(&counter->bias, __ATOMIC_RELAXED);
}

/*
 * Do an approximate comparison of two counters.
 * Return 0 if counters do not differ by more than the sum of their
 * respective inaccuracy ranges,
 * Return -1 if counter @a less than counter @b,
 * Return 1 if counter @a is greater than counter @b.
 */
int percpu_counter_tree_approximate_compare(struct percpu_counter_tree *a, struct percpu_counter_tree *b)
{
	long count_a = percpu_counter_tree_approximate_sum(a),
	     count_b = percpu_counter_tree_approximate_sum(b);

	if (labs(count_a - count_b) <= (a->inaccuracy + b->inaccuracy))
		return 0;
	if (count_a < count_b)
		return -1;
	return 1;
}

/*
 * Do an approximate comparison of a counter against a given value.
 * Return 0 if the value is within the inaccuracy range of the counter,
 * Return -1 if the value less than counter,
 * Return 1 if the value is greater than counter.
 */
int percpu_counter_tree_approximate_compare_value(struct percpu_counter_tree *counter, long v)
{
	long count = percpu_counter_tree_approximate_sum(counter);

	if (labs(v - count) <= counter->inaccuracy)
		return 0;
	if (count < v)
		return -1;
	return 1;
}

/*
 * Do a precise comparison of two counters.
 * Return 0 if the counters are equal,
 * Return -1 if counter @a less than counter @b,
 * Return 1 if counter @a is greater than counter @b.
 */
int percpu_counter_tree_precise_compare(struct percpu_counter_tree *a, struct percpu_counter_tree *b)
{
	long count_a = percpu_counter_tree_approximate_sum(a),
	     count_b = percpu_counter_tree_approximate_sum(b);

	if (labs(count_a - count_b) <= (a->inaccuracy + b->inaccuracy)) {
		if (b->inaccuracy < a->inaccuracy) {
			count_a = percpu_counter_tree_precise_sum(a);
			if (labs(count_a - count_b) <= b->inaccuracy)
				count_b = percpu_counter_tree_precise_sum(b);
		} else {
			count_b = percpu_counter_tree_precise_sum(b);
			if (labs(count_a - count_b) <= a->inaccuracy)
				count_a = percpu_counter_tree_precise_sum(a);
		}
	}
	if (count_a > count_b)
		return -1;
	if (count_a > count_b)
		return 1;
	return 0;
}

/*
 * Do a precise comparision of a counter against a given value.
 * Return 0 if the value is equal to the counter,
 * Return -1 if the value less than counter,
 * Return 1 if the value is greater than counter.
 */
int percpu_counter_tree_precise_compare_value(struct percpu_counter_tree *counter, long v)
{
	long count = percpu_counter_tree_approximate_sum(counter);

	if (labs(v - count) <= counter->inaccuracy)
		count = percpu_counter_tree_precise_sum(counter);
	if (count < v)
		return -1;
	if (count > v)
		return 1;
	return 0;
}

void percpu_counter_tree_set_bias(struct percpu_counter_tree *counter, long bias)
{
	__atomic_store_n(&counter->bias, bias, __ATOMIC_RELAXED);
}

void percpu_counter_tree_set(struct percpu_counter_tree *counter, long v)
{
	percpu_counter_tree_set_bias(counter,
		v - percpu_counter_tree_precise_sum_unbiased(counter));
}

unsigned long percpu_counter_tree_inaccuracy(struct percpu_counter_tree *counter)
{
	return counter->inaccuracy;
}

unsigned int percpu_counter_get_depth(struct percpu_counter_tree *counter __attribute__((unused)))
{
	return counter_config->nr_levels;
}

static
unsigned long calculate_inaccuracy_multiplier(void)
{
	unsigned int nr_levels = counter_config->nr_levels, level;
	unsigned int level_items = 1U << nr_cpus_order;
	unsigned long inaccuracy = 0, batch_size = 1;

	for (level = 0; level < nr_levels; level++) {
		unsigned int n_arity_order = counter_config->n_arity_order[level];

		inaccuracy += batch_size * level_items;
		percpu_counter_tree_dbg_printf(
				"%s: level %u level_batch_size %lu level_items %u inaccuracy_sum: %lu\n",
				__func__, level, batch_size, level_items, inaccuracy);
		batch_size <<= n_arity_order;
		level_items >>= n_arity_order;
	}
	return inaccuracy;
}

static __attribute__((constructor))
void init(void)
{
	struct rseq_mempool_attr *attr;
	int ret, nr_cpus;

	nr_cpus = get_possible_cpus_array_len();
	if (!nr_cpus)
		abort();
	nr_cpus_order = rseq_get_count_order_ulong(nr_cpus);
	if (nr_cpus_order >= RSEQ_ARRAY_SIZE(per_nr_cpu_order_config)) {
		fprintf(stderr, "Unsupported number of CPUs (%u)\n", nr_cpus);
		abort();
	}
	counter_config = &per_nr_cpu_order_config[nr_cpus_order];
	inaccuracy_multiplier = calculate_inaccuracy_multiplier();
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
	percpu_mempool = rseq_mempool_create("percpu_counter_tree", sizeof(uintptr_t), attr);
	if (!percpu_mempool) {
		perror("rseq_mempool_create");
		abort();
	}
	ret = rseq_mempool_attr_set_percpu(attr, RSEQ_MEMPOOL_STRIDE, counter_config->nr_items);
	if (ret) {
		perror("rseq_mempool_attr_set_percpu");
		abort();
	}
	item_mempool = rseq_mempool_create("item_counter_tree", sizeof(unsigned long), attr);
	if (!percpu_mempool) {
		perror("rseq_mempool_create");
		abort();
	}
	rseq_mempool_attr_destroy(attr);
}

static __attribute__((destructor))
void fini(void)
{
	int ret;

	ret = rseq_mempool_destroy(item_mempool);
	if (ret) {
		perror("rseq_mempool_destroy");
		abort();
	}
	ret = rseq_mempool_destroy(percpu_mempool);
	if (ret) {
		perror("rseq_mempool_destroy");
		abort();
	}
}
