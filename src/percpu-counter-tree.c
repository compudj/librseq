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
#include <limits.h>
#include <hwloc.h>

#include <rseq/rseq.h>
#include <rseq/mempool.h>
#include <rseq/percpu-counter-tree.h>
#include "rseq-utils.h"
#include "smp.h"
#include "rcu.h"

#define RSEQ_COUNTER_SET_SIZE	(4 * sizeof(unsigned long))
#define BIT_PER_ULONG		(8 * sizeof(unsigned long))

#ifdef COUNTER_DEBUG
#define percpu_counter_tree_dbg_printf(...)		printf(__VA_ARGS__)
#else
#define percpu_counter_tree_dbg_printf(...)
#endif

struct percpu_counter_tree {
	/* Fast-path fields. */
	void __rseq_percpu *level0;
	unsigned long level0_bit_mask;
	unsigned long approx_sum;
	long bias;			/* bias for counter_set */
	enum percpu_counter_tree_type type;

	/* Slow-path fields. */
	uint8_t __rseq_percpu *items;
	unsigned long batch_size_order;
	unsigned long inaccuracy;	/* approximation imprecise within ± inaccuracy */

	/* This lock protects precise sum state. */
	pthread_mutex_t lock;
	unsigned long nr_ongoing_precise_sum;
};

/*
 * Use the extra "meta" CPU to hold the fragmented counter set list
 * node (next_fragmented) and alloc bitmap.
 * A counter set holds 32 one-byte counters on 64-bit, or 16 one-byte
 * counters on 32-bit.
 */
struct rseq_byte_counter_set_meta {
	struct rseq_byte_counter_set_meta *prev, *next;	/* fragmented list nodes */
	unsigned long alloc_bitmap;
};

struct rseq_byte_counter_set {
	union {
		uint8_t counters[RSEQ_COUNTER_SET_SIZE];
		struct rseq_byte_counter_set_meta meta;
	} u;
} __attribute__((aligned(RSEQ_COUNTER_SET_SIZE)));

struct rseq_mempool_byte {
	struct rseq_mempool *pool;
	struct rseq_byte_counter_set_meta fragmented_head;
	unsigned int nr_cpus;
	unsigned int meta_index;

	/* This lock protects allocation/free within the pool. */
	pthread_mutex_t lock;
};

#define MAX_NR_LEVELS 5

struct counter_config {
	unsigned int nr_items;
	unsigned char nr_levels;
	unsigned char n_arity_order[MAX_NR_LEVELS];
};

static int *cpu_mapping_os_to_logical;
static struct rseq_rcu_gp_state rcu_gp;

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
static struct rseq_mempool_byte *percpu_byte_mempool, *item_mempool;
static struct rseq_mempool *percpu_long_mempool;
static unsigned int nr_cpus_order, inaccuracy_multiplier;

union word {
	unsigned int word;
	uint8_t bytes[4];
};

/*
 * Atomic add return fallback using 4-byte cmpxchg for architectures
 * which do not implement byte atomics. This is OK because the memory
 * layout of the byte counter set guarantees that counter sets contain
 * RSEQ_COUNTER_SET_SIZE counters, and are aligned on
 * RSEQ_COUNTER_SET_SIZE. The value of RSEQ_COUNTER_SET_SIZE needs to be
 * at least 4 bytes.
 */
static
uint8_t atomic_byte_add_return_relaxed(uint8_t *p, uint8_t v)
{
	if (__atomic_always_lock_free(sizeof(uint8_t), 0)) {
		return __atomic_add_fetch(p, v, __ATOMIC_RELAXED);
	} else {
		union word *wp = (union word *)((uintptr_t)p & ~(sizeof(union word) - 1));
		unsigned int offset = p - &wp->bytes[0];
		union word orig, newv;
		uint8_t new_byte;

		orig.word = __atomic_load_n(&wp->word, __ATOMIC_RELAXED);
		do {
			newv.word = orig.word;
			new_byte = newv.bytes[offset] + v;
			newv.bytes[offset] = new_byte;
		} while (!__atomic_compare_exchange_n(&wp->word, &orig.word,
				newv.word, false, __ATOMIC_RELAXED, __ATOMIC_RELAXED));
		return new_byte;
	}
}

static
uint8_t atomic_byte_load_relaxed(uint8_t *p)
{
	if (__atomic_always_lock_free(sizeof(uint8_t), 0)) {
		return __atomic_load_n(p, __ATOMIC_RELAXED);
	} else {
		union word *wp = (union word *)((uintptr_t)p & ~(sizeof(union word) - 1));
		unsigned int offset = p - &wp->bytes[0];
		union word load;

		load.word = __atomic_load_n(&wp->word, __ATOMIC_RELAXED);
		return load.bytes[offset];
	}
}

/*
 * Ensure that cpu index placement follows the logical processor unit
 * (PU) order from hwloc, which provides better topology locality for
 * contiguous numbers.
 */
static
int cpu_os_to_logical(int cpu)
{
	if (!cpu_mapping_os_to_logical)
		return cpu;
        return cpu_mapping_os_to_logical[cpu];
}

static
struct rseq_byte_counter_set_meta *counter_set_to_meta(struct rseq_mempool_byte *pool, struct rseq_byte_counter_set __rseq_percpu *set)
{
	return &rseq_percpu_ptr(set, pool->meta_index)->u.meta;
}

static
struct rseq_byte_counter_set __rseq_percpu *byte_counter_to_set(uint8_t __rseq_percpu *p)
{
	return (struct rseq_byte_counter_set __rseq_percpu *)((uintptr_t) p & ~(RSEQ_COUNTER_SET_SIZE - 1));
}

static
struct rseq_byte_counter_set __rseq_percpu *meta_to_counter_set(struct rseq_mempool_byte *pool, struct rseq_byte_counter_set_meta *meta)
{
	return (struct rseq_byte_counter_set __rseq_percpu *) ((uintptr_t) meta - (pool->meta_index * RSEQ_MEMPOOL_STRIDE));
}

static
uint8_t __rseq_percpu *rseq_mempool_byte_zmalloc(struct rseq_mempool_byte *pool)
{
	struct rseq_byte_counter_set __rseq_percpu *percpu_counter_set;
	struct rseq_byte_counter_set_meta *meta;
	uint8_t __rseq_percpu *percpu_counter = NULL;

	pthread_mutex_lock(&pool->lock);

	/* Try to allocate from fragmented counter sets. */
	if (pool->fragmented_head.next != &pool->fragmented_head) {
		unsigned int index;
		unsigned int cpu;

		meta = pool->fragmented_head.next;
		percpu_counter_set = meta_to_counter_set(pool, meta);

		/* Find a free bit, use it. */
		index = rseq_fls_ulong((~meta->alloc_bitmap) & ((1UL << RSEQ_COUNTER_SET_SIZE) - 1));
		if (!index)
			abort();
		index--;	/* from 0 to n-1 */
		meta->alloc_bitmap |= (1UL << index);
		/* if no free bits left, remove from fragmented list. */
		if (rseq_hweight_ulong(meta->alloc_bitmap) == RSEQ_COUNTER_SET_SIZE) {
			meta->next->prev = meta->prev;
			meta->prev->next = meta->next;
		}
		percpu_counter = &percpu_counter_set->u.counters[index];
		/* Zero counters if not zero already. */
		for (cpu = 0; cpu < pool->nr_cpus; cpu++) {
			uint8_t *counter = rseq_percpu_ptr(percpu_counter, cpu);

			if (*counter)
				*counter = 0;
		}
		goto unlock;
	}

	/* Call allocator. */
	percpu_counter_set = (struct rseq_byte_counter_set __rseq_percpu *)rseq_mempool_percpu_zmalloc(pool->pool);
	if (!percpu_counter_set) {
		goto unlock;
	}

	/* Use first. */
	meta = counter_set_to_meta(pool, percpu_counter_set);
	meta->alloc_bitmap |= (1UL << 0);
	percpu_counter = &percpu_counter_set->u.counters[0];

	/* Add to fragmented list. */
	pool->fragmented_head.next->prev = meta;
	meta->next = pool->fragmented_head.next;
	meta->prev = &pool->fragmented_head;
	pool->fragmented_head.next = meta;

unlock:
	pthread_mutex_unlock(&pool->lock);
	return percpu_counter;
}

static
void rseq_mempool_byte_free(struct rseq_mempool_byte *pool, uint8_t __rseq_percpu *p)
{
	struct rseq_byte_counter_set_meta *meta;
	struct rseq_byte_counter_set *set;
	unsigned int index;
	int count;

	if (!p)
		return;

	pthread_mutex_lock(&pool->lock);
	set = byte_counter_to_set(p);
	meta = counter_set_to_meta(pool, set);
	/* If last in counter set, remove from fragmented list and free set. */
	count = rseq_hweight_ulong(meta->alloc_bitmap);
	if (count == 1) {
		/* Remove from list. */
		meta->next->prev = meta->prev;
		meta->prev->next = meta->next;
		rseq_mempool_percpu_free(set);
		goto unlock;
	}
	/* If set is newly fragmented, add to fragmented list. */
	if (count == RSEQ_COUNTER_SET_SIZE) {
		pool->fragmented_head.next->prev = meta;
		meta->next = pool->fragmented_head.next;
		meta->prev = &pool->fragmented_head;
		pool->fragmented_head.next = meta;
	}
	/* Clear bit from meta. */
	index = p - set->u.counters;
	meta->alloc_bitmap &= ~(1UL << index);
unlock:
	pthread_mutex_unlock(&pool->lock);
	return;
}

static
struct rseq_mempool_byte *rseq_mempool_byte_create(const char *pool_name, size_t nr_cpus)
{
	struct rseq_mempool_attr *attr = NULL;
	struct rseq_mempool_byte *pool = NULL;
	int ret;

	pool = calloc(1, sizeof(struct rseq_mempool_byte));
	if (!pool)
		goto error;
	attr = rseq_mempool_attr_create();
	if (!attr)
		goto error;
	ret = rseq_mempool_attr_set_percpu(attr, RSEQ_MEMPOOL_STRIDE, nr_cpus + 1);
	if (ret)
		goto error;
	pool->pool = rseq_mempool_create(pool_name, sizeof(struct rseq_byte_counter_set), attr);
	if (!pool->pool)
		goto error;
	rseq_mempool_attr_destroy(attr);
	attr = NULL;
	pool->fragmented_head.next = &pool->fragmented_head;
	pool->fragmented_head.prev = &pool->fragmented_head;
	pool->nr_cpus = nr_cpus;
	pool->meta_index = nr_cpus;
	pthread_mutex_init(&pool->lock, NULL);
	return pool;

error:
	if (attr)
		rseq_mempool_attr_destroy(attr);
	free(pool);
	return NULL;
}

static
int rseq_mempool_byte_destroy(struct rseq_mempool_byte *pool)
{
	int ret;

	ret = rseq_mempool_destroy(pool->pool);
	if (ret)
		return ret;
	pthread_mutex_destroy(&pool->lock);
	free(pool);
	return 0;
}

static
struct rseq_mempool *rseq_mempool_long_create(const char *pool_name, size_t nr_cpus)
{
	struct rseq_mempool_attr *attr = NULL;
	struct rseq_mempool *pool = NULL;
	int ret;

	attr = rseq_mempool_attr_create();
	if (!attr)
		goto error;
	ret = rseq_mempool_attr_set_percpu(attr, RSEQ_MEMPOOL_STRIDE, nr_cpus);
	if (ret)
		goto error;
	pool = rseq_mempool_create(pool_name, sizeof(unsigned long), attr);
	if (!pool)
		goto error;
	rseq_mempool_attr_destroy(attr);
	attr = NULL;
	return pool;

error:
	if (attr)
		rseq_mempool_attr_destroy(attr);
	return NULL;
}

struct percpu_counter_tree *percpu_counter_tree_alloc(unsigned long batch_size, enum percpu_counter_tree_type type)
{
	struct percpu_counter_tree *counter = NULL;

	/* Batch size must be power of 2 */
	if (!batch_size || (batch_size & (batch_size - 1)))
		return NULL;
	switch (type) {
	case PERCPU_COUNTER_TREE_TYPE_BYTE:
		/* Maximum batch size is 256 (one byte). */
		if (batch_size > (1U << CHAR_BIT))
			return NULL;
		break;
	case PERCPU_COUNTER_TREE_TYPE_LONG:
		break;
	default:
		return NULL;
	}
	counter = calloc(1, sizeof(struct percpu_counter_tree));
	if (!counter)
		goto error;
	counter->batch_size_order = rseq_get_count_order_ulong(batch_size);
	counter->approx_sum = 0;
	counter->bias = 0;
	counter->nr_ongoing_precise_sum = 0;
	counter->type = type;
	if (!nr_cpus_order) {
		counter->items = NULL;
		counter->level0_bit_mask = 0;
	} else {
		switch (type) {
		case PERCPU_COUNTER_TREE_TYPE_BYTE:
			counter->level0 = (void __rseq_percpu *)rseq_mempool_byte_zmalloc(percpu_byte_mempool);
			break;
		case PERCPU_COUNTER_TREE_TYPE_LONG:
			counter->level0 = (void __rseq_percpu *)rseq_mempool_zmalloc(percpu_long_mempool);
			break;
		}
		if (!counter->level0) {
			goto error;
		}
		counter->items = (uint8_t __rseq_percpu *)rseq_mempool_byte_zmalloc(item_mempool);
		if (!counter->items)
			goto free_level0;
		counter->level0_bit_mask = 1UL << counter->batch_size_order;
	}
	counter->inaccuracy = inaccuracy_multiplier << counter->batch_size_order;
	pthread_mutex_init(&counter->lock, NULL);
	return counter;

free_level0:
	switch (type) {
	case PERCPU_COUNTER_TREE_TYPE_BYTE:
		rseq_mempool_byte_free(percpu_byte_mempool, counter->level0);
		break;
	case PERCPU_COUNTER_TREE_TYPE_LONG:
		rseq_mempool_percpu_free(counter->level0);
		break;
	}
error:
	free(counter);
	return NULL;
}

void percpu_counter_tree_destroy(struct percpu_counter_tree *counter)
{
	if (!counter)
		return;
	pthread_mutex_destroy(&counter->lock);
	if (counter->items)
		rseq_mempool_byte_free(item_mempool, counter->items);
	if (counter->level0) {
		switch (counter->type) {
		case PERCPU_COUNTER_TREE_TYPE_BYTE:
			rseq_mempool_byte_free(percpu_byte_mempool, counter->level0);
			break;
		case PERCPU_COUNTER_TREE_TYPE_LONG:
			rseq_mempool_percpu_free(counter->level0);
			break;
		}
	}
	free(counter);
}

static
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

static
void percpu_counter_tree_add_slowpath(struct percpu_counter_tree *counter, long inc, int cpu, unsigned long bit_mask)
{
	unsigned int level_items, item_index = 0, nr_levels = counter_config->nr_levels,
		     level, n_arity_order, inc_shift;
	int logical_cpu = cpu_os_to_logical(cpu);

	if (!nr_cpus_order)
		abort();	/* Should never be called for 1 cpu. */
	n_arity_order = counter_config->n_arity_order[0];
	bit_mask <<= n_arity_order;
	level_items = 1U << (nr_cpus_order - n_arity_order);
	inc_shift = counter->batch_size_order;

	for (level = 1; level < nr_levels; level++) {
		if ((inc >> inc_shift) & ((1UL << n_arity_order) - 1)) {
			unsigned long orig, res;
			uint8_t *count;

			count = rseq_percpu_ptr(counter->items,
						item_index + (logical_cpu & (level_items - 1)));
			res = atomic_byte_add_return_relaxed(count, inc >> inc_shift);
			orig = res - (inc >> inc_shift);
			percpu_counter_tree_dbg_printf(
					"%s: cpu: %d, level %u, inc: %ld, bit_mask: %lu, orig %lu, res %lu\n",
					__func__, cpu, level, inc, bit_mask,
					orig << inc_shift, res << inc_shift);
			inc = percpu_counter_tree_carry(orig << inc_shift, res << inc_shift,
							inc, bit_mask);
		}
		if (!inc)
			return;
		item_index += level_items;
		inc_shift += n_arity_order;
		n_arity_order = counter_config->n_arity_order[level];
		level_items >>= n_arity_order;
		bit_mask <<= n_arity_order;
	}
	percpu_counter_tree_dbg_printf("%s: cpu: %d, last level add %ld\n", __func__, cpu, inc);
	(void)__atomic_add_fetch(&counter->approx_sum, inc, __ATOMIC_RELAXED);
}

static
void percpu_counter_tree_byte_add(struct percpu_counter_tree *counter, long inc)
{
	struct rseq_rcu_read_state rcu_state;
	unsigned long bit_mask;
	int cpu;

	if (!inc)
		return;
	cpu = rseq_current_cpu();
	rseq_rcu_read_begin(&rcu_gp, &rcu_state, cpu);
	bit_mask = __atomic_load_n(&counter->level0_bit_mask, __ATOMIC_RELAXED);
	/*
	 * Control dependency orders level0_bit_mask load vs
	 * stores to the tree level 0 and intermediate nodes.
	 */
	if (rseq_unlikely(!bit_mask)) {
		if (!nr_cpus_order) {
			/* Single CPU. */
			counter->approx_sum += inc;
		} else {
			/* Ongoing precise sum. */
			(void)__atomic_add_fetch(&counter->approx_sum, inc, __ATOMIC_RELAXED);
		}
		goto end;
	}
	if (rseq_likely(inc & ((1UL << counter->batch_size_order) - 1))) {
		unsigned long orig, res;

		res = atomic_byte_add_return_relaxed(rseq_percpu_ptr((uint8_t __rseq_percpu *)counter->level0, cpu), inc);
		orig = res - inc;
		percpu_counter_tree_dbg_printf("%s: cpu: %d, inc: %ld, bit_mask: %lu, orig %lu, res %lu\n",
				__func__, cpu, inc, bit_mask, orig, res);
		inc = percpu_counter_tree_carry(orig, res, inc, bit_mask);
	}
	if (inc)
		percpu_counter_tree_add_slowpath(counter, inc, cpu, bit_mask);
end:
	rseq_rcu_read_end(&rcu_gp, &rcu_state);
}

static
void percpu_counter_tree_long_add(struct percpu_counter_tree *counter, long inc)
{
	unsigned long orig, res, bit_mask = counter->level0_bit_mask;
	int cpu;

	if (!inc)
		return;
	bit_mask = counter->level0_bit_mask;
	if (rseq_unlikely(!bit_mask)) {
		/* Single CPU. */
		counter->approx_sum += inc;
		return;
	}
	cpu = rseq_current_cpu();
	res = __atomic_add_fetch(rseq_percpu_ptr((unsigned long __rseq_percpu *)counter->level0, cpu),
				 inc, __ATOMIC_RELAXED);
	orig = res - inc;
	percpu_counter_tree_dbg_printf("%s: cpu: %d, inc: %ld, bit_mask: %lu, orig %lu, res %lu\n",
			__func__, cpu, inc, bit_mask, orig, res);
	inc = percpu_counter_tree_carry(orig, res, inc, bit_mask);
	if (inc)
		percpu_counter_tree_add_slowpath(counter, inc, cpu, bit_mask);
}

void percpu_counter_tree_add(struct percpu_counter_tree *counter, long inc)
{
	switch (counter->type) {
	case PERCPU_COUNTER_TREE_TYPE_BYTE:
		percpu_counter_tree_byte_add(counter, inc);
		break;
	case PERCPU_COUNTER_TREE_TYPE_LONG:
		percpu_counter_tree_long_add(counter, inc);
		break;
	default:
		abort();
	}
}

long percpu_counter_tree_approximate_sum(struct percpu_counter_tree *counter)
{
	return (long) (__atomic_load_n(&counter->approx_sum, __ATOMIC_RELAXED) +
		       (unsigned long)__atomic_load_n(&counter->bias, __ATOMIC_RELAXED));
}

/*
 * The precise sum is only accurate if updaters are quiescent, because
 * they may be in flight and propagating a carry.
 * 
 * Surround updaters by an RCU read-side critical section, and use the
 * level 0 bit mask value 0 to divert updaters to the global approximate
 * counter sum while at least one precise sum is being aggregated.
 * 
 * Precise sum aggregation wait for a grace period to ensure updaters
 * are not modifying the level 0 and intermediate tree nodes while the
 * precise sum reads those values.
 */
static
long percpu_counter_tree_byte_precise_sum_unbiased(struct percpu_counter_tree *counter)
{
	unsigned int level_items, item_index = 0, nr_levels = counter_config->nr_levels,
		     level, n_arity_order, inc_shift;
	unsigned long sum = 0;
	int nr_cpus, cpu;

	if (!nr_cpus_order)
		return counter->approx_sum;

	pthread_mutex_lock(&counter->lock);
	if (++counter->nr_ongoing_precise_sum == 1)
		__atomic_store_n(&counter->level0_bit_mask, 0, __ATOMIC_RELAXED);
	pthread_mutex_unlock(&counter->lock);

	rseq_rcu_wait_grace_period(&rcu_gp);

	nr_cpus = get_possible_cpus_array_len();
	if (!nr_cpus)
		abort();

	/* Level 0 */
	for (cpu = 0; cpu < nr_cpus; cpu++) {
		uint8_t *count = rseq_percpu_ptr((uint8_t __rseq_percpu *)counter->level0, cpu);
		unsigned long v = (unsigned long)atomic_byte_load_relaxed(count);

		sum += v & ((1UL << counter->batch_size_order) - 1);
	}

	n_arity_order = counter_config->n_arity_order[0];
	level_items = 1U << (nr_cpus_order - n_arity_order);
	inc_shift = counter->batch_size_order;
	for (level = 1; level < nr_levels; level++) {
		unsigned int level_item_index;

		for (level_item_index = 0; level_item_index < level_items; level_item_index++) {
			uint8_t *count;
			unsigned long v;

			count = rseq_percpu_ptr(counter->items, item_index + level_item_index);
			v = (unsigned long)atomic_byte_load_relaxed(count);
			sum += (v & ((1UL << n_arity_order) - 1)) << inc_shift;
		}
		item_index += level_items;
		inc_shift += n_arity_order;
		n_arity_order = counter_config->n_arity_order[level];
		level_items >>= n_arity_order;
	}
	/* Last level */
	sum += __atomic_load_n(&counter->approx_sum, __ATOMIC_RELAXED);

	pthread_mutex_lock(&counter->lock);
	if (--counter->nr_ongoing_precise_sum == 0) {
		__atomic_store_n(&counter->level0_bit_mask,
				 1UL << counter->batch_size_order,
				 __ATOMIC_RELEASE);
	}
	pthread_mutex_unlock(&counter->lock);
	return (long) sum;
}

static
long percpu_counter_tree_long_precise_sum_unbiased(struct percpu_counter_tree *counter)
{
	unsigned long sum = 0;
	int nr_cpus, cpu;

	if (!nr_cpus_order)
		return counter->approx_sum;

	nr_cpus = get_possible_cpus_array_len();
	if (!nr_cpus)
		abort();

	/* Level 0 */
	for (cpu = 0; cpu < nr_cpus; cpu++) {
		unsigned long *count = rseq_percpu_ptr((unsigned long __rseq_percpu *)counter->level0, cpu);
		unsigned long v = __atomic_load_n(count, __ATOMIC_RELAXED);

		sum += v;
	}
	return (long) sum;
}

static
long percpu_counter_tree_precise_sum_unbiased(struct percpu_counter_tree *counter)
{
	switch (counter->type) {
	case PERCPU_COUNTER_TREE_TYPE_BYTE:
		return percpu_counter_tree_byte_precise_sum_unbiased(counter);
	case PERCPU_COUNTER_TREE_TYPE_LONG:
		return percpu_counter_tree_long_precise_sum_unbiased(counter);
	default:
		abort();
	}
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

unsigned int percpu_counter_tree_get_depth(struct percpu_counter_tree *counter __attribute__((unused)))
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

static
int init_cpu_mapping(void)
{
	hwloc_topology_t topology;
	hwloc_obj_t obj;
	int nbpu, ret, cpu;
	bool identity = true;

	hwloc_topology_init(&topology);
	hwloc_topology_load(topology);

	nbpu = hwloc_get_nbobjs_by_type(topology, HWLOC_OBJ_PU);
	if (nbpu <= 0) {
		ret = -EINVAL;
		goto end;
	}
	cpu_mapping_os_to_logical = calloc(nbpu, sizeof(int));
	if (!cpu_mapping_os_to_logical) {
		ret = -ENOMEM;
		goto end;
	}
	obj = hwloc_get_obj_by_type(topology, HWLOC_OBJ_PU, 0);
	while (obj) {
		if (obj->os_index >= (unsigned int)nbpu) {
			ret = -EINVAL;
			goto end;
		}
		cpu_mapping_os_to_logical[obj->os_index] = obj->logical_index;
		obj = hwloc_get_next_obj_by_type(topology, HWLOC_OBJ_PU, obj);
	}
	for (cpu = 0; cpu < nbpu; cpu++) {
		if (cpu_mapping_os_to_logical[cpu] != cpu) {
			identity = false;
			break;
		}
	}
	if (identity) {
		/* No need for a mapping table for identity function. */
		free(cpu_mapping_os_to_logical);
		cpu_mapping_os_to_logical = NULL;
	}
	ret = 0;
end:
	if (ret)
		free(cpu_mapping_os_to_logical);
	hwloc_topology_destroy(topology);

	return ret;
}

static
void fini_cpu_mapping(void)
{
	free(cpu_mapping_os_to_logical);
}

static __attribute__((constructor))
void init(void)
{
	int nr_cpus;

	rseq_rcu_gp_init(&rcu_gp);
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
	percpu_byte_mempool = rseq_mempool_byte_create("percpu_counter_tree_byte", nr_cpus);
	if (!percpu_byte_mempool) {
		perror("rseq_mempool_byte_create");
		abort();
	}
	percpu_long_mempool = rseq_mempool_long_create("percpu_counter_tree_long", nr_cpus);
	if (!percpu_long_mempool) {
		perror("rseq_mempool_create");
		abort();
	}
	item_mempool = rseq_mempool_byte_create("item_counter_tree", counter_config->nr_items);
	if (!item_mempool) {
		perror("rseq_mempool_byte_create");
		abort();
	}
	if (init_cpu_mapping())
		abort();
}

static __attribute__((destructor))
void fini(void)
{
	int ret;

	fini_cpu_mapping();
	ret = rseq_mempool_byte_destroy(item_mempool);
	if (ret) {
		perror("rseq_mempool_byte_destroy");
		abort();
	}
	ret = rseq_mempool_byte_destroy(percpu_byte_mempool);
	if (ret) {
		perror("rseq_mempool_byte_destroy");
		abort();
	}
	rseq_rcu_gp_exit(&rcu_gp);
}
