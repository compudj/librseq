/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: 2025 Mathieu Desnoyers <mathieu.desnoyers@efficios.com> */

#ifndef _RSEQ_PERCPU_COUNTER_TREE_H
#define _RSEQ_PERCPU_COUNTER_TREE_H

# ifdef __cplusplus
extern "C" {
# endif

enum percpu_counter_tree_type {
	PERCPU_COUNTER_TREE_TYPE_BYTE = 0,
	PERCPU_COUNTER_TREE_TYPE_LONG = 1,
};

struct percpu_counter_tree;

/* Fast paths */
void percpu_counter_tree_add(struct percpu_counter_tree *counter, long inc);
long percpu_counter_tree_approximate_sum(struct percpu_counter_tree *counter);

/* Slow paths */
struct percpu_counter_tree *percpu_counter_tree_alloc(unsigned long batch_size, enum percpu_counter_tree_type type);
void percpu_counter_tree_destroy(struct percpu_counter_tree *counter);
long percpu_counter_tree_precise_sum(struct percpu_counter_tree *counter);
int percpu_counter_tree_approximate_compare(struct percpu_counter_tree *a, struct percpu_counter_tree *b);
int percpu_counter_tree_approximate_compare_value(struct percpu_counter_tree *counter, long v);
int percpu_counter_tree_precise_compare(struct percpu_counter_tree *a, struct percpu_counter_tree *b);
int percpu_counter_tree_precise_compare_value(struct percpu_counter_tree *counter, long v);
void percpu_counter_tree_set_bias(struct percpu_counter_tree *counter, long bias);
void percpu_counter_tree_set(struct percpu_counter_tree *counter, long v);
unsigned long percpu_counter_tree_inaccuracy(struct percpu_counter_tree *counter);
unsigned int percpu_counter_tree_get_depth(struct percpu_counter_tree *counter);

#ifdef __cplusplus
}
#endif

#endif  /* _RSEQ_PERCPU_COUNTER_TREE_H */
