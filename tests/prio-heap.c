/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Static-sized priority heap containing pointers. Based on CLRS,
 * chapter 6.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <rseq/compiler.h>

#include "prio-heap.h"

#define rseq_max_t(type, a, b)	\
	((type) (a) > (type) (b) ? (type) (a) : (type) (b))

#ifdef DEBUG_HEAP
void check_heap(const struct ptr_heap *heap)
{
	size_t i;

	if (!heap->len)
		return;

	for (i = 1; i < heap->len; i++)
		BT_ASSERT_DBG(!heap->gt(heap->ptrs[i], heap->ptrs[0]));
}
#endif

static
size_t parent(size_t i)
{
	return (i - 1) >> 1;
}

static
size_t left(size_t i)
{
	return (i << 1) + 1;
}

static
size_t right(size_t i)
{
	return (i << 1) + 2;
}

/*
 * Copy of heap->ptrs pointer is invalid after heap_grow.
 */
static
int heap_grow(struct ptr_heap *heap, size_t new_len)
{
	void **new_ptrs;

	if (rseq_likely(heap->alloc_len >= new_len))
		return 0;

	heap->alloc_len = rseq_max_t(size_t, new_len, heap->alloc_len << 1);
	new_ptrs = calloc(heap->alloc_len, sizeof(void *));
	if (rseq_unlikely(!new_ptrs))
		return -ENOMEM;
	if (rseq_likely(heap->ptrs))
		memcpy(new_ptrs, heap->ptrs, heap->len * sizeof(void *));
	free(heap->ptrs);
	heap->ptrs = new_ptrs;
	return 0;
}

static
int heap_set_len(struct ptr_heap *heap, size_t new_len)
{
	int ret;

	ret = heap_grow(heap, new_len);
	if (rseq_unlikely(ret))
		return ret;
	heap->len = new_len;
	return 0;
}

int bt_heap_init(struct ptr_heap *heap, size_t alloc_len,
	      int gt(void *a, void *b))
{
	heap->ptrs = NULL;
	heap->len = 0;
	heap->alloc_len = 0;
	heap->gt = gt;
	/*
	 * Minimum size allocated is 1 entry to ensure memory allocation
	 * never fails within bt_heap_replace_max.
	 */
	return heap_grow(heap, rseq_max_t(size_t, 1, alloc_len));
}

void bt_heap_free(struct ptr_heap *heap)
{
	free(heap->ptrs);
}

static void heapify(struct ptr_heap *heap, size_t i)
{
	void **ptrs = heap->ptrs;
	size_t l, r, largest;

	for (;;) {
		void *tmp;

		l = left(i);
		r = right(i);
		if (l < heap->len && heap->gt(ptrs[l], ptrs[i]))
			largest = l;
		else
			largest = i;
		if (r < heap->len && heap->gt(ptrs[r], ptrs[largest]))
			largest = r;
		if (rseq_unlikely(largest == i))
			break;
		tmp = ptrs[i];
		ptrs[i] = ptrs[largest];
		ptrs[largest] = tmp;
		i = largest;
	}
	check_heap(heap);
}

void *bt_heap_replace_max(struct ptr_heap *heap, void *p)
{
	void *res;

	if (rseq_unlikely(!heap->len)) {
		(void) heap_set_len(heap, 1);
		heap->ptrs[0] = p;
		check_heap(heap);
		return NULL;
	}

	/* Replace the current max and heapify */
	res = heap->ptrs[0];
	heap->ptrs[0] = p;
	heapify(heap, 0);
	return res;
}

int bt_heap_insert(struct ptr_heap *heap, void *p)
{
	void **ptrs;
	size_t pos;
	int ret;

	ret = heap_set_len(heap, heap->len + 1);
	if (rseq_unlikely(ret))
		return ret;
	ptrs = heap->ptrs;
	pos = heap->len - 1;
	while (pos > 0 && heap->gt(p, ptrs[parent(pos)])) {
		/* Move parent down until we find the right spot */
		ptrs[pos] = ptrs[parent(pos)];
		pos = parent(pos);
	}
	ptrs[pos] = p;
	check_heap(heap);
	return 0;
}

void *bt_heap_remove(struct ptr_heap *heap)
{
	switch (heap->len) {
	case 0:
		return NULL;
	case 1:
		(void) heap_set_len(heap, 0);
		return heap->ptrs[0];
	}
	/* Shrink, replace the current max by previous last entry and heapify */
	heap_set_len(heap, heap->len - 1);
	/* len changed. previous last entry is at heap->len */
	return bt_heap_replace_max(heap, heap->ptrs[heap->len]);
}

void *bt_heap_cherrypick(struct ptr_heap *heap, void *p)
{
	size_t pos, len = heap->len;

	for (pos = 0; pos < len; pos++)
		if (rseq_unlikely(heap->ptrs[pos] == p))
			goto found;
	return NULL;
found:
	if (rseq_unlikely(heap->len == 1)) {
		(void) heap_set_len(heap, 0);
		check_heap(heap);
		return heap->ptrs[0];
	}
	/* Replace p with previous last entry and heapify. */
	heap_set_len(heap, heap->len - 1);
	/* len changed. previous last entry is at heap->len */
	heap->ptrs[pos] = heap->ptrs[heap->len];
	heapify(heap, pos);
	return p;
}

int bt_heap_copy(struct ptr_heap *dst, struct ptr_heap *src)
{
	int ret;

	ret = bt_heap_init(dst, src->alloc_len, src->gt);
	if (ret < 0)
		goto end;

	ret = heap_set_len(dst, src->len);
	if (ret < 0)
		goto end;

	memcpy(dst->ptrs, src->ptrs, src->len * sizeof(void *));

end:
	return ret;
}
