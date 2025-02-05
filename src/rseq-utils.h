// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>

#ifndef _RSEQ_COMMON_UTILS_H
#define _RSEQ_COMMON_UTILS_H

#include <stdbool.h>
#include <stdint.h>
#include <syscall.h>
#include <unistd.h>
#include <sys/auxv.h>
#include <linux/auxvec.h>

#include <rseq/rseq.h>

/* Allocate a large area for the TLS. */
#define RSEQ_THREAD_AREA_ALLOC_SIZE	1024

/* Original struct rseq feature size is 20 bytes. */
#define ORIG_RSEQ_FEATURE_SIZE		20

/* Original struct rseq allocation size is 32 bytes. */
#define ORIG_RSEQ_ALLOC_SIZE		32

#define RSEQ_ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define __rseq_align_mask(v, mask)	(((v) + (mask)) & ~(mask))
#define rseq_align(v, align)		__rseq_align_mask(v, (__typeof__(v)) (align) - 1)

static inline
unsigned int rseq_fls_u64(uint64_t x)
{
	unsigned int r = 64;

	if (!x)
		return 0;

	if (!(x & 0xFFFFFFFF00000000ULL)) {
		x <<= 32;
		r -= 32;
	}
	if (!(x & 0xFFFF000000000000ULL)) {
		x <<= 16;
		r -= 16;
	}
	if (!(x & 0xFF00000000000000ULL)) {
		x <<= 8;
		r -= 8;
	}
	if (!(x & 0xF000000000000000ULL)) {
		x <<= 4;
		r -= 4;
	}
	if (!(x & 0xC000000000000000ULL)) {
		x <<= 2;
		r -= 2;
	}
	if (!(x & 0x8000000000000000ULL)) {
		x <<= 1;
		r -= 1;
	}
	return r;
}

static inline
unsigned int rseq_fls_u32(uint32_t x)
{
	unsigned int r = 32;

	if (!x)
		return 0;
	if (!(x & 0xFFFF0000U)) {
		x <<= 16;
		r -= 16;
	}
	if (!(x & 0xFF000000U)) {
		x <<= 8;
		r -= 8;
	}
	if (!(x & 0xF0000000U)) {
		x <<= 4;
		r -= 4;
	}
	if (!(x & 0xC0000000U)) {
		x <<= 2;
		r -= 2;
	}
	if (!(x & 0x80000000U)) {
		x <<= 1;
		r -= 1;
	}
	return r;
}

static inline
unsigned int rseq_fls_ulong(unsigned long x)
{
#if RSEQ_BITS_PER_LONG == 32
	return rseq_fls_u32(x);
#else
	return rseq_fls_u64(x);
#endif
}

/*
 * Return the minimum order for which x <= (1UL << order).
 * Return -1 if x is 0.
 */
static inline
int rseq_get_count_order_ulong(unsigned long x)
{
	if (!x)
		return -1;

	return rseq_fls_ulong(x - 1);
}

#define RSEQ_DEFAULT_PAGE_SIZE	4096

static inline
unsigned long rseq_get_page_len(void)
{
	long page_len = sysconf(_SC_PAGE_SIZE);

	if (page_len < 0)
		page_len = RSEQ_DEFAULT_PAGE_SIZE;
	return (unsigned long) page_len;
}

static inline
int rseq_hweight_ulong(unsigned long v)
{
	return __builtin_popcountl(v);
}

static inline
bool is_pow2(uint64_t x)
{
	return !(x & (x - 1));
}

/*
 * Calculate offset needed to align p on alignment towards higher
 * addresses. Alignment must be a power of 2
 */
static inline
off_t offset_align(uintptr_t p, size_t alignment)
{
	return (alignment - p) & (alignment - 1);
}

static inline
int sys_rseq(struct rseq_abi *rseq_abi, uint32_t rseq_len,
	     int flags, uint32_t sig)
{
	return syscall(__NR_rseq, rseq_abi, rseq_len, flags, sig);
}

static inline
int sys_getcpu(unsigned int *cpu, unsigned int *node)
{
	return syscall(__NR_getcpu, cpu, node, NULL);
}

/*
 * Return the feature size supported by the kernel.
 *
 * Depending on the value returned by getauxval(AT_RSEQ_FEATURE_SIZE):
 *
 * 0:   Return ORIG_RSEQ_FEATURE_SIZE (20)
 * > 0: Return the value from getauxval(AT_RSEQ_FEATURE_SIZE).
 *
 * It should never return a value below ORIG_RSEQ_FEATURE_SIZE.
 */
static inline
unsigned int get_rseq_kernel_feature_size(void)
{
	unsigned long auxv_rseq_feature_size, auxv_rseq_align;

	auxv_rseq_align = getauxval(AT_RSEQ_ALIGN);
	assert(!auxv_rseq_align || auxv_rseq_align <= RSEQ_THREAD_AREA_ALLOC_SIZE);

	auxv_rseq_feature_size = getauxval(AT_RSEQ_FEATURE_SIZE);
	assert(!auxv_rseq_feature_size || auxv_rseq_feature_size <= RSEQ_THREAD_AREA_ALLOC_SIZE);
	if (auxv_rseq_feature_size)
		return auxv_rseq_feature_size;
	else
		return ORIG_RSEQ_FEATURE_SIZE;
}

#endif /* _RSEQ_COMMON_UTILS_H */
