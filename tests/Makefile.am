# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2022 EfficiOS Inc.

AM_CPPFLAGS += -I$(top_srcdir)/tests/utils

SUBDIRS = utils unit

TEST_EXTENSIONS = .tap
TAP_LOG_DRIVER_FLAGS = --merge --comments
TAP_LOG_DRIVER = env AM_TAP_AWK='$(AWK)' \
	RSEQ_TESTS_SRCDIR='$(abs_top_srcdir)/tests' \
	RSEQ_TESTS_BUILDDIR='$(abs_top_builddir)/tests' \
	$(SHELL) $(srcdir)/utils/tap-driver.sh

noinst_PROGRAMS = \
	basic_percpu_ops_test.tap \
	basic_percpu_ops_test_cxx.tap \
	basic_percpu_ops_mm_cid_test.tap \
	basic_percpu_ops_mm_cid_test_cxx.tap \
	basic_test.tap \
	basic_test_cxx.tap \
	param_test \
	param_test_cxx \
	param_test_mm_cid \
	param_test_mm_cid_cxx \
	param_test_benchmark \
	param_test_benchmark_cxx \
	param_test_mm_cid_benchmark \
	param_test_mm_cid_benchmark_cxx \
	param_test_compare_twice \
	param_test_compare_twice_cxx \
	param_test_mm_cid_compare_twice \
	param_test_mm_cid_compare_twice_cxx \
	test_rseq_biased_lock

dist_noinst_SCRIPTS = \
	run_param_test.tap \
	run_param_test_cxx.tap

basic_percpu_ops_test_tap_SOURCES = basic_percpu_ops_test.c
basic_percpu_ops_test_tap_LDADD = $(top_builddir)/src/librseq.la $(top_builddir)/tests/utils/libtap.la $(DL_LIBS)

basic_percpu_ops_test_cxx_tap_SOURCES = basic_percpu_ops_test_cxx.cpp
basic_percpu_ops_test_cxx_tap_LDADD = $(top_builddir)/src/librseq.la $(top_builddir)/tests/utils/libtap.la $(DL_LIBS)

basic_percpu_ops_mm_cid_test_tap_SOURCES = basic_percpu_ops_test.c
basic_percpu_ops_mm_cid_test_tap_CPPFLAGS = $(AM_CPPFLAGS) -DBUILDOPT_RSEQ_PERCPU_MM_CID
basic_percpu_ops_mm_cid_test_tap_LDADD = $(top_builddir)/src/librseq.la $(top_builddir)/tests/utils/libtap.la $(DL_LIBS)

basic_percpu_ops_mm_cid_test_cxx_tap_SOURCES = basic_percpu_ops_test_cxx.cpp
basic_percpu_ops_mm_cid_test_cxx_tap_CPPFLAGS = $(AM_CPPFLAGS) -DBUILDOPT_RSEQ_PERCPU_MM_CID
basic_percpu_ops_mm_cid_test_cxx_tap_LDADD = $(top_builddir)/src/librseq.la $(top_builddir)/tests/utils/libtap.la $(DL_LIBS)

basic_test_tap_SOURCES = basic_test.c
basic_test_tap_LDADD = $(top_builddir)/src/librseq.la $(top_builddir)/tests/utils/libtap.la $(DL_LIBS)

basic_test_cxx_tap_SOURCES = basic_test_cxx.cpp
basic_test_cxx_tap_LDADD = $(top_builddir)/src/librseq.la $(top_builddir)/tests/utils/libtap.la $(DL_LIBS)

param_test_SOURCES = param_test.c
param_test_LDADD = $(top_builddir)/src/librseq.la $(DL_LIBS)

param_test_cxx_SOURCES = param_test_cxx.cpp
param_test_cxx_LDADD = $(top_builddir)/src/librseq.la $(DL_LIBS)

param_test_mm_cid_SOURCES = param_test.c
param_test_mm_cid_CPPFLAGS = $(AM_CPPFLAGS) -DBUILDOPT_RSEQ_PERCPU_MM_CID
param_test_mm_cid_LDADD = $(top_builddir)/src/librseq.la $(DL_LIBS)

param_test_mm_cid_cxx_SOURCES = param_test_cxx.cpp
param_test_mm_cid_cxx_CPPFLAGS = $(AM_CPPFLAGS) -DBUILDOPT_RSEQ_PERCPU_MM_CID
param_test_mm_cid_cxx_LDADD = $(top_builddir)/src/librseq.la $(DL_LIBS)

param_test_benchmark_SOURCES = param_test.c
param_test_benchmark_CPPFLAGS = $(AM_CPPFLAGS) -DBENCHMARK
param_test_benchmark_LDADD = $(top_builddir)/src/librseq.la $(DL_LIBS)

param_test_benchmark_cxx_SOURCES = param_test_cxx.cpp
param_test_benchmark_cxx_CPPFLAGS = $(AM_CPPFLAGS) -DBENCHMARK
param_test_benchmark_cxx_LDADD = $(top_builddir)/src/librseq.la $(DL_LIBS)

param_test_mm_cid_benchmark_SOURCES = param_test.c
param_test_mm_cid_benchmark_CPPFLAGS = $(AM_CPPFLAGS) -DBENCHMARK -DBUILDOPT_RSEQ_PERCPU_MM_CID
param_test_mm_cid_benchmark_LDADD = $(top_builddir)/src/librseq.la $(DL_LIBS)

param_test_mm_cid_benchmark_cxx_SOURCES = param_test_cxx.cpp
param_test_mm_cid_benchmark_cxx_CPPFLAGS = $(AM_CPPFLAGS) -DBENCHMARK -DBUILDOPT_RSEQ_PERCPU_MM_CID
param_test_mm_cid_benchmark_cxx_LDADD = $(top_builddir)/src/librseq.la $(DL_LIBS)

param_test_compare_twice_SOURCES = param_test.c
param_test_compare_twice_CPPFLAGS = $(AM_CPPFLAGS) -DRSEQ_COMPARE_TWICE
param_test_compare_twice_LDADD = $(top_builddir)/src/librseq.la $(DL_LIBS)

param_test_compare_twice_cxx_SOURCES = param_test_cxx.cpp
param_test_compare_twice_cxx_CPPFLAGS = $(AM_CPPFLAGS) -DRSEQ_COMPARE_TWICE
param_test_compare_twice_cxx_LDADD = $(top_builddir)/src/librseq.la $(DL_LIBS)

param_test_mm_cid_compare_twice_SOURCES = param_test.c
param_test_mm_cid_compare_twice_CPPFLAGS = $(AM_CPPFLAGS) -DRSEQ_COMPARE_TWICE -DBUILDOPT_RSEQ_PERCPU_MM_CID
param_test_mm_cid_compare_twice_LDADD = $(top_builddir)/src/librseq.la $(DL_LIBS)

param_test_mm_cid_compare_twice_cxx_SOURCES = param_test_cxx.cpp
param_test_mm_cid_compare_twice_cxx_CPPFLAGS = $(AM_CPPFLAGS) -DRSEQ_COMPARE_TWICE -DBUILDOPT_RSEQ_PERCPU_MM_CID
param_test_mm_cid_compare_twice_cxx_LDADD = $(top_builddir)/src/librseq.la $(DL_LIBS)

test_rseq_biased_lock_SOURCES = rseq_biased_lock.c test_rseq_biased_lock.c rseq_biased_lock.h
test_rseq_biased_lock_LDADD = $(top_builddir)/src/librseq.la $(DL_LIBS)

TESTS = \
	basic_percpu_ops_test.tap \
	basic_percpu_ops_test_cxx.tap \
	basic_percpu_ops_mm_cid_test.tap \
	basic_percpu_ops_mm_cid_test_cxx.tap \
	basic_test.tap \
	basic_test_cxx.tap \
	run_param_test.tap \
	run_param_test_cxx.tap
