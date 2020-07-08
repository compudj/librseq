# SPDX-License-Identifier: MIT
#
# Copyright (C) 2020 Michael Jeanson <mjeanson@efficios.com>
#

AM_CFLAGS += -I$(top_srcdir)/include -I$(top_builddir)/include -I$(top_srcdir)/tests/utils

SUBDIRS = utils

TEST_EXTENSIONS = .tap
TAP_LOG_DRIVER_FLAGS = --merge --comments
TAP_LOG_DRIVER = env AM_TAP_AWK='$(AWK)' \
	RSEQ_TESTS_SRCDIR='$(abs_top_srcdir)/tests' \
	RSEQ_TESTS_BUILDDIR='$(abs_top_builddir)/tests' \
	$(SHELL) $(srcdir)/utils/tap-driver.sh

noinst_PROGRAMS = basic_percpu_ops_test.tap basic_test.tap param_test \
		  param_test_benchmark param_test_compare_twice
dist_noinst_SCRIPTS = run_param_test.tap

basic_percpu_ops_test_tap_SOURCES = basic_percpu_ops_test.c
basic_percpu_ops_test_tap_LDADD = $(top_builddir)/src/librseq.la $(top_builddir)/tests/utils/libtap.la

basic_test_tap_SOURCES = basic_test.c
basic_test_tap_LDADD = $(top_builddir)/src/librseq.la $(top_builddir)/tests/utils/libtap.la

param_test_SOURCES = param_test.c
param_test_LDADD = $(top_builddir)/src/librseq.la

param_test_benchmark_SOURCES = param_test.c
param_test_benchmark_CPPFLAGS = -DBENCHMARK
param_test_benchmark_LDADD = $(top_builddir)/src/librseq.la

param_test_compare_twice_SOURCES = param_test.c
param_test_compare_twice_CPPFLAGS = -DRSEQ_COMPARE_TWICE
param_test_compare_twice_LDADD = $(top_builddir)/src/librseq.la

TESTS = basic_percpu_ops_test.tap basic_test.tap run_param_test.tap
