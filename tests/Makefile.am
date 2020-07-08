# SPDX-License-Identifier: MIT
#
# Copyright (C) 2019 Michael Jeanson <mjeanson@efficios.com>
#

AM_CFLAGS += -I$(top_srcdir)/include -I$(top_builddir)/include

noinst_PROGRAMS = basic_percpu_ops_test basic_test param_test \
		  param_test_benchmark param_test_compare_twice

basic_percpu_ops_test_SOURCES = basic_percpu_ops_test.c
basic_percpu_ops_test_LDADD = $(top_builddir)/src/librseq.la

basic_test_SOURCES = basic_test.c
basic_test_LDADD = $(top_builddir)/src/librseq.la

param_test_SOURCES = param_test.c
param_test_LDADD = $(top_builddir)/src/librseq.la

param_test_benchmark_SOURCES = param_test.c
param_test_benchmark_CPPFLAGS = -DBENCHMARK
param_test_benchmark_LDADD = $(top_builddir)/src/librseq.la

param_test_compare_twice_SOURCES = param_test.c
param_test_compare_twice_CPPFLAGS = -DRSEQ_COMPARE_TWICE
param_test_compare_twice_LDADD = $(top_builddir)/src/librseq.la

TESTS = basic_percpu_ops_test basic_test run_param_test.sh
