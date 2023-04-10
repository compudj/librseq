# SPDX-License-Identifier: MIT

AM_CPPFLAGS += -I$(top_srcdir)/tests/utils

TEST_EXTENSIONS = .tap
TAP_LOG_DRIVER_FLAGS = --merge --comments
TAP_LOG_DRIVER = env AM_TAP_AWK='$(AWK)' \
	RSEQ_TESTS_SRCDIR='$(abs_top_srcdir)/tests' \
	RSEQ_TESTS_BUILDDIR='$(abs_top_builddir)/tests' \
	$(SHELL) $(abs_top_srcdir)/tests/utils/tap-driver.sh

noinst_PROGRAMS = \
	arch_mo.tap \
	arch_mo_cxx.tap

arch_mo_tap_SOURCES = arch-mo.c
arch_mo_tap_LDADD = $(top_builddir)/tests/utils/libtap.la $(DL_LIBS)

arch_mo_cxx_tap_SOURCES = arch-mo-cxx.cpp
arch_mo_cxx_tap_LDADD = $(top_builddir)/tests/utils/libtap.la $(DL_LIBS)

TESTS = \
	arch_mo.tap \
	arch_mo_cxx.tap
