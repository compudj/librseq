# SPDX-License-Identifier: MIT
#
# Copyright (C) 2019 Michael Jeanson <mjeanson@efficios.com>
#

AM_CPPFLAGS += -I$(top_srcdir)/include -I$(top_builddir)/include

lib_LTLIBRARIES = librseq.la

librseq_la_SOURCES = \
	rseq.c

if HAVE_DO_ON_CPU
librseq_la_SOURCES += \
	cpu-op.c  \
	percpu-op.c \
	do-on-cpu-insn.h
endif

librseq_la_LDFLAGS = -no-undefined -version-info $(RSEQ_LIBRARY_VERSION)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = librseq.pc
