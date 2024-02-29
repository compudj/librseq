# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2022 EfficiOS Inc.

lib_LTLIBRARIES = librseq.la

librseq_la_SOURCES = \
	rseq.c rseq-percpu-alloc.c

librseq_la_LDFLAGS = -no-undefined -version-info $(RSEQ_LIBRARY_VERSION)
librseq_la_LIBADD = $(DL_LIBS)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = librseq.pc
