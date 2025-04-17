# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2022 EfficiOS Inc.

lib_LTLIBRARIES = librseq.la

librseq_la_SOURCES = \
	rseq.c rseq-mempool.c rseq-utils.h smp.c smp.h list.h \
	percpu-counter-tree.c rcu.c rcu.h

librseq_la_LDFLAGS = -no-undefined -version-info $(RSEQ_LIBRARY_VERSION)
librseq_la_LIBADD = $(DL_LIBS)

if ENABLE_NUMA
librseq_la_LIBADD += -lnuma
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = librseq.pc
