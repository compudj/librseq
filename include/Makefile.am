# SPDX-License-Identifier: MIT
#
# Copyright (C) 2019 Michael Jeanson <mjeanson@efficios.com>
#

nobase_include_HEADERS = \
	rseq/rseq.h \
	rseq/rseq-arm.h \
	rseq/rseq-mips.h \
	rseq/rseq-ppc.h \
	rseq/rseq-s390.h \
	rseq/rseq-skip.h \
	rseq/rseq-x86.h

if HAVE_CPU_OPV
nobase_include_HEADERS += \
	rseq/cpu-op.h \
	rseq/percpu-op.h
endif
