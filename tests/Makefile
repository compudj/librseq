# SPDX-License-Identifier: MIT
#
# Copyright (C) 2016  Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
#

CPPFLAGS += -I../include
CFLAGS += -O2 -g -L../ -Wl,-rpath=../
LDFLAGS += -pthread

all: basic_percpu_ops_test

INCLUDES=$(wildcard ../include/rseq/*.h)

basic_percpu_ops_test: basic_percpu_ops_test.c ${INCLUDES}
	$(CC) $(CFLAGS) $(LDFLAGS) $(CPPFLAGS) $< -lrseq -o $@

.PHONY: clean

clean:
	rm -f basic_percpu_ops_test
