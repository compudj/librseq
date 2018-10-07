# Copyright (C) 2016  Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
#
# THIS MATERIAL IS PROVIDED AS IS, WITH ABSOLUTELY NO WARRANTY EXPRESSED
# OR IMPLIED. ANY USE IS AT YOUR OWN RISK.
#
# Permission is hereby granted to use or copy this program for any
# purpose, provided the above notices are retained on all copies.
# Permission to modify the code and to distribute modified code is
# granted, provided the above notices are retained, and a notice that
# the code was modified is included with the above copyright notice.

CPPFLAGS += -I../include
CFLAGS += -O2 -g
LDFLAGS += -pthread

all: basic_percpu_ops_test

INCLUDES=$(wildcard ../include/rseq/*.h)

basic_percpu_ops_test: basic_percpu_ops_test.c ${INCLUDES}
	$(CC) $(CFLAGS) $(LDFLAGS) $(CPPFLAGS) -shared -fpic \
			$< -o $@

.PHONY: clean

clean:
	rm -f basic_percpu_ops_test
