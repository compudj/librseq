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

CPPFLAGS = -O2 -g -I./include
LDFLAGS = -pthread

all: librseq.so

INCLUDES=$(wildcard remote/*.h)

librseq.so: src/rseq.c ${INCLUDES}
	$(CC) $(CFLAGS) $(LDFLAGS) $(CPPFLAGS) -shared -fpic src/rseq.c -o $@

.PHONY: clean fetch

clean:
	rm -f librseq.so
