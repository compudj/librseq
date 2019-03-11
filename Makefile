# SPDX-License-Identifier: MIT
#
# Copyright (C) 2016  Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
#

SUBDIRS = tests/

CPPFLAGS += -I./include
CFLAGS += -O2 -g
LDFLAGS += -pthread

PREFIX = /usr/local

all: librseq.so subdirs

subdirs:
	for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir; \
	done

INCLUDES=$(wildcard include/rseq/*.h)

librseq.so: src/rseq.c src/cpu-op.c src/percpu-op.c ${INCLUDES}
	$(CC) $(CFLAGS) $(LDFLAGS) $(CPPFLAGS) -shared -fpic \
			src/rseq.c src/cpu-op.c src/percpu-op.c -o $@

.PHONY: clean install uninstall subdirs

clean:
	$(MAKE) -C $(SUBDIRS) clean
	rm -f librseq.so

install: librseq.so
	mkdir -p $(DESTDIR)$(PREFIX)/lib
	cp librseq.so $(DESTDIR)$(PREFIX)/lib/librseq.so
	mkdir -p $(DESTDIR)$(PREFIX)/include/rseq
	cp include/rseq/*.h $(DESTDIR)$(PREFIX)/include/rseq

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/lib/librseq.so
	rm -f $(DESTDIR)$(PREFIX)/include/rseq/*.h
	rmdir $(DESTDIR)$(PREFIX)/include/rseq/
