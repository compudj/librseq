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
