# SPDX-License-Identifier: MIT

AM_CFLAGS += -I$(top_srcdir)/include -I$(top_builddir)/include

noinst_LTLIBRARIES = libtap.la
libtap_la_SOURCES = tap.c tap.h

dist_check_SCRIPTS = \
	tap-driver.sh \
	tap.sh \
	utils.sh
