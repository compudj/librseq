# SPDX-License-Identifier: MIT
#
# Copyright (C) 2019 Michael Jeanson <mjeanson@efficios.com>
#

AC_PREREQ(2.59)
AC_INIT([librseq],[0.1.0-pre],[mathieu dot desnoyers at efficios dot com], [], [https://github.com/compudj/librseq/])

# Following the numbering scheme proposed by libtool for the library version
# http://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
AC_SUBST([RSEQ_LIBRARY_VERSION], [0:0:0])

AC_CONFIG_HEADERS([include/config.h])
AC_CONFIG_AUX_DIR([config])
AC_CONFIG_MACRO_DIR([m4])

AC_CANONICAL_TARGET
AC_CANONICAL_HOST

AM_INIT_AUTOMAKE([foreign dist-bzip2 no-dist-gzip nostdinc])
AM_MAINTAINER_MODE([enable])

# Enable silent rules if available (Introduced in AM 1.11)
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_REQUIRE_AUX_FILE([tap-driver.sh])

# Checks for C compiler
AC_USE_SYSTEM_EXTENSIONS
AC_PROG_CC
AC_PROG_CC_STDC
AC_PROG_CXX

# Checks for programs.
AC_PROG_AWK
AC_PROG_MAKE_SET

LT_INIT

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

AX_C___ATTRIBUTE__
AS_IF([test "x$ax_cv___attribute__" = "xyes"],
	[:],
	[AC_MSG_ERROR([The compiler does not support __attribute__ extensions])])

AX_PTHREAD(,[AC_MSG_ERROR([Could not configure pthreads support])])

AM_CFLAGS="$AM_CFLAGS $PTHREAD_CFLAGS"

# Checks for library functions.
AC_FUNC_MMAP
AC_FUNC_FORK
AC_CHECK_FUNCS([ \
	memset \
	strerror \
])

# AC_FUNC_MALLOC causes problems when cross-compiling.
#AC_FUNC_MALLOC

# Check for headers
AC_HEADER_STDBOOL
AC_CHECK_HEADERS([ \
	limits.h \
	stddef.h \
])

AC_CHECK_HEADER([linux/rseq.h])
AS_IF([test "x${ac_cv_header_linux_rseq_h}" != "xyes"], [
	AC_MSG_ERROR([Cannot find 'linux/rseq.h'.])
])

AM_CPPFLAGS="-include config.h"
AC_SUBST(AM_CPPFLAGS)

AM_CFLAGS="-Wall -Wextra $AM_CFLAGS"
AC_SUBST(AM_CFLAGS)

AC_CONFIG_FILES([
	Makefile
	include/Makefile
	src/Makefile
	src/librseq.pc
])

AC_OUTPUT

#
# Mini-report on what will be built.
#

PPRINT_INIT
PPRINT_SET_INDENT(1)
PPRINT_SET_TS(38)

AS_ECHO
AS_ECHO("${PPRINT_COLOR_BLDBLU}librseq $PACKAGE_VERSION${PPRINT_COLOR_RST}")
AS_ECHO

PPRINT_SUBTITLE([Features])

PPRINT_PROP_STRING([Target architecture], $host_cpu)

report_bindir="`eval eval echo $bindir`"
report_libdir="`eval eval echo $libdir`"

# Print the bindir and libdir this `make install' will install into.
AS_ECHO
PPRINT_SUBTITLE([Install directories])
PPRINT_PROP_STRING([Binaries], [$report_bindir])
PPRINT_PROP_STRING([Libraries], [$report_libdir])
