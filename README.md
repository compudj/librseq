Library for Restartable Sequences
=================================

by Mathieu Desnoyers


Building
--------

    make
    make install

Requirements
------------

It requires Linux kernel headers from kernel >= 4.18 to build on x86, arm, ppc,
and mips. It requires Linux kernel headers from kernel >= 4.19 to build on
s390.

Building against local version of kernel headers
------------------------------------------------

cd /path/to/kernel/sources
make headers_install
cd /path/to/librseq
CPPFLAGS=-I/path/to/kernel/sources/usr/include make
