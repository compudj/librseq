// SPDX-License-Identifier: LGPL-2.1-only
/*
 * percpu-op.c
 *
 * Copyright (C) 2017 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; only
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <rseq/rseq.h>
#include <rseq/cpu-op.h>
