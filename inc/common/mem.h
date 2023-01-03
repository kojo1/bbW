/* mem.h
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#include <stddef.h>
#include "common/except.h"

#define BW_MALLOC(exc, sz) bW_malloc(((bW_EXCEPT *)exc), sz)
#define BW_FREE(p)         bW_free(p)
#define BW_MEMCPY(to, from, size) memcpy(to, from, size)
#define bW_MEMSET(p, v, sz)       memset(p, v, sz)

void *bW_malloc(bW_EXCEPT *exc, size_t sz);
void  bW_free(void *p);