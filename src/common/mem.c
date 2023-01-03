/* mem.c
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

#include "common/except.h"
#include "common/mem.h"
#include "common/error.h"

#include "wolfssl/wolfcrypt/memory.h"

static void *bW_heap;

void *bW_malloc(bW_EXCEPT *exc, size_t sz)
{
    void *p = wolfSSL_Malloc(sz);
    if(p == NULL)
        RAISE(exc, ERR_MEMORY);
    return p + sizeof(uint16_t);
}

void bW_free(void *p)
{
    if(p == NULL)
        return;
    wolfSSL_Free(p - sizeof(uint16_t));
}
