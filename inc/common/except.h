/* except.h
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

#ifndef EXCEPTION_H
#define EXCEPTION_H

#include <setjmp.h>

typedef struct {
    int code;
    jmp_buf exc;
} bW_EXCEPT;

#define TRY(e) \
    if ((((bW_EXCEPT *)e)->code = setjmp(((bW_EXCEPT *)e)->exc)) == 0)
#define RAISE(e, c) longjmp(((bW_EXCEPT *)e)->exc, (c))
#define EXCEPT else
#define CODE(e) ((bW_EXCEPT *)e)->code

#endif

