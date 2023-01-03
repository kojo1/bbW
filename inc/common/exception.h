/* exception.h
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

typedef struct yT_exception {
    jmp_buf jmp;
    struct yT_exception *parent;
    int err;
} yT_exception;

typedef struct {
    yT_exception exc;
} yT_Exception_ctx;

#define yT_onException_return(ctx, errno)        \
    {                                            \
        int ret;                                 \
        if ((ret = setjmp((ctx)->exc.jmp)) != 0) \
            (ctx)->exc.err = (errno & 0xffff) << 16 | ret; \
            return (ctx)->exc.err;               \
    }

#define yT_onException_goto(ctx, to, errno)        \
    {                                              \
        int ret;                                   \
        if ((ret = setjmp((ctx)->exc.jmp)) != 0) { \
            (ctx)->exc.err = (errno & 0xffff) << 16 | ret; \
            goto to;                               \
        }                                          \
    }

#define yT_raiseException(ctx, err) \
    longjmp((ctx)->exc.jmp, err);

#define yt_getErrMajor(ctx) (((ctx)->exc.err) >> 16)
#define yt_getErrMinor(ctx) (((ctx)->exc.err) & 0xffff)

#endif

