/* tls.c
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

#include "ssl.h"

WOLFSSL_CTX *wolfSSL_CTX_new(SSLSide side)
{
    WOLFSSL_CTX *ctx = XMALLOC(sizeof(WOLFSSL_CTX), NULL, YT_HEAP);

    yt_recInit(ctx);
    return ctx;
}

void wolfSSL_CTX_free(WOLFSSL_CTX *ctx)
{
    XFREE(ctx, NULL, YT_HEAP);
}

WOLFSSL *wolfSSL_new(WOLFSSL_CTX *ctx)
{
    WOLFSSL *tls = XMALLOC(sizeof(WOLFSSL), NULL, YT_HEAP);
    tls->ctx = ctx;
    return tls;
}

void wolfSSL_free(WOLFSSL *tls)
{
    XFREE(tls, NULL, YT_HEAP);
}

void wolfSSL_SetIOWriteCtx(WOLFSSL *tls, void *ctx)
{
        tls->wCtx = ctx;
}

void olfSSL_SetIOReadCtx(WOLFSSL *tls, void *ctx)
{
    tls->rCtx = ctx;
}

int wolfSSL_connect(WOLFSSL *tls)
{

    yt_sendClientHello(tls);
    return 0;

}
