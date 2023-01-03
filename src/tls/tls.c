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

#include "common/mem.h"
#include "tls/tls.h"
#include "tls/rec.h"
#include "tls/hs1_cHello.h"

WOLFSSL_METHOD *wolfTLS_client_method(void) 
{ 
    return (WOLFSSL_METHOD *)wolfTLS_client_method;
}
WOLFSSL_METHOD *wolfTLS_server_method(void)
{
    return (WOLFSSL_METHOD *)wolfTLS_server_method;
}

WOLFSSL_CTX *bbWtls_CTX_new(bW_EXCEPT *exc, WOLFSSL_METHOD *method)
{
    WOLFSSL_CTX *ctx = BW_MALLOC(exc, sizeof(WOLFSSL_CTX));
    XMEMCPY(ctx, exc, sizeof(bW_EXCEPT));
    bW_recInit(ctx);
    return ctx;
}

void bbWtls_CTX_free(WOLFSSL_CTX *ctx)
{
    if (ctx == NULL)
        return;
    wc_LockMutex((wolfSSL_Mutex *)ctx);
    if(ctx->ref == 0)
        BW_FREE(ctx);
    wc_UnLockMutex((wolfSSL_Mutex *)ctx);
}

WOLFSSL *bbWtls_new(WOLFSSL_CTX *ctx)
{
    WOLFSSL *tls;

    if (ctx == NULL)
        RAISE(tls, BW_ERR(ERR_TLS, ERR_PTR));
    wc_LockMutex((wolfSSL_Mutex *)ctx);
    tls = BW_MALLOC((bW_EXCEPT *)ctx, sizeof(WOLFSSL));
    ctx->ref++;
    wc_UnLockMutex((wolfSSL_Mutex *)ctx);
    XMEMCPY(tls, ctx, sizeof(bW_EXCEPT));
    wc_InitRng(&tls->rng);
    tls->ctx = *ctx;
    return tls;
}

void bbWtls_free(WOLFSSL *tls)
{
    if (tls == NULL)
        return;
    wc_LockMutex((wolfSSL_Mutex *)tls->ctx_p);
    if(tls->ctx_p->ref > 0)
        tls->ctx_p->ref--;
    if(tls->ctx_p->ref == 0)
        BW_FREE(tls->ctx_p);
    wc_UnLockMutex((wolfSSL_Mutex *) tls->ctx_p);
    BW_FREE(tls);
}

void bbWtls_SetIOWriteCtx(WOLFSSL *tls, void *ctx)
{
    if(tls == NULL || ctx == NULL)
        RAISE(tls, BW_ERR(ERR_TLS, ERR_PTR));
    tls->wCtx = ctx;
}

void bbWtls_SetIOReadCtx(WOLFSSL *tls, void *ctx)
{
    if (tls == NULL || ctx == NULL)
        RAISE(tls, BW_ERR(ERR_TLS, ERR_PTR));
    tls->rCtx = ctx;
}

int bbWtls_connect(WOLFSSL *tls)
{
    if (tls == NULL)
        RAISE(tls, BW_ERR(ERR_TLS, ERR_PTR));

    switch(tls->stat) {
    case BW_HS_BEGIN:
        bW_sendClientHello(tls);
        tls->stat = BW_HS_CHELLO_SENT;
        FALL_THROUGH;

    case BW_HS_CHELLO_SENT:
        bW_processReply(tls);
        tls->stat = BW_HS_FINISHED;
        FALL_THROUGH;

    case BW_HS_FINISHED:;

    }
 
    return 0;
}
