/* tls.h
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

#ifndef TLS_H
#define TLS_H

#include "common/common.h"

typedef enum {
    YT_TLS_SERVER,
    YT_TLS_CLIENT,
} SSLSide;

#define YT_TLS13_MAJOR 0x3
#define YT_TLS13_MINOR 0x4
#define YT_TLS12_MAJOR 0x3
#define YT_TLS12_MINOR 0x3

typedef struct WOLFSSL_CTX {
    yT_exception exc;
    int     err;
    SSLSide side;
    void *write;
    void *read;
} WOLFSSL_CTX;

typedef struct WOLFSSL {
    yT_exception exc;
    WOLFSSL_CTX *ctx;
    void  *wCtx;
    void  *rCtx;
} WOLFSSL;

typedef int (*CallbackIORecv)(WOLFSSL *ssl, char *buf, int sz, void *ctx);
typedef int (*CallbackIOSend)(WOLFSSL *ssl, char *buf, int sz, void *ctx);


WOLFSSL_CTX *wolfSSL_CTX_new(SSLSide side);
void wolfSSL_CTX_free(WOLFSSL_CTX *ctx);

WOLFSSL *wolfSSL_new(WOLFSSL_CTX *ctx);
void wolfSSL_free(WOLFSSL *tls);

void wolfSSL_SetIOWriteCtx(WOLFSSL *tls, void *ctx);
void wolfSSL_SetIOReadCtx(WOLFSSL *tls, void *ctx);

int  wolfSSL_connect(WOLFSSL *tls);

#endif
