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
    BW_TLS_SERVER,
    BW_TLS_CLIENT,
} bW_SSLSide;

typedef struct {
    bW_SSLSide side;
    uint8_t  major;
    uint8_t  minor;
} WOLFSSL_METHOD;

#define BW_TLS13_MAJOR 0x3
#define BW_TLS13_MINOR 0x4
#define BW_TLS12_MAJOR 0x3
#define BW_TLS12_MINOR 0x3

/* RFC8446 B.3. Handshake Protocol */
typedef enum
{
    BW_CLIENT_HELLO = 1,
    BW_SERVER_HELLO = 2,
    BW_NEW_SESSION_TICKET = 4,
    BW_END_OF_EARLY_DATA = 5,
    BW_ENCRYPTED_EXTENSIONS = 8,
    BW_CERTIFICATE = 11,
    BW_CERTIFICATE_REQUEST = 13,
    BW_CERTIFICATE_VERIFY = 15,
    BW_FINISHED = 20,
    BW_KEY_UPDATE = 24,
    BW_MESSAGE_HASH = 254,
} bW_HandshakeType;

typedef enum {
    BW_HS_BEGIN,
    BW_HS_CHELLO_SENT,
    BW_HS_FINISHED,
} bW_HS_STAT;

typedef struct {
    uint8_t *cipherSuites;
    uint8_t *supVer;
    uint8_t *sigAlgo;
    uint8_t *supGroup;
} bW_CipherCTX;

typedef struct WOLFSSL_CTX {
    bW_EXCEPT exc;
    int     err;
    WOLFSSL_METHOD *method;
    void *write;
    void *read;
    bW_CipherCTX cCtx;
    int ref; /* reference count of child WOLFSSLs */
} WOLFSSL_CTX;

typedef struct WOLFSSL {
    bW_EXCEPT exc;
    WOLFSSL_CTX  ctx;       /* Copied of parent CTX. 
                               Items might be changed for TLS instance */
    WOLFSSL_CTX  *ctx_p;    /* for CTX level Mutex */
    WC_RNG rng;
    bW_HS_STAT stat; 
    void *wCtx;             /* for i/o callback context*/
    void *rCtx;             /* for i/o callback context*/
} WOLFSSL;

typedef int (*CallbackIORecv)(WOLFSSL *ssl, uint8_t *buf, int sz, void *ctx);
typedef int (*CallbackIOSend)(WOLFSSL *ssl, uint8_t *buf, int sz, void *ctx);

WOLFSSL_METHOD *wolfTLS_client_method(void);
WOLFSSL_METHOD *wolfTLS_server_method(void);

WOLFSSL_CTX *bbWtls_CTX_new(bW_EXCEPT *exc, WOLFSSL_METHOD *method);
void bbWtls_CTX_free(WOLFSSL_CTX *ctx);

WOLFSSL *bbWtls_new(WOLFSSL_CTX *ctx);
void bbWtls_free(WOLFSSL *tls);

void bbWtls_SetIOWriteCtx(WOLFSSL *tls, void *ctx);
void bbWtls_SetIOReadCtx(WOLFSSL *tls, void *ctx);

int  bbWtls_connect(WOLFSSL *tls);

#endif
