/* hs1_cHello.c
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

#include "wolfssl/wolfcrypt/settings.h"

#include "wolfssl/wolfcrypt/random.h"
#include "tls/tls.h"
#include "tls/record.h"
#include "tls/extention.h"
#include "tls/handshake.h"

static uint8_t *setSigAlgo(uint8_t *buf) { return buf; };
static uint8_t *supportedGroups(uint8_t *buf) { return buf; };
static uint8_t *keyShare(uint8_t *buf) { return buf; };

/* FRC8446 B .4. Cipher Suites */
typedef struct {
    uint8_t value[2];
} CipherSuite;

#define TLS_AES_128_GCM_SHA256       {0x13, 0x01}
#define TLS_AES_256_GCM_SHA384       {0x13, 0x02}
#define TLS_CHACHA20_POLY1305_SHA256 {0x13, 0x03}
#define TLS_AES_128_CCM_SHA256       {0x13, 0x04}
#define TLS_AES_128_CCM_8_SHA256     {0x13, 0x05}

static CipherSuite cipherSuites[] = {
#if defined(HAVE_AESGCM)
    TLS_AES_128_GCM_SHA256,
#endif
#if defined(HAVE_AESGCM) && defined(WOLFSSL_SHA384)
    TLS_AES_256_GCM_SHA384,
#endif
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    TLS_CHACHA20_POLY1305_SHA256,
#endif
#if defined(HAVE_AESCCM)
    TLS_AES_128_CCM_SHA256,
    TLS_AES_128_CCM_8_SHA256,
#endif
};

static uint8_t *setRandom(uint8_t *buff)
{
    #define RANDOM_SIZE 32
    WC_RNG rng;
    wc_InitRng(&rng);
    wc_RNG_GenerateBlock(&rng, buff, RANDOM_SIZE);
    buff += RANDOM_SIZE;
    return buff;
}

static uint8_t *setSessionId(uint8_t *buff)
{
    #define SESSION_ID 0
    *buff++ = SESSION_ID;
    return buff;
}

static uint8_t *setCompMethods(uint8_t *buff)
{
#define COMP_METHOD_NUM 1
#define COMP_METHOD 0
    *buff++ = COMP_METHOD_NUM; /* 0x01 */
    *buff++ = COMP_METHOD;     /* 0x00 */
    return buff;
}

static uint8_t *setCipherSuites(uint8_t * buff)
{
    buff = yt_set2bytes(buff, (uint16_t)sizeof(cipherSuites));
    XMEMCPY(buff, cipherSuites, sizeof(cipherSuites));
    return buff + sizeof(cipherSuites);
}

static int getCipherSuitesLen()
{
    return sizeof(cipherSuites) + 2;
}


/* RFC8446 4.1.2. Client Hello */
YT_LOCAL void yt_sendClientHello(WOLFSSL *tls)
{
    uint8_t *buff;    /* handshake message buffer*/
    uint8_t *recBuff; /* Record header + handshake message */
    int cHelloSize;

    #define LEN_LEN          2
    #define PROTO_VER_LEN    2
    #define CHELLO_HEAD_LEN  4
    #define SESSION_ID_LEN   1
    #define RANDOM_LEN      32
    #define COMP_METHODS_LEN 2

    cHelloSize =
        LEN_LEN + PROTO_VER_LEN + RANDOM_LEN + SESSION_ID_LEN +
        getCipherSuitesLen() + COMP_METHODS_LEN + yt_getExtentionsLen();

    recBuff = XMALLOC(YT_REC_HDR + CHELLO_HEAD_LEN + cHelloSize, NULL, YT_HEAP);
    buff = recBuff + YT_REC_HDR;

    *buff++ = YT_CLIENT_HELLO;
    buff = yt_set3bytes(buff, cHelloSize);
    *buff++ = YT_TLS12_MAJOR;
    *buff++ = YT_TLS12_MINOR;

    /* Client Hello Items */
    buff = setRandom(buff);
    buff = setSessionId(buff);
    buff = setCipherSuites(buff);
    buff = setCompMethods(buff);

    /* Extentions */
    buff = yt_set2bytes(buff, yt_getExtentionsLen());
    buff = yt_setSupportedVer(buff);
    buff = yt_setSigAlogs(buff);
    buff = yt_setSupportedGroups(buff);
    buff = yt_setKeyShare(buff);

    yt_recWrite(tls, YT_HANDSHAKE, recBuff, CHELLO_HEAD_LEN + cHelloSize);

    #if defined(YT_DEBUG)
    yt_debugDump("Client Hello", recBuff, YT_REC_HDR + CHELLO_HEAD_LEN + cHelloSize);
    #endif

    XFREE(recBuff, NULL, YT_HEAP);
}
