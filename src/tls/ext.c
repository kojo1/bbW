/* ext.c
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

#include "common/common.h"
#include "tls/tls.h"
#include "tls/ext.h"

#include "wolfssl/wolfcrypt/curve25519.h"


BBW_LOCAL uint8_t *bW_set2bytes(uint8_t *buff, int len)
{
    *buff++ = len >> 8;
    *buff++ = len & 0xff;
    return buff;
}

BBW_LOCAL uint8_t *bW_set3bytes(uint8_t *buff, int len)
{
    *buff++ = len >> 15;
    *buff++ = len >> 8;
    *buff++ = len & 0xff;
    return buff;
}

static uint8_t *set2byteList(uint8_t *buff, uint16_t *list, int len)
{
    for (; len > 0; len--, list++, buff+=2)
        bW_set2bytes(buff, *list);
    return buff;
}

BBW_LOCAL uint8_t *bW_setExtentionHeader(uint8_t *buff, bW_extType type, int len)
{
    buff = bW_set2bytes(buff, type);
    buff = bW_set2bytes(buff, len);
    return buff;
}

#define SUPPRTED_VER_LEN 2
BBW_LOCAL int getExtLenSupportedVer(void)
{
    return SUPPRTED_VER_LEN + 5;
}

BBW_LOCAL uint8_t *bW_setSupportedVer(WOLFSSL *tls, uint8_t *buff)
{
    buff = bW_setExtentionHeader(buff, BW_SUPPORTED_VERSIONS, SUPPRTED_VER_LEN + 1);

    /* Extention body */
    *buff++ = SUPPRTED_VER_LEN; /* Supported Verion Length */
    *buff++ = BW_TLS13_MAJOR;
    *buff++ = BW_TLS13_MINOR;
    return buff;
}

static uint16_t sigAlogs[] = {
/* RSASSA-PKCS1-v1_5 algorithms */
#if !defined(NO_RSA)
    #if !defined(NO_SHA256)
        BW_RSA_PKCS1_SHA256,
    #endif
    #if defined(WOLFSSL_SHA384)
        BW_RSA_PKCS1_SHA384,
    #endif
    #if defined(WOLFSSL_SHA512)
        BW_RSA_PKCS1_SHA512,
    #endif
#endif

    /* ECDSA Algorithms */
#if defined(HAVE_ECC)
    #if !defined(NO_SHA256)
        BW_ECDSA_SECP256R1_SHA256,
    #endif
    #if defined(WOLFSSL_SHA384)
        BW_ECDSA_SECP384R1_SHA384,
    #endif
    #if defined(WOLFSSL_SHA512)
        BW_ECDSA_SECP521R1_SHA512,
    #endif
#endif

/* RSASSA-PSS Algorithms with public key OID RSAencryption */
#if !defined(NO_RSA)
    #if !defined(NO_SHA256)
        BW_RSA_PSS_RSAE_SHA256,
    #endif
    #if defined(WOLFSSL_SHA384)
        BW_RSA_PSS_RSAE_SHA384,
    #endif
    #if defined(WOLFSSL_SHA512)
        BW_RSA_PSS_RSAE_SHA512,
    #endif
#endif

    /* EDDSA Algorithms */
#if defined(HAVE_ED25519)
        BW_ED25519,
#endif
#if defined(HAVE_ED448)
        BW_ED448,
#endif

/* RSASSA-PSS Algorithms with public key OID RSASSA-PSS */
#if !defined(NO_RSA) && defined(WC_RSA_PSS)
    #if !defined(NO_SHA256)
        BW_RSA_PSS_PSS_SHA256,
    #endif
    #if defined(WOLFSSL_SHA384)
        BW_RSA_PSS_PSS_SHA384,
    #endif
    #if defined(WOLFSSL_SHA512)
        BW_RSA_PSS_PSS_SHA512,
    #endif
#endif

/* Legacy algorithms */
#if !defined(NO_RSA) && !defined(NO_SHA)
        BW_RSA_PKCS1_SHA1,
#endif
};

static int getExtLenSigAlogs(void)
{
    return sizeof(sigAlogs) + 6;
}

BBW_LOCAL uint8_t *bW_setSigAlogs(WOLFSSL *tls, uint8_t *buff)
{
    buff = bW_setExtentionHeader(buff, BW_SIGNATURE_ALGORITHMS, sizeof(sigAlogs) + 2);
    buff = bW_set2bytes(buff, (uint16_t)sizeof(sigAlogs));
    buff = set2byteList(buff, sigAlogs, sizeof(sigAlogs)/2);
    return buff;
}

static uint16_t namedGroup[] = {
    /* Elliptic Curve Groups (ECDHE) */
#if defined(HAVE_ECC)
    BW_SECP256R1,
    BW_SECP384R1,
    BW_SECP521R1,
#endif
#if defined(HAVE_CURVE25519)
    BW_X25519,
#endif
#if defined(HAVE_CURVE448)
    BW_X448,
#endif

    /* Finite Field Groups DHE */
#if !defined(NO_DH)
    BW_FFDHE2048,
    BW_FFDHE3072,
    BW_FFDHE4096,
    BW_FFDHE6144,
    BW_FFDHE8192,
#endif
};

static int getExtLenSupportedGroups(void){
    return sizeof(namedGroup) + 6;
}

BBW_LOCAL uint8_t *bW_setSupportedGroups(WOLFSSL *tls, uint8_t *buff)
{
    buff = bW_setExtentionHeader(buff, BW_SUPPORTED_GROUPS, sizeof(namedGroup)+ 2);
    buff = bW_set2bytes(buff, (uint16_t)sizeof(namedGroup));
    buff = set2byteList(buff, namedGroup, sizeof(namedGroup)/2);
    return buff;
}

static uint8_t *getKeyShare_genCurve25519(WOLFSSL *tls, uint8_t *pub)
{
    int ret;
    uint32_t pubSz = CURVE25519_KEYSIZE;
    curve25519_key key; /* to be stored in tls */
    
    if (wc_curve25519_init(&key) != 0)
        RAISE(tls, BW_ERR(ERR_CURVE25519, ERR_INIT));

    if(wc_curve25519_make_key(&tls->rng, CURVE25519_KEYSIZE, &key) != 0)
        RAISE(tls, BW_ERR(ERR_CURVE25519, ERR_KEYGEN));
    if (wc_curve25519_export_public_ex(&key, pub, &pubSz,
                                       EC25519_LITTLE_ENDIAN) != 0)
        RAISE(tls, BW_ERR(ERR_CURVE25519, ERR_PUBEX));

    return pub + CURVE25519_KEYSIZE;
}

static int getExtLenKeyShare(void)
{
    return 10 + CURVE25519_KEYSIZE;
}

BBW_LOCAL uint8_t *bW_setKeyShare(WOLFSSL *tls, uint8_t *buff)
{
    buff = bW_setExtentionHeader(buff, BW_KEY_SHARE, 38);
    buff = bW_set2bytes(buff, 36);

    buff = bW_set2bytes(buff, BW_X25519);
    buff = bW_set2bytes(buff, 32);

    buff = getKeyShare_genCurve25519(tls, buff);

    return buff;
}

BBW_LOCAL int bW_getExtentionsLen()
{
    int len = 0;
    len += getExtLenSupportedVer();
    len += getExtLenSigAlogs();
    len += getExtLenSupportedGroups();
    len += getExtLenKeyShare();
    return len;
}