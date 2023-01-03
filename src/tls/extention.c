/* extention.c
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
#include "tls/extention.h"


YT_LOCAL uint8_t *yt_set2bytes(uint8_t *buff, int len)
{
    *buff++ = len >> 8;
    *buff++ = len & 0xff;
    return buff;
}

YT_LOCAL uint8_t *yt_set3bytes(uint8_t *buff, int len)
{
    *buff++ = len >> 15;
    *buff++ = len >> 8;
    *buff++ = len & 0xff;
    return buff;
}

static uint8_t *set2byteList(uint8_t *buff, uint16_t *list, int len)
{
    for (; len > 0; len--, list++, buff+=2)
        yt_set2bytes(buff, *list);
    return buff;
}

YT_LOCAL uint8_t *yt_setExtentionHeader(uint8_t *buff, YT_extType type, int len)
{
    buff = yt_set2bytes(buff, type);
    buff = yt_set2bytes(buff, len);
    return buff;
}

#define SUPPRTED_VER_LEN 2
YT_LOCAL int getExtLenSupportedVer(void)
{
    return SUPPRTED_VER_LEN + 5;
}

YT_LOCAL uint8_t *yt_setSupportedVer(uint8_t *buff)
{
    buff = yt_setExtentionHeader(buff, YT_SUPPORTED_VERSIONS, SUPPRTED_VER_LEN + 1);

    /* Extention body */
    *buff++ = SUPPRTED_VER_LEN; /* Supported Verion Length */
    *buff++ = YT_TLS13_MAJOR;
    *buff++ = YT_TLS13_MINOR;
    return buff;
}

static uint16_t sigAlogs[] = {
/* RSASSA-PKCS1-v1_5 algorithms */
#if !defined(NO_RSA)
    #if !defined(NO_SHA256)
        YT_RSA_PKCS1_SHA256,
    #endif
    #if defined(WOLFSSL_SHA384)
        YT_RSA_PKCS1_SHA384,
    #endif
    #if defined(WOLFSSL_SHA512)
        YT_RSA_PKCS1_SHA512,
    #endif
#endif

    /* ECDSA Algorithms */
#if defined(HAVE_ECC)
    #if !defined(NO_SHA256)
        YT_ECDSA_SECP256R1_SHA256,
    #endif
    #if defined(WOLFSSL_SHA384)
        YT_ECDSA_SECP384R1_SHA384,
    #endif
    #if defined(WOLFSSL_SHA512)
        YT_ECDSA_SECP521R1_SHA512,
    #endif
#endif

/* RSASSA-PSS Algorithms with public key OID RSAencryption */
#if !defined(NO_RSA)
    #if !defined(NO_SHA256)
        YT_RSA_PSS_RSAE_SHA256,
    #endif
    #if defined(WOLFSSL_SHA384)
        YT_RSA_PSS_RSAE_SHA384,
    #endif
    #if defined(WOLFSSL_SHA512)
        YT_RSA_PSS_RSAE_SHA512,
    #endif
#endif

    /* EDDSA Algorithms */
#if defined(HAVE_ED25519)
        YT_ED25519,
#endif
#if defined(HAVE_ED448)
        YT_ED448,
#endif

/* RSASSA-PSS Algorithms with public key OID RSASSA-PSS */
#if !defined(NO_RSA) && defined(WC_RSA_PSS)
    #if !defined(NO_SHA256)
        YT_RSA_PSS_PSS_SHA256,
    #endif
    #if defined(WOLFSSL_SHA384)
        YT_RSA_PSS_PSS_SHA384,
    #endif
    #if defined(WOLFSSL_SHA512)
        YT_RSA_PSS_PSS_SHA512,
    #endif
#endif

/* Legacy algorithms */
#if !defined(NO_RSA) && !defined(NO_SHA)
        YT_RSA_PKCS1_SHA1,
#endif
};

static int getExtLenSigAlogs(void)
{
    return sizeof(sigAlogs) + 6;
}

YT_LOCAL uint8_t *yt_setSigAlogs(uint8_t *buff)
{
    buff = yt_setExtentionHeader(buff, YT_SIGNATURE_ALGORITHMS, sizeof(sigAlogs) + 2);
    buff = yt_set2bytes(buff, (uint16_t)sizeof(sigAlogs));
    buff = set2byteList(buff, sigAlogs, sizeof(sigAlogs)/2);
    return buff;
}

static uint16_t namedGroup[] = {
    /* Elliptic Curve Groups (ECDHE) */
#if defined(HAVE_ECC)
    YT_SECP256R1,
    YT_SECP384R1,
    YT_SECP521R1,
#endif
#if defined(WOLFSSL_CURVE25519)
    YT_X25519,
#endif
#if defined(WOLFSSL_CURVE448)
    YT_X448,
#endif

    /* Finite Field Groups DHE */
#if !defined(NO_DH)
    YT_FFDHE2048,
    YT_FFDHE3072,
    YT_FFDHE4096,
    YT_FFDHE6144,
    YT_FFDHE8192,
#endif
};

static int getExtLenSupportedGroups(void){
    return sizeof(namedGroup) + 6;
}

YT_LOCAL uint8_t *yt_setSupportedGroups(uint8_t *buff)
{
    buff = yt_setExtentionHeader(buff, YT_SUPPORTED_GROUPS, sizeof(namedGroup)+ 2);
    buff = yt_set2bytes(buff, (uint16_t)sizeof(namedGroup));
    buff = set2byteList(buff, namedGroup, sizeof(namedGroup)/2);
    return buff;
}

static int getExtLenKeyShare(void)
{
    return 4;
}

YT_LOCAL uint8_t *yt_setKeyShare(uint8_t *buff)
{
    buff = yt_setExtentionHeader(buff, YT_KEY_SHARE, 0);
    return buff;
}

YT_LOCAL int yt_getExtentionsLen()
{
    int len = 0;
    len += getExtLenSupportedVer();
    len += getExtLenSigAlogs();
    len += getExtLenSupportedGroups();
    len += getExtLenKeyShare();
    return len;
}