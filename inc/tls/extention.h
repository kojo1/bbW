/* extention.h
 *
 * Copyright     = C 2006-2022 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 *     = at your option any later version.
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



/* RFC8446 4.2. Extensions */
typedef enum
{
    YT_SERVER_NAME=0 ,                             /* RFC 6066 */
    YT_MAX_FRAGMENT_LENGTH=1 ,                     /* RFC 6066 */
    YT_STATUS_REQUEST=5 ,                          /* RFC 6066 */
    YT_SUPPORTED_GROUPS=10 ,                       /* RFC 8422, 7919 */
    YT_SIGNATURE_ALGORITHMS=13 ,                   /* RFC 8446 */
    YT_USE_SRTP=14 ,                               /* RFC 5764 */
    YT_HEARTBEAT=15 ,                              /* RFC 6520 */
    YT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION=16 , /* RFC 7301 */
    YT_SIGNED_CERTIFICATE_TIMESTAMP=18 ,           /* RFC 6962 */
    YT_CLIENT_CERTIFICATE_TYPE=19 ,                /* RFC 7250 */
    YT_SERVER_CERTIFICATE_TYPE=20 ,                /* RFC 7250 */
    YT_PADDING=21 ,                                /* RFC 7685 */
    YT_PRE_SHARED_KEY=41 ,                         /* RFC 8446 */
    YT_EARLY_DATA=42 ,                             /* RFC 8446 */
    YT_SUPPORTED_VERSIONS=43 ,                     /* RFC 8446 */
    YT_COOKIE=44 ,                                 /* RFC 8446 */
    YT_PSK_KEY_EXCHANGE_MODES=45 ,                 /* RFC 8446 */
    YT_CERTIFICATE_AUTHORITIES=47 ,                /* RFC 8446 */
    YT_OID_FILTERS=48 ,                            /* RFC 8446 */
    YT_POST_HANDSHAKE_AUTH=49 ,                    /* RFC 8446 */
    YT_SIGNATURE_ALGORITHMS_CERT=50 ,              /* RFC 8446 */
    YT_KEY_SHARE=51 ,                              /* RFC 8446 */
} YT_extType;

/* RFC8446 4.2.3. Signature Algorithms */
enum {
    /* RSASSA-PKCS1-v1_5 algorithms */
    YT_RSA_PKCS1_SHA256 = 0X0401,
    YT_RSA_PKCS1_SHA384 = 0X0501,
    YT_RSA_PKCS1_SHA512 = 0X0601,

    /* ECDSA ALGORITHMS */
    YT_ECDSA_SECP256R1_SHA256 = 0X0403,
    YT_ECDSA_SECP384R1_SHA384 = 0X0503,
    YT_ECDSA_SECP521R1_SHA512 = 0X0603,

    /* RSASSA-PSS ALGORITHMS WITH PUBLIC KEY OID RSAENCRYPTION */
    YT_RSA_PSS_RSAE_SHA256 = 0X0804,
    YT_RSA_PSS_RSAE_SHA384 = 0X0805,
    YT_RSA_PSS_RSAE_SHA512 = 0X0806,

    /* EDDSA ALGORITHMS */
    YT_ED25519 = 0X0807,
    YT_ED448 = 0X0808,

    /* RSASSA-PSS ALGORITHMS WITH PUBLIC KEY OID RSASSA-PSS */
    YT_RSA_PSS_PSS_SHA256 = 0X0809,
    YT_RSA_PSS_PSS_SHA384 = 0X080A,
    YT_RSA_PSS_PSS_SHA512 = 0X080B,

    /* LEGACY ALGORITHMS */
    YT_RSA_PKCS1_SHA1 = 0X0201,
    YT_ECDSA_SHA1 = 0X0203,

    /* RESERVED CODE POINTS */
    PRIVATE_USE = 0XFE00,

} YT_SignatureScheme;



/* RFC8446 4.2.7. Supported Groups */
enum
{

    /* Elliptic Curve Groups (ECDHE) */
    YT_SECP256R1 = 0X0017,
    YT_SECP384R1 = 0X0018,
    YT_SECP521R1 = 0X0019,
    YT_X25519    = 0X001D,
    YT_X448      = 0X001E,

    /* Finite Field Groups DHE */
    YT_FFDHE2048 = 0X0100,
    YT_FFDHE3072 = 0X0101,
    YT_FFDHE4096 = 0X0102,
    YT_FFDHE6144 = 0X0103,
    YT_FFDHE8192 = 0X0104,

    /* Reserved Code Points */
    YT_FFDHE_PRIVATE_USE,
    YT_ECDHE_PRIVATE_USE,
} YT_NamedGroup;

YT_LOCAL uint8_t *yt_set2bytes(uint8_t *buff, int len);
YT_LOCAL uint8_t *yt_set3bytes(uint8_t *buff, int len);
YT_LOCAL uint8_t *yt_setExtentionHeader(uint8_t *buff, YT_extType type, int len);

YT_LOCAL int yt_getExtLenSupportedVer(void);
YT_LOCAL int yt_getExtentionsLen(void);
YT_LOCAL uint8_t *yt_setSupportedGroups(uint8_t *buff);
YT_LOCAL uint8_t *yt_setKeyShare(uint8_t *buff);
YT_LOCAL uint8_t *yt_setSupportedVer(uint8_t *buff);
YT_LOCAL uint8_t *yt_setSigAlogs(uint8_t *buff);