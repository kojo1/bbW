/* ext.h
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
    BW_SERVER_NAME=0 ,                             /* RFC 6066 */
    BW_MAX_FRAGMENT_LENGTH=1 ,                     /* RFC 6066 */
    BW_STATUS_REQUEST=5 ,                          /* RFC 6066 */
    BW_SUPPORTED_GROUPS=10 ,                       /* RFC 8422, 7919 */
    BW_SIGNATURE_ALGORITHMS=13 ,                   /* RFC 8446 */
    BW_USE_SRTP=14 ,                               /* RFC 5764 */
    BW_HEARTBEAT=15 ,                              /* RFC 6520 */
    BW_APPLICATION_LAYER_PROTOCOL_NEGOTIATION=16 , /* RFC 7301 */
    BW_SIGNED_CERTIFICATE_TIMESTAMP=18 ,           /* RFC 6962 */
    BW_CLIENT_CERTIFICATE_TYPE=19 ,                /* RFC 7250 */
    BW_SERVER_CERTIFICATE_TYPE=20 ,                /* RFC 7250 */
    BW_PADDING=21 ,                                /* RFC 7685 */
    BW_PRE_SHARED_KEY=41 ,                         /* RFC 8446 */
    BW_EARLY_DATA=42 ,                             /* RFC 8446 */
    BW_SUPPORTED_VERSIONS=43 ,                     /* RFC 8446 */
    BW_COOKIE=44 ,                                 /* RFC 8446 */
    BW_PSK_KEY_EXCHANGE_MODES=45 ,                 /* RFC 8446 */
    BW_CERTIFICATE_AUTHORITIES=47 ,                /* RFC 8446 */
    BW_OID_FILTERS=48 ,                            /* RFC 8446 */
    BW_POST_HANDSHAKE_AUTH=49 ,                    /* RFC 8446 */
    BW_SIGNATURE_ALGORITHMS_CERT=50 ,              /* RFC 8446 */
    BW_KEY_SHARE=51 ,                              /* RFC 8446 */
} bW_extType;

/* RFC8446 4.2.3. Signature Algorithms */
enum {
    /* RSASSA-PKCS1-v1_5 algorithms */
    BW_RSA_PKCS1_SHA256 = 0X0401,
    BW_RSA_PKCS1_SHA384 = 0X0501,
    BW_RSA_PKCS1_SHA512 = 0X0601,

    /* ECDSA ALGORITHMS */
    BW_ECDSA_SECP256R1_SHA256 = 0X0403,
    BW_ECDSA_SECP384R1_SHA384 = 0X0503,
    BW_ECDSA_SECP521R1_SHA512 = 0X0603,

    /* RSASSA-PSS ALGORITHMS WITH PUBLIC KEY OID RSAENCRYPTION */
    BW_RSA_PSS_RSAE_SHA256 = 0X0804,
    BW_RSA_PSS_RSAE_SHA384 = 0X0805,
    BW_RSA_PSS_RSAE_SHA512 = 0X0806,

    /* EDDSA ALGORITHMS */
    BW_ED25519 = 0X0807,
    BW_ED448 = 0X0808,

    /* RSASSA-PSS ALGORITHMS WITH PUBLIC KEY OID RSASSA-PSS */
    BW_RSA_PSS_PSS_SHA256 = 0X0809,
    BW_RSA_PSS_PSS_SHA384 = 0X080A,
    BW_RSA_PSS_PSS_SHA512 = 0X080B,

    /* LEGACY ALGORITHMS */
    BW_RSA_PKCS1_SHA1 = 0X0201,
    BW_ECDSA_SHA1 = 0X0203,

    /* RESERVED CODE POINTS */
    PRIVATE_USE = 0XFE00,

} bW_SignatureScheme;



/* RFC8446 4.2.7. Supported Groups */
enum
{

    /* Elliptic Curve Groups (ECDHE) */
    BW_SECP256R1 = 0X0017,
    BW_SECP384R1 = 0X0018,
    BW_SECP521R1 = 0X0019,
    BW_X25519    = 0X001D,
    BW_X448      = 0X001E,

    /* Finite Field Groups DHE */
    BW_FFDHE2048 = 0X0100,
    BW_FFDHE3072 = 0X0101,
    BW_FFDHE4096 = 0X0102,
    BW_FFDHE6144 = 0X0103,
    BW_FFDHE8192 = 0X0104,

    /* Reserved Code Points */
    BW_FFDHE_PRIVATE_USE,
    BW_ECDHE_PRIVATE_USE,
} bW_NamedGroup;

BBW_LOCAL uint8_t *bW_set2bytes(uint8_t *buff, int len);
BBW_LOCAL uint8_t *bW_set3bytes(uint8_t *buff, int len);
BBW_LOCAL uint8_t *bW_setExtentionHeader(uint8_t *buff, bW_extType type, int len);

BBW_LOCAL int bW_getExtLenSupportedVer(void);
BBW_LOCAL int bW_getExtentionsLen(void);
BBW_LOCAL uint8_t *bW_setSupportedGroups(WOLFSSL *tls, uint8_t *buff);
BBW_LOCAL uint8_t *bW_setKeyShare(WOLFSSL *tls, uint8_t *buff);
BBW_LOCAL uint8_t *bW_setSupportedVer(WOLFSSL *tls, uint8_t *buff);
BBW_LOCAL uint8_t *bW_setSigAlogs(WOLFSSL *tls, uint8_t *buff);