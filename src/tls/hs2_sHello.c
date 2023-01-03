/* hs3_sHello.c
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

#include <stdint.h>

#include "tls/tls.h"
#include "tls/hs2_sHello.h"

static uint8_t *get3bytes(uint8_t *buff, uint32_t *v)
{
    *v = buff[0] << 16 | buff[1] << 8 | buff[2];
    return buff + 3;
}

static uint8_t *get2bytes(uint8_t *buff, uint16_t *v)
{
    *v = buff[0] << 8 | buff[1];
    return buff + 2;
}

static uint8_t *get1byte(uint8_t *buff, uint8_t *v)
{
    *v = buff[0];
    return buff + 1;
}

static uint8_t *keyShare(WOLFSSL *tls, uint8_t *buff)
{
    
    return buff;
}

BBW_LOCAL void bW_DoServerHello(WOLFSSL *tls, uint8_t *buff, int len)
{
    uint32_t msgLen;
    uint16_t version;
    uint8_t *random;
    #define RANDOM_SIZE 32
    uint8_t sessionIdLen;
    uint16_t suite;
    uint8_t  compMethod;
    uint16_t extLen;

    buff++; /* Skip message type */
    buff = get3bytes(buff, &msgLen);
    random = get2bytes(buff, &version);

#if defined(BBWTLS_DEBUG)
    bW_debugDump("Server Hello", buff, msgLen);
#endif

    buff = random + RANDOM_SIZE;
    buff = get1byte (buff, &sessionIdLen);
    buff = get2bytes(buff, &suite);
    buff = get1byte (buff, &compMethod);
    buff = get2bytes(buff, &extLen);

#if defined(BBWTLS_DEBUG)
    printf("version=%04x, sessionIdLen=%d, suite*%04x, compMethod=%02x, extLen=%x\n", 
            version, sessionIdLen, suite, compMethod, extLen);
#endif

    buff = keyShare (tls, buff);
}
