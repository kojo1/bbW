/* rec.h
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

#ifndef RECORD_H
#define RECORD_H

#include "common/common.h"
#include "tls.h"

/* FRC8446 B.1. Record Layer */
typedef enum bW_ContentType {
    BW_CHANGE_CIPHER_SPEC = 20,
    BW_ALERT              = 21,
    BW_HANDSHAKE          = 22,
    BW_APPLICATON_DATA    = 23,
} bW_ContentType;

#define BW_REC_HDR 5

BBW_LOCAL void bW_recInit(WOLFSSL_CTX *ctx);

BBW_LOCAL int bW_recWrite(WOLFSSL *tls, bW_ContentType type, uint8_t *tlsRec, int len);
BBW_LOCAL int bW_processReply(WOLFSSL *tls);

#endif
