/* record.h
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
typedef enum YT_ContentType {
    YT_CHANGE_CIPHER_SPEC = 20,
    YT_ALERT              = 21,
    YT_HANDSHAKE          = 22,
    YT_APPLICATON_DATA    = 23,
} YT_ContentType;

#define YT_REC_HDR 5

YT_LOCAL void yt_recInit(WOLFSSL_CTX *ctx);

YT_LOCAL int yt_recWrite(WOLFSSL *tls, YT_ContentType type, uint8_t *tlsRec, int len);
#endif
