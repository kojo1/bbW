/* handshake.h
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


#include "tls/hs1_cHello.h"

/* RFC8446 B.3. Handshake Protocol */
typedef enum {
    YT_CLIENT_HELLO         = 1,
    YT_SERVER_HELLO         = 2,
    YT_NEW_SESSION_TICKET   = 4,
    YT_END_OF_EARLY_DATA    = 5,
    YT_ENCRYPTED_EXTENSIONS = 8,
    YT_CERTIFICATE          = 11,
    YT_CERTIFICATE_REQUEST  = 13,
    YT_CERTIFICATE_VERIFY   = 15,
    YT_FINISHED             = 20,
    YT_KEY_UPDATE           = 24,
    YT_MESSAGE_HASH         = 254,
} YT_HandshakeType;

