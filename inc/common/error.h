/* error.h
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

#ifndef ERROR_H
#define ERROR_H

enum
{
    ERR_SOCKET      = 101,    /* Socket error           */
    ERR_REC         = 102,    /* TLS record error */
    ERR_IO          = 103,    /* Network i/o error    */
    ERR_HANDSHAKE   = 104,    /* Error on handshake */
    ERR_MEMORY      = 104,    /* Heap memory allocation error */
    ERR_CTX         = 105,    /* Error on TLS Context operation */
    ERR_TLS         = 106,    /* Error on TLS operation */
    ERR_ECC         = 110,    /* Error on ECC operation */
    ERR_CURVE25519  = 111,    /* Error on Curve25519 operation */
    ERR_CURVE488    = 112,    /* Error on Curve448 operation */
};

enum
{
    ERR_PTR         = 100,    /* bad pointer            */
    ERR_NEW         = 0,      /* new, get resorce error */
    ERR_CLOSED      = 1,      /* already closed         */
    ERR_INIT        = 2,      /* initialization error   */
    ERR_CONNECT     = 3,      /* connect error          */
    ERR_HEADER      = 4,      /* header error           */
    ERR_TYPE        = 5,      /* type error             */
    ERR_LEN         = 6,      /* length error           */   
    ERR_READ        = 7,      /* read error             */
    ERR_WRITE       = 8,      /* write error            */
    ERR_KEYGEN      = 10,     /* key generation error   */
    ERR_PUBEX       = 11,     /* public key export error  */
};

#define BW_ERR_MAJOR(code) (((code) & 0xffff))
#define BW_ERR_MINOR(code) (((code)&0xffff0000) >> 16)
#define BW_ERR(major, minor) (((minor) << 16) | (major & 0xffff))

#endif
