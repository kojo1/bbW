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
    ERR_NULLPOINTER = -100, /* NULL pointer           */
    ERR_RECWRITE = -101,    /* TLS record wirte error */
    ERR_RECREAD  = -102,    /* TLS record read error  */
    ERR_IOWRITE  = -103,    /* Network write error    */
    ERR_IOREAD   = -104,    /* Network read error     */
};

#endif
