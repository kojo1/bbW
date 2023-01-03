/* tcp.h
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

#ifndef TCP_H
#define TCP_H

/* Exception wrapper for socket APIs*/
#define bbWtcp_socket(exc, ret, a, b, c) ((ret = socket(a, b, c)) == -1 ? RAISE(exc, BW_ERR(ERR_SOCKET, ERR_NEW)) : ret)
#define bbWtcp_inet_pton(exc, a, b, c)  if(inet_pton(a, b, c) == -1)RAISE(exc, BW_ERR(ERR_SOCKET, ERR_INIT));
#define bbWtcp_connect(exc, a, b, c)    if(connect(a, b, c)   == -1)RAISE(exc, BW_ERR(ERR_SOCKET, ERR_CONNECT));
#define bbWtcp_close(fd)                if(fd != -1)close(fd)
#endif