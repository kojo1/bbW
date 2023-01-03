/* tlsRecord.c
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

#include "stdio.h"
#include <errno.h>

/* socket includes */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#include "tls/tls.h"
#include "tls/record.h"

int yt_recWrite(WOLFSSL *tls, YT_ContentType type, uint8_t *tlsRec, int len)
{
    int ret;
    CallbackIOSend writeCb = (CallbackIOSend)tls->ctx->write;

    if(tls == NULL || tls->ctx == NULL || tls->ctx->write == NULL || tls->wCtx == NULL
       || tlsRec == NULL)
        yT_raiseException(tls, ERR_NULLPOINTER);

    /* RFC8446 B.1. Record Layer */
    tlsRec[0] = type;
    tlsRec[1] = YT_TLS12_MAJOR;
    tlsRec[2] = YT_TLS12_MINOR;
    tlsRec[3] = (len >> 8) & 0xff;
    tlsRec[4] = len & 0xff;
    ret = (writeCb)(tls, (char *)tlsRec, len + YT_REC_HDR, tls->wCtx);

    return ret;
}

static int IORecv(WOLFSSL *tls, char *buff, int sz, void *ctx)
{
    /* By default, ctx will be a pointer to the file descriptor to read from.
     * This can be changed by calling wolfSSL_SetIOReadCtx(). */
    int sockfd = *(int *)ctx;
    int recvd;

    /* Receive message from socket */
    if ((recvd = recv(sockfd, buff, sz, 0)) == -1)
    {
        /* error encountered. Be responsible and report it in wolfSSL terms */
        fprintf(stderr, "IO RECEIVE ERROR: ");
        yT_raiseException(tls, ERR_IOREAD);
    }
    else if (recvd == 0)
    {
        printf("Connection closed\n");
        yT_raiseException(tls, ERR_IOREAD);
    }

    /* successful receive */
    printf("IORecv: received %d bytes from %d\n", sz, sockfd);
    return recvd;
}

static int IOSend(WOLFSSL *tls, char *buff, int sz, void *ctx)
{
    int sockfd = *(int *)ctx;
    int sent;

    /* Receive message from socket */
    if ((sent = send(sockfd, buff, sz, 0)) == -1)
    {
        /* error encountered. Be responsible and report it in wolfSSL terms */
        fprintf(stderr, "IO SEND ERROR: %d\n", errno);
        yT_raiseException(tls, ERR_IOWRITE);
    }
    else if (sent == 0)
    {
        printf("Connection closed\n");
        return 0;
    }

    /* successful send */
    printf("IOSend: sent %d bytes to %d\n", sz, sockfd);
    return sent;
}

void yt_recInit(WOLFSSL_CTX *ctx)
{
    ctx->write = IOSend;
    ctx->read = IORecv;
}