/* rec.c
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
#include "tls/rec.h"
#include "tls/hs2_sHello.h"

int bW_recWrite(WOLFSSL *tls, bW_ContentType type, uint8_t *tlsRec, int len)
{
    int ret;
    CallbackIOSend writeCb = (CallbackIOSend)tls->ctx.write;

    if(tls->ctx.write == NULL || tlsRec == NULL)
        RAISE(tls, BW_ERR(ERR_REC, ERR_PTR));

    /* RFC8446 B.1. Record Layer */
    tlsRec[0] = type;
    tlsRec[1] = BW_TLS12_MAJOR;
    tlsRec[2] = BW_TLS12_MINOR;
    tlsRec[3] = (len >> 8) & 0xff;
    tlsRec[4] = len & 0xff;
    ret = (writeCb)(tls, tlsRec, len + BW_REC_HDR, tls->wCtx);

    return ret;
}

int bW_recRead(WOLFSSL *tls, bW_ContentType *type, uint8_t **buff)
{
    int ret;
    int len;
    uint8_t header[BW_REC_HDR];
    CallbackIOSend readCb = (CallbackIOSend)tls->ctx.read;

    if (type == NULL || buff == NULL)
        RAISE(tls, BW_ERR(ERR_REC, ERR_PTR));

    ret = (readCb)(tls, header, BW_REC_HDR, tls->wCtx);
    if(ret != BW_REC_HDR)
        RAISE(tls, BW_ERR(ERR_REC, ERR_HEADER));

    /* RFC8446 B.1. Record Layer */
    if (header[1] != BW_TLS12_MAJOR || header[2] != BW_TLS12_MINOR)
            RAISE(tls, BW_ERR(ERR_REC, ERR_HEADER));
    len = header[3] << 8 | header[4];
    if(len > 0x4000)
            RAISE(tls, BW_ERR(ERR_REC, ERR_HEADER));

    *type = header[0];
    *buff = (uint8_t *)BW_MALLOC(tls, len);
    ret =  (readCb)(tls, *buff, len, tls->wCtx);
    if(ret != len)
        RAISE(tls, BW_ERR(ERR_REC, ERR_READ));
    
    return ret;
}

static int IORecv(WOLFSSL *tls, uint8_t *buff, int sz, void *ctx)
{
    /* By default, ctx will be a pointer to the file descriptor to read from.
     * This can be changed by calling wolfSSL_SetIOReadCtx(). */
    int sockfd = *(int *)ctx;
    int recvd;

    if (buff == NULL || ctx == NULL)
        RAISE(tls, BW_ERR(ERR_SOCKET, ERR_PTR));
    /* Receive message from socket */
    if ((recvd = recv(sockfd, buff, sz, 0)) == -1)
    {
        /* error encountered. Be responsible and report it in wolfSSL terms */
        fprintf(stderr, "IO RECEIVE ERROR: ");
        RAISE(tls, BW_ERR(ERR_SOCKET, ERR_READ));
    }
    else if (sz > 0 && recvd == 0)
    {
        printf("Connection closed\n");
        RAISE(tls, BW_ERR(ERR_SOCKET, ERR_CLOSED));
    }

    /* successful receive */
#if defined(BBWTLS_DEBUG)
    bW_debugDump("Message", buff, sz);
#endif
    return recvd;
}

static int IOSend(WOLFSSL *tls, uint8_t *buff, int sz, void *ctx)
{
    int sockfd = *(int *)ctx;
    int sent;

    /* Receive message from socket */
    if ((sent = send(sockfd, buff, sz, 0)) == -1)
    {
        /* error encountered. Be responsible and report it in wolfSSL terms */
        fprintf(stderr, "IO SEND ERROR: %d\n", errno);
        RAISE(tls, BW_ERR(ERR_SOCKET, ERR_WRITE));
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

static void DoHandshakeMessage(WOLFSSL *tls, uint8_t *buff, int len)
{
    int msg_type;

    if(tls == NULL || buff == NULL)
        RAISE(tls, BW_ERR(ERR_HANDSHAKE, ERR_PTR));

    msg_type = buff[0];

    switch(tls->stat) {
    case BW_HS_CHELLO_SENT:
        if (msg_type == BW_SERVER_HELLO) {
            bW_DoServerHello(tls, buff, len);
        } else
            RAISE(tls, BW_ERR(ERR_HANDSHAKE, ERR_TYPE));
        break;

    default:
        RAISE(tls, BW_ERR(ERR_HANDSHAKE, ERR_TYPE));
    }

}

BBW_LOCAL void bW_recInit(WOLFSSL_CTX *ctx)
{
    ctx->write = IOSend;
    ctx->read  = IORecv;
}

BBW_LOCAL int bW_processReply(WOLFSSL *tls)
{
    uint8_t *buff;
    int len;
    bW_ContentType type;

    len = bW_recRead(tls, &type, &buff);
    switch(type) {
    case BW_HANDSHAKE:
        DoHandshakeMessage(tls, buff, len);
        BW_FREE(buff);
        break;
    case BW_CHANGE_CIPHER_SPEC:
    case BW_ALERT:
    case BW_APPLICATON_DATA:
    default:
        RAISE(ERR_REC, ERR_TYPE);
    }

    return 0;
}
