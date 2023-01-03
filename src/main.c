#include "stdio.h"

/* socket includes */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#include "ssl.h"

#define DEFAULT_PORT 11111

int main(int argc, char **argv)
{
    int sockfd;
    struct sockaddr_in servAddr;
    int ret;

    WOLFSSL_CTX *ctx;
    WOLFSSL *tls;

    #define GLOBAL_ERROR (-1)
    yT_Exception_ctx exc_ctx;
    yT_onException_goto(&exc_ctx, err_exit, GLOBAL_ERROR);

        /* Check for proper calling convention */
        if (argc != 2)
    {
        printf("usage: %s <IPv4 address>\n", argv[0]);
        return 0;
    }

    /* Create a socket that uses an internet IPv4 address,
     * Sets the socket to be stream based (TCP),
     * 0 means choose the default protocol. */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        fprintf(stderr, "ERROR: failed to create the socket\n");
        ret = -1;
        goto err_exit;
    }

    /* Initialize the server address struct with zeros */
    memset(&servAddr, 0, sizeof(servAddr));

    /* Fill in the server address */
    servAddr.sin_family = AF_INET;           /* using IPv4      */
    servAddr.sin_port = htons(DEFAULT_PORT); /* on DEFAULT_PORT */

    /* Get the server IPv4 address from the command line call */
    if (inet_pton(AF_INET, argv[1], &servAddr.sin_addr) != 1)
    {
        fprintf(stderr, "ERROR: invalid address\n");
        ret = -1;
        goto err_exit;
    }

    /* Connect to the server */
    if ((ret = connect(sockfd, (struct sockaddr *)&servAddr, sizeof(servAddr))) == -1)
    {
        fprintf(stderr, "ERROR: failed to connect\n");
        goto err_exit;
    }

    printf("yT Started\n");
    ctx = wolfSSL_CTX_new(YT_TLS_CLIENT);
    tls = wolfSSL_new(ctx);
    wolfSSL_SetIOWriteCtx(tls, (void *)&sockfd);
    wolfSSL_connect(tls);
    printf("TLS Connected\n");
    return 0;

err_exit:
    printf("TLS Connection Error(%d, %d)\n",
           yt_getErrMajor(&exc_ctx), yt_getErrMinor(&exc_ctx));
    return 0;
}