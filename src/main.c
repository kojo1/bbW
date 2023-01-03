#include "stdio.h"

/* socket includes */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#include "tcp/tcp.h"
#include "tls/tls.h"
#include "common/except.h"


#define DEFAULT_PORT 11111

int main(int argc, char **argv)
{
    int sockfd = -1;
    struct sockaddr_in servAddr;
    int ret;

    WOLFSSL_CTX *ctx = NULL;
    WOLFSSL     *tls = NULL;

    bW_EXCEPT exc; /* Exception Descriptor */

    TRY(&exc)
    {
        printf("TLS Client Started\n");

        bbWtcp_socket(&exc, sockfd, AF_INET, SOCK_STREAM, 0);

        memset(&servAddr, 0, sizeof(servAddr));
        servAddr.sin_family = AF_INET;           /* using IPv4      */
        servAddr.sin_port = htons(DEFAULT_PORT); /* on DEFAULT_PORT */
        bbWtcp_inet_pton(&exc, AF_INET, argv[1], &servAddr.sin_addr);

        bbWtcp_connect(&exc, sockfd, (struct sockaddr *)&servAddr, sizeof(servAddr));

        printf("TCP connected\n");

        ctx = bbWtls_CTX_new(&exc, wolfTLS_client_method());
        tls = bbWtls_new(ctx);
        bbWtls_SetIOWriteCtx(tls, (void *)&sockfd);
        bbWtls_SetIOReadCtx(tls, (void *)&sockfd);
        bbWtls_connect(tls);

        printf("TLS Connected\n");
    }
    EXCEPT
    {
        printf("TLS Connection Error(%d, %d)\n", BW_ERR_MAJOR(CODE(&exc)), BW_ERR_MINOR(CODE(&exc)));
        bbWtls_free(tls);
        bbWtcp_close(sockfd);
        bbWtls_CTX_free(ctx);
        return -1;
    }
    err_exit:
    return 0;
    
}