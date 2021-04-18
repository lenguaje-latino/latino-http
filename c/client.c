// https://aticleworld.com/ssl-server-client-using-openssl-in-c/
// openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout mycert.pem -out mycert.pem
// Compile the Client : gcc -Wall -o client  client.c -L/usr/lib -lssl -lcrypto
//  Run :   ./client <host_name> <port_number>

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#define FAIL    -1
int OpenConnection(const char *hostname, int port)
{
    int sd;
    struct hostent *host;
    struct sockaddr_in addr;
    printf("antes de %s\n", "gethostbyname");
    if ( (host = gethostbyname(hostname)) == NULL )    
    {
        printf("error en :%s\n", "gethostbyname");
        perror(hostname);
        abort();
    }
    printf("despues de %s\n", "gethostbyname");
    printf("antes de %s\n", "socket");
    sd = socket(PF_INET, SOCK_STREAM, NULL);
    printf("despues de %s\n", "socket");
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != NULL )
    {
        printf("error en :%s\n", "connect");
        close(sd);
        perror(hostname);
        abort();
    }
    printf("antes del return:%i\n", sd);
    return sd;
}
SSL_CTX* InitCTX(void)
{
    printf("%s", "InitCTX");
    SSL_METHOD *method;
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    method = TLSv1_2_client_method();  /* Create new client-method instance */
    ctx = SSL_CTX_new(method);   /* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}
void ShowCerts(SSL* ssl)
{
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    }
    else
        printf("Info: No client certificates configured.\n");
}

#define MAX_BUFFER 1024*32 

int main(int count, char *strings[])
{
    printf("%s", "running client\n");
    SSL_CTX *ctx;
    int server;
    SSL *ssl;
    char buf[MAX_BUFFER];
    char acClientRequest[MAX_BUFFER] = {0};
    int bytes;
    char *hostname, *portnum;
    if ( count != 3 )
    {
        printf("usage: %s <hostname> <portnum>\n", strings[0]);
        exit(0);
    }
    printf("antes de %s\n", "SSL_library_init");
    SSL_library_init();
    printf("despues de %s\n", "SSL_library_init");
    hostname=strings[1];
    portnum=strings[2];
    printf("despues de %s\n", "InitCTX");
    ctx = InitCTX();
    printf("despues de %s\n", "InitCTX");
    printf("antes de %s\n", "OpenConnection");
    server = OpenConnection(hostname, atoi(portnum));
    printf("despues de %s\n", "OpenConnection");
    printf("server: %i\n", server);
    printf("antes de %s\n", "SSL_new");
    ssl = SSL_new(ctx);      /* create new SSL connection state */
    printf("despues de %s\n", "SSL_new");
    printf("antes de %s\n", "SSL_set_fd");
    SSL_set_fd(ssl, server);    /* attach the socket descriptor */
    printf("despues de %s\n", "SSL_set_fd");
    if ( SSL_connect(ssl) == FAIL )   /* perform the connection */
        ERR_print_errors_fp(stderr);
    else
    {
        /*
        char acUsername[16] = {0};
        char acPassword[16] = {0};
        const char *cpRequestMessage = "<Body>\
                               <UserName>%s<UserName>\
                 <Password>%s<Password>\
                 <\Body>";
                 */
        const char *cpRequestMessage = "GET /%s HTTP/1.1\r\n\r\n";
        // printf("Enter the User Name : ");
        // scanf("%s",acUsername);
        // printf("\n\nEnter the Password : ");
        // scanf("%s",acPassword);
        // sprintf(acClientRequest, cpRequestMessage, acUsername,acPassword);   /* construct reply */
        sprintf(acClientRequest, cpRequestMessage, "get");   /* construct reply */
        printf("\n\nConnected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);        /* get any certs */
        SSL_write(ssl,acClientRequest, strlen(acClientRequest));   /* encrypt & send message */
        bytes = SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */
        buf[bytes] = 0;
        printf("Received: \"%s\"\n", buf);
        SSL_free(ssl);        /* release connection state */
    }
    close(server);         /* close socket */
    SSL_CTX_free(ctx);        /* release context */
    return 0;
}