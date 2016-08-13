#include "ssl.h"

SSL_CTX *ssl_context;

int init_ssl(char *key, char *cert) {

    ssl_context = malloc(sizeof(SSL_CTX));

    /* we want to use TLSv1 only */
    if ((ssl_context = SSL_CTX_new(TLSv1_server_method())) == NULL) {
        fprintf(stderr, "Error creating SSL context.\n");
        return 0;
    }

    /* register private key */
    if (SSL_CTX_use_PrivateKey_file(ssl_context, key,
                                    SSL_FILETYPE_PEM) == 0) {
        SSL_CTX_free(ssl_context);
        fprintf(stderr, "Error associating private key.\n");
        return 0;
    }

    /* register public key (certificate) */
    if (SSL_CTX_use_certificate_file(ssl_context, cert,
                                     SSL_FILETYPE_PEM) == 0) {
        SSL_CTX_free(ssl_context);
        fprintf(stderr, "Error associating certificate.\n");
        return 0;
    }

    return 1;
}

int setup_secure_socket(struct sockaddr_in *addr, int secure_port) {
    int secure_sock;

    if ((secure_sock = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
        SSL_CTX_free(ssl_context);
        fprintf(stderr, "Failed creating socket.\n");
        return 0;
    }

    addr->sin_port = htons(secure_port);

    if (bind(secure_sock, (struct sockaddr *) addr, sizeof(*addr))) {
        SSL_CTX_free(ssl_context);
        close(secure_sock);
        fprintf(stderr, "Failed binding socket.\n");
        return 0;
    }

    if (listen(secure_sock, 5)) {
        SSL_CTX_free(ssl_context);
        close(secure_sock);
        fprintf(stderr, "Error listening on socket.\n");
        return 0;
    }

    return secure_sock;
}

SSL *wrap_client_socket(int client_sock, int sock) {
    SSL *client_context;
    client_context = malloc(sizeof(SSL));

    if ((client_context = SSL_new(ssl_context)) == NULL) {
        close(sock);
        SSL_CTX_free(ssl_context);
        fprintf(stderr, "Error creating client SSL context.\n");
        return NULL;
    }

    if (SSL_set_fd(client_context, client_sock) == 0) {
        close(sock);
        SSL_free(client_context);
        SSL_CTX_free(ssl_context);
        fprintf(stderr, "Error creating client SSL context.\n");
        return NULL;
    }

    if (SSL_accept(client_context) <= 0) {
        close(sock);
        SSL_free(client_context);
        SSL_CTX_free(ssl_context);
        fprintf(stderr, "Error accepting (handshake) client SSL context.\n");
        return NULL;
    }
    return client_context;
}