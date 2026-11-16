/* Synthetic local TLS 1.3 peer that responds to a requested ALPS extension. */
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

static int add_alps(SSL *ssl, unsigned int type, unsigned int context,
                    const unsigned char **out, size_t *out_len, X509 *cert,
                    size_t chain_index, int *alert, void *arg) {
    static const unsigned char settings[] = {0, 0};
    (void)ssl; (void)type; (void)context; (void)cert;
    (void)chain_index; (void)alert; (void)arg;
    *out = settings;
    *out_len = sizeof(settings);
    return 1;
}

static int receive_alps(SSL *ssl, unsigned int type, unsigned int context,
                        const unsigned char *in, size_t in_len, X509 *cert,
                        size_t chain_index, int *alert, void *arg) {
    (void)ssl; (void)type; (void)context; (void)in; (void)in_len;
    (void)cert; (void)chain_index; (void)alert; (void)arg;
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 4) return 2;
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx || !SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) ||
        !SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) ||
        !SSL_CTX_use_certificate_file(ctx, argv[1], SSL_FILETYPE_PEM) ||
        !SSL_CTX_use_PrivateKey_file(ctx, argv[2], SSL_FILETYPE_PEM) ||
        !SSL_CTX_add_custom_ext(ctx, (unsigned int)strtoul(argv[3], NULL, 0),
            SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_ONLY | SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
            add_alps, NULL, NULL, receive_alps, NULL)) return 3;

    int listener = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (listener < 0 || bind(listener, (struct sockaddr *)&address, sizeof(address)) ||
        listen(listener, 1)) return 4;
    socklen_t length = sizeof(address);
    if (getsockname(listener, (struct sockaddr *)&address, &length)) return 5;
    printf("%u\n", (unsigned int)ntohs(address.sin_port));
    fflush(stdout);
    int client = accept(listener, NULL, NULL);
    SSL *connection = SSL_new(ctx);
    if (client >= 0 && connection) {
        SSL_set_fd(connection, client);
        (void)SSL_accept(connection);
    }
    SSL_free(connection);
    if (client >= 0) close(client);
    close(listener);
    SSL_CTX_free(ctx);
    return 0;
}
