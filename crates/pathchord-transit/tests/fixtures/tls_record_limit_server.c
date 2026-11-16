/* Local OpenSSL TLS peer offering a configurable RFC 8449 receive limit. */
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static unsigned char offered_limit[2];
static size_t offered_length = 2;
static int saw_client_limit;
static int measure_records;
static size_t largest_record;
static size_t record_count;
static size_t largest_sent_record;

static int add_limit(SSL *ssl, unsigned int type, unsigned int context,
                     const unsigned char **out, size_t *length, X509 *cert,
                     size_t chain_index, int *alert, void *arg) {
    (void)ssl; (void)type; (void)context; (void)cert;
    (void)chain_index; (void)alert; (void)arg;
    *out = offered_limit;
    *length = offered_length;
    return 1;
}

static int receive_limit(SSL *ssl, unsigned int type, unsigned int context,
                         const unsigned char *input, size_t length, X509 *cert,
                         size_t chain_index, int *alert, void *arg) {
    (void)ssl; (void)type; (void)context; (void)cert;
    (void)chain_index; (void)alert; (void)arg;
    saw_client_limit = length == 2 && input[0] == 0x40 && input[1] == 0x01;
    return saw_client_limit;
}

static void record_trace(int write_p, int version, int type, const void *buffer,
                         size_t length, SSL *ssl, void *arg) {
    (void)version; (void)ssl; (void)arg;
    const unsigned char *header = buffer;
    if (measure_records && type == SSL3_RT_HEADER && length == 5 && header[0] == 23) {
        size_t size = ((size_t)header[3] << 8) | header[4];
        if (write_p) {
            if (size > largest_sent_record) largest_sent_record = size;
        } else {
            if (size > largest_record) largest_record = size;
            record_count++;
        }
    }
}

int main(int argc, char **argv) {
    if (argc != 6) return 2;
    int version = atoi(argv[3]) == 12 ? TLS1_2_VERSION : TLS1_3_VERSION;
    unsigned long limit = strtoul(argv[4], NULL, 10);
    offered_limit[0] = (unsigned char)(limit >> 8);
    offered_limit[1] = (unsigned char)limit;
    offered_length = (size_t)strtoul(argv[5], NULL, 10);
    if (offered_length > sizeof(offered_limit)) return 2;
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx || !SSL_CTX_set_min_proto_version(ctx, version) ||
        !SSL_CTX_set_max_proto_version(ctx, version) ||
        !SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES128-GCM-SHA256") ||
        !SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256") ||
        !SSL_CTX_use_certificate_file(ctx, argv[1], SSL_FILETYPE_PEM) ||
        !SSL_CTX_use_PrivateKey_file(ctx, argv[2], SSL_FILETYPE_PEM) ||
        !SSL_CTX_add_custom_ext(ctx, 0x1c,
            SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_2_SERVER_HELLO | SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
            add_limit, NULL, NULL, receive_limit, NULL)) return 3;
    SSL_CTX_set_msg_callback(ctx, record_trace);

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
    int success = 0;
    if (client >= 0 && connection) {
        SSL_set_fd(connection, client);
        if (SSL_accept(connection) == 1) {
            measure_records = 1;
            unsigned char input[8192];
            size_t received = 0;
            while (received < 26 + 5000) {
                int count = SSL_read(connection, input, sizeof(input));
                if (count <= 0) break;
                received += (size_t)count;
            }
            if (received == 26 + 5000) {
                unsigned char response[20002];
                response[0] = response[1] = 0;
                for (size_t i = 0; i < 20000; i++) response[i + 2] = (unsigned char)(i % 251);
                success = SSL_write(connection, response, sizeof(response)) == sizeof(response);
            }
        }
    }
    printf("%d %d %zu %zu %zu\n", success, saw_client_limit, largest_record, record_count, largest_sent_record);
    fflush(stdout);
    SSL_free(connection);
    if (client >= 0) close(client);
    close(listener);
    SSL_CTX_free(ctx);
    return 0;
}
