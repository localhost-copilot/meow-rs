/* Local, synthetic OpenSSL session-cache peer for DTLS interoperability tests.
 * Build with the system OpenSSL 3, separately from meow's isolated client. */
#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 4 || atoi(argv[3]) != 0) return 2;
    SSL_CTX *ctx = SSL_CTX_new(DTLS_server_method());
    SSL_CTX_set_security_level(ctx, 0);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET | SSL_OP_NO_QUERY_MTU | SSL_OP_NO_EXTENDED_MASTER_SECRET);
    SSL_CTX_set_min_proto_version(ctx, DTLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, DTLS1_2_VERSION);
    if (!SSL_CTX_set_cipher_list(ctx, argv[2])) return 3;
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER);
    unsigned char context[] = "fixture", secret[48], id[32];
    memset(secret, 0x39, sizeof(secret));
    memset(id, 0x42, sizeof(id));
    SSL_CTX_set_session_id_context(ctx, context, sizeof(context));
    SSL *ssl = SSL_new(ctx);
    SSL_SESSION *session = SSL_SESSION_new();
    const SSL_CIPHER *cipher = sk_SSL_CIPHER_value(SSL_get_ciphers(ssl), 0);
    /* Skip TLS 1.3 suites returned ahead of the configured DTLS suite. */
    for (int i = 0; i < sk_SSL_CIPHER_num(SSL_get_ciphers(ssl)); i++) {
        const SSL_CIPHER *candidate = sk_SSL_CIPHER_value(SSL_get_ciphers(ssl), i);
        if (strcmp(SSL_CIPHER_get_name(candidate), argv[2]) == 0) cipher = candidate;
    }
    SSL_SESSION_set_protocol_version(session, DTLS1_2_VERSION);
    SSL_SESSION_set_cipher(session, cipher);
    SSL_SESSION_set1_master_key(session, secret, sizeof(secret));
    SSL_SESSION_set1_id(session, id, sizeof(id));
    SSL_SESSION_set1_id_context(session, context, sizeof(context));
    SSL_SESSION_set_time(session, time(NULL));
    SSL_SESSION_set_timeout(session, 300);
    if (!SSL_CTX_add_session(ctx, session)) return 4;
    SSL_SESSION_free(session);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in local = {.sin_family = AF_INET, .sin_port = htons(atoi(argv[1])), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    if (bind(fd, (struct sockaddr *)&local, sizeof(local))) return 5;
    puts("READY"); fflush(stdout);
    unsigned char buffer[16384];
    struct sockaddr_storage peer;
    socklen_t size = sizeof(peer);
    if (recvfrom(fd, buffer, sizeof(buffer), MSG_PEEK, (struct sockaddr *)&peer, &size) < 0) return 6;
    if (connect(fd, (struct sockaddr *)&peer, size)) return 7;
    BIO *bio = BIO_new_dgram(fd, BIO_NOCLOSE);
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &peer);
    SSL_set_bio(ssl, bio, bio);
    SSL_set_mtu(ssl, 1500);
    if (SSL_accept(ssl) != 1 || !SSL_session_reused(ssl)) { ERR_print_errors_fp(stderr); return 8; }
    int n;
    while ((n = SSL_read(ssl, buffer, sizeof(buffer))) > 0) {
        if (SSL_write(ssl, buffer, n) != n) return 9;
    }
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);
    return 0;
}
