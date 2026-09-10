/* GnuTLS implements the server side of Cisco DTLS 0.9; OpenSSL is client-only.
 * Synthetic premaster/session ID match dtls_resumption_server.c. */
#include <arpa/inet.h>
#include <gnutls/gnutls.h>
#include <gnutls/dtls.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void check(int result) {
    if (result < 0) { fprintf(stderr, "%s\n", gnutls_strerror(result)); exit(1); }
}
int main(int argc, char **argv) {
    if (argc != 4) return 2;
    int aes256 = strstr(argv[2], "AES256") != NULL;
    int dhe = strstr(argv[2], "DHE-") != NULL;
    gnutls_session_t session;
    gnutls_certificate_credentials_t credentials;
    check(gnutls_global_init());
    check(gnutls_init(&session, GNUTLS_SERVER | GNUTLS_DATAGRAM));
    check(gnutls_certificate_allocate_credentials(&credentials));
    check(gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, credentials));
    char priority[256];
    snprintf(priority, sizeof(priority), "NORMAL:-VERS-ALL:+VERS-DTLS0.9:-KX-ALL:+%s:-CIPHER-ALL:+AES-%d-CBC:-MAC-ALL:+SHA1:%%COMPAT", dhe ? "DHE-RSA" : "RSA", aes256 ? 256 : 128);
    check(gnutls_priority_set_direct(session, priority, NULL));
    unsigned char secret[48], id[32], buffer[16384];
    memset(secret, 0x39, sizeof(secret)); memset(id, 0x42, sizeof(id));
    gnutls_datum_t master = {secret, sizeof(secret)}, sid = {id, sizeof(id)};
    check(gnutls_session_set_premaster(session, GNUTLS_SERVER, GNUTLS_DTLS0_9,
        dhe ? GNUTLS_KX_DHE_RSA : GNUTLS_KX_RSA,
        aes256 ? GNUTLS_CIPHER_AES_256_CBC : GNUTLS_CIPHER_AES_128_CBC, GNUTLS_MAC_SHA1, GNUTLS_COMP_NULL, &master, &sid));
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in local = {.sin_family = AF_INET, .sin_port = htons(atoi(argv[1])), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    if (bind(fd, (struct sockaddr *)&local, sizeof(local))) return 3;
    puts("READY"); fflush(stdout);
    struct sockaddr_storage peer;
    socklen_t size = sizeof(peer);
    if (recvfrom(fd, buffer, sizeof(buffer), MSG_PEEK, (struct sockaddr *)&peer, &size) < 0) return 4;
    if (connect(fd, (struct sockaddr *)&peer, size)) return 5;
    gnutls_transport_set_int(session, fd);
    gnutls_dtls_set_mtu(session, 1500);
    check(gnutls_handshake(session));
    if (!gnutls_session_is_resumed(session)) return 6;
    int n;
    while ((n = gnutls_record_recv(session, buffer, sizeof(buffer))) > 0) {
        if (gnutls_record_send(session, buffer, n) != n) return 7;
    }
    gnutls_deinit(session); gnutls_certificate_free_credentials(credentials);
    close(fd); gnutls_global_deinit();
    return 0;
}
