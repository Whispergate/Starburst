#ifndef STARBURST_BROWSERPIVOT_H
#define STARBURST_BROWSERPIVOT_H

#include <macros.h>

#ifdef INCLUDE_CMD_BROWSERPIVOT

/* ---------------------------------------------------------------
 *  WinSock constants  - defined independently so browserpivot
 *  can build without INCLUDE_CMD_SOCKS.
 * -------------------------------------------------------------- */
#define BP_AF_INET          2
#define BP_SOCK_STREAM      1
#define BP_IPPROTO_TCP      6
#define BP_FIONBIO          0x8004667EL
#define BP_INVALID_SOCKET   (~(uintptr_t)0)
#define BP_SOCKET_ERROR     (-1)
#define BP_SOL_SOCKET       0xFFFF
#define BP_SO_REUSEADDR     0x0004
#define BP_WSAEWOULDBLOCK   10035
#define BP_SOMAXCONN        0x7FFFFFFF

/* ---------------------------------------------------------------
 *  WinINet constants
 * -------------------------------------------------------------- */
#define BP_INTERNET_OPEN_TYPE_PRECONFIG  0
#define BP_INTERNET_FLAG_NO_CACHE_WRITE  0x04000000
#define BP_INTERNET_FLAG_RELOAD          0x80000000
#define BP_HTTP_QUERY_STATUS_CODE        19
#define BP_HTTP_QUERY_RAW_HEADERS_CRLF   22
#define BP_HTTP_QUERY_FLAG_NUMBER        0x20000000
#define BP_HTTP_QUERY_CONTENT_LENGTH     5

/* ---------------------------------------------------------------
 *  HINTERNET typedef - <wininet.h> is NOT included via common.h
 *  unless GITHUB_TRANSPORT is defined.
 * -------------------------------------------------------------- */
#ifndef _WININET_
typedef void* HINTERNET;
#endif

namespace stardust { class instance; }

namespace starburst {

    /* =============================================================
     *  WinSock function-pointer typedefs  (bp_ prefix)
     * ============================================================= */
    typedef int       (__stdcall *bp_fn_WSAStartup)( uint16_t, void* );
    typedef uintptr_t (__stdcall *bp_fn_socket)( int, int, int );
    typedef int       (__stdcall *bp_fn_connect)( uintptr_t, const void*, int );
    typedef int       (__stdcall *bp_fn_send)( uintptr_t, const char*, int, int );
    typedef int       (__stdcall *bp_fn_recv)( uintptr_t, char*, int, int );
    typedef int       (__stdcall *bp_fn_closesocket)( uintptr_t );
    typedef int       (__stdcall *bp_fn_select)( int, void*, void*, void*, const void* );
    typedef int       (__stdcall *bp_fn_ioctlsocket)( uintptr_t, long, unsigned long* );
    typedef int       (__stdcall *bp_fn_WSAGetLastError)( void );
    typedef int       (__stdcall *bp_fn_WSACleanup)( void );
    typedef uint16_t  (__stdcall *bp_fn_htons)( uint16_t );
    typedef uint16_t  (__stdcall *bp_fn_ntohs)( uint16_t );
    typedef unsigned long (__stdcall *bp_fn_inet_addr)( const char* );
    typedef int       (__stdcall *bp_fn_bind)( uintptr_t, const void*, int );
    typedef int       (__stdcall *bp_fn_listen)( uintptr_t, int );
    typedef uintptr_t (__stdcall *bp_fn_accept)( uintptr_t, void*, int* );
    typedef int       (__stdcall *bp_fn_setsockopt)( uintptr_t, int, int, const char*, int );

    struct BpWsApis {
        bp_fn_WSAStartup       pWSAStartup;
        bp_fn_socket           psocket;
        bp_fn_connect          pconnect;
        bp_fn_send             psend;
        bp_fn_recv             precv;
        bp_fn_closesocket      pclosesocket;
        bp_fn_select           pselect;
        bp_fn_ioctlsocket      pioctlsocket;
        bp_fn_WSAGetLastError  pWSAGetLastError;
        bp_fn_WSACleanup       pWSACleanup;
        bp_fn_htons            phtons;
        bp_fn_ntohs            pntohs;
        bp_fn_inet_addr        pinet_addr;
        bp_fn_bind             pbind;
        bp_fn_listen           plisten;
        bp_fn_accept           paccept;
        bp_fn_setsockopt       psetsockopt;
    };

    /* =============================================================
     *  WinSock structs  (bp_ prefix)
     * ============================================================= */
#pragma pack(push, 1)
    struct bp_sockaddr_in {
        int16_t  sin_family;
        uint16_t sin_port;
        uint32_t sin_addr;
        char     sin_zero[8];
    };

    struct bp_fd_set {
        unsigned int fd_count;
        uintptr_t    fd_array[64];
    };

    struct bp_timeval {
        long tv_sec;
        long tv_usec;
    };
#pragma pack(pop)

    /* =============================================================
     *  WinINet function-pointer typedefs
     * ============================================================= */
    typedef HINTERNET (__stdcall *bp_fn_InternetOpenA)(
        const char*, unsigned long, const char*, const char*, unsigned long );
    typedef HINTERNET (__stdcall *bp_fn_InternetOpenUrlA)(
        HINTERNET, const char*, const char*, unsigned long, unsigned long, uintptr_t );
    typedef int       (__stdcall *bp_fn_InternetReadFile)(
        HINTERNET, void*, unsigned long, unsigned long* );
    typedef int       (__stdcall *bp_fn_InternetCloseHandle)(
        HINTERNET );
    typedef int       (__stdcall *bp_fn_HttpQueryInfoA)(
        HINTERNET, unsigned long, void*, unsigned long*, unsigned long* );

    struct BpInetApis {
        bp_fn_InternetOpenA       pInternetOpenA;
        bp_fn_InternetOpenUrlA    pInternetOpenUrlA;
        bp_fn_InternetReadFile    pInternetReadFile;
        bp_fn_InternetCloseHandle pInternetCloseHandle;
        bp_fn_HttpQueryInfoA      pHttpQueryInfoA;
    };

    /* =============================================================
     *  BrowserPivotState - all state for the browser-pivot proxy
     * ============================================================= */
    struct BrowserPivotState {
        BpWsApis          ws;
        BpInetApis        inet;

        HINTERNET         h_internet;
        uintptr_t         listen_sock;
        uint16_t          port;

        HANDLE            h_thread;
        volatile LONG     running;

        HMODULE           h_ws2;
        HMODULE           h_wininet;

        stardust::instance* inst_ptr;
    };

    /* =============================================================
     *  Public API
     * ============================================================= */
    auto declfn bp_init(
        _Inout_ stardust::instance& inst,
        _In_    uint16_t            port
    ) -> bool;

    auto declfn bp_destroy(
        _Inout_ stardust::instance& inst
    ) -> void;

}

#endif // INCLUDE_CMD_BROWSERPIVOT
#endif // STARBURST_BROWSERPIVOT_H
