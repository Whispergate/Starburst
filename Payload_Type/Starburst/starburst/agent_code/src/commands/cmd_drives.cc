#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_DRIVES

using namespace stardust;
using namespace starburst;

typedef DWORD (WINAPI *fn_GetLogicalDriveStringsW)( DWORD, LPWSTR );
typedef UINT  (WINAPI *fn_GetDriveTypeW)( LPCWSTR );

auto declfn starburst::cmd_drives(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    (void)params;

    auto k32 = (HMODULE)inst.kernel32.handle;

    auto pGetLogicalDriveStringsW = reinterpret_cast<fn_GetLogicalDriveStringsW>(
        inst.kernel32.GetProcAddress( k32,
            symbol<LPCSTR>( "GetLogicalDriveStringsW" ) ) );
    auto pGetDriveTypeW = reinterpret_cast<fn_GetDriveTypeW>(
        inst.kernel32.GetProcAddress( k32,
            symbol<LPCSTR>( "GetDriveTypeW" ) ) );

    if ( !pGetLogicalDriveStringsW || !pGetDriveTypeW ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "API resolution failed" ) ) );
        return;
    }

    wchar_t drive_buf[512] = { 0 };
    DWORD len = pGetLogicalDriveStringsW( 511, drive_buf );
    if ( len == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "GetLogicalDriveStringsW failed" ) ) );
        return;
    }

    uint32_t out_cap = 4096;
    auto output = static_cast<char*>( inst.heap_alloc( out_cap ) );
    if ( !output ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
        return;
    }

    uint32_t off = 0;
    str_copy( output + off, symbol<char*>( const_cast<char*>( "Drive\tType\n" ) ) );
    off = str_len( output );

    wchar_t* p = drive_buf;
    while ( *p && off + 40 < out_cap ) {
        // convert drive letter to narrow
        char narrow[8] = { 0 };
        inst.kernel32.WideCharToMultiByte( CP_ACP, 0, p, -1, narrow, 8, nullptr, nullptr );
        uint32_t nlen = str_len( narrow );
        memory::copy( output + off, narrow, nlen );
        off += nlen;
        output[off++] = '\t';

        UINT dtype = pGetDriveTypeW( p );
        switch ( dtype ) {
            case 2:
                str_copy( output + off, symbol<char*>( const_cast<char*>( "Removable" ) ) );
                off += 9;
                break;
            case 3:
                str_copy( output + off, symbol<char*>( const_cast<char*>( "Fixed" ) ) );
                off += 5;
                break;
            case 4:
                str_copy( output + off, symbol<char*>( const_cast<char*>( "Remote" ) ) );
                off += 6;
                break;
            case 5:
                str_copy( output + off, symbol<char*>( const_cast<char*>( "CDROM" ) ) );
                off += 5;
                break;
            case 6:
                str_copy( output + off, symbol<char*>( const_cast<char*>( "RAMDisk" ) ) );
                off += 7;
                break;
            default:
                str_copy( output + off, symbol<char*>( const_cast<char*>( "Unknown" ) ) );
                off += 7;
                break;
        }
        output[off++] = '\n';

        // advance to next null-terminated string
        while ( *p ) p++;
        p++;
    }

    output[off] = '\0';
    queue_response( inst, task_uuid, RESPONSE_SUCCESS, output );
    inst.heap_free( output );
}

#endif
