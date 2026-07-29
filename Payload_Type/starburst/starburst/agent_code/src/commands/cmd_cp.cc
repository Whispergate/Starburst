#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_CP

using namespace stardust;
using namespace starburst;

auto declfn starburst::cmd_cp(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    uint32_t src_len = 0;
    auto src = parser_string( params, &src_len );
    uint32_t dst_len = 0;
    auto dst = parser_string( params, &dst_len );

    if ( !src || src_len == 0 || !dst || dst_len == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "need source and destination" ) ) );
        return;
    }

    char src_buf[520] = { 0 };
    uint32_t sc = src_len < 519 ? src_len : 519;
    memory::copy( src_buf, src, sc );

    char dst_buf[520] = { 0 };
    uint32_t dc = dst_len < 519 ? dst_len : 519;
    memory::copy( dst_buf, dst, dc );

    wchar_t wsrc[520] = { 0 };
    wchar_t wdst[520] = { 0 };
    inst.kernel32.MultiByteToWideChar( CP_ACP, 0, src_buf, -1, wsrc, 520 );
    inst.kernel32.MultiByteToWideChar( CP_ACP, 0, dst_buf, -1, wdst, 520 );

    if ( inst.kernel32.CopyFileW( wsrc, wdst, FALSE ) ) {
        queue_response( inst, task_uuid, RESPONSE_SUCCESS,
            symbol<char*>( const_cast<char*>( "copied" ) ) );
    } else {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "CopyFileW failed" ) ) );
    }
}

#endif
