#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_REV2SELF

using namespace stardust;
using namespace starburst;

auto declfn starburst::cmd_rev2self(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    if ( !inst.advapi32.RevertToSelf() ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "RevertToSelf failed" ) ) );
        return;
    }

    if ( inst.agent.impersonated_token ) {
        inst.kernel32.CloseHandle( inst.agent.impersonated_token );
        inst.agent.impersonated_token = nullptr;
    }

    queue_response( inst, task_uuid, RESPONSE_SUCCESS,
        symbol<char*>( const_cast<char*>( "reverted to self" ) ) );
}

#endif
