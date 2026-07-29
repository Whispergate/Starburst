#include <common.h>
#include <commands.h>
#include <config.h>

using namespace stardust;
using namespace starburst;

#ifndef MODULE_CMD_ID
#error "MODULE_CMD_ID must be defined"
#endif

#ifndef MODULE_NAME
#error "MODULE_NAME must be defined"
#endif

#define _HANDLER_PASTE(prefix, name) prefix ## name
#define _HANDLER_NAME(name) _HANDLER_PASTE(cmd_, name)

extern "C" int module_init(
    instance*                inst,
    instance::LoadedCommand* table,
    int                      max_commands
) {
    if ( max_commands < 1 ) return 0;

    table[0].cmd_id  = MODULE_CMD_ID;
    table[0].handler = reinterpret_cast<void*>( _HANDLER_NAME(MODULE_NAME) );
    table[0].active  = false;

    return 1;
}
