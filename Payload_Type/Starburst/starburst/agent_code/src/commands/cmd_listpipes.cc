#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_LISTPIPES

using namespace stardust;
using namespace starburst;

auto declfn starburst::cmd_listpipes(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    wchar_t pipe_path[] = { '\\', '\\', '.', '\\', 'p', 'i', 'p', 'e', '\\', '*', '\0' };

    WIN32_FIND_DATAW fd = {};
    HANDLE h_find = inst.kernel32.FindFirstFileW( pipe_path, &fd );
    if ( h_find == INVALID_HANDLE_VALUE ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "FindFirstFileW on pipe namespace failed" ) ) );
        return;
    }

    uint32_t out_cap = 32768;
    auto output = static_cast<char*>( inst.heap_alloc( out_cap ) );
    if ( !output ) {
        inst.kernel32.FindClose( h_find );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
        return;
    }
    uint32_t off = 0;

    do {
        char name[260] = { 0 };
        inst.kernel32.WideCharToMultiByte( CP_ACP, 0, fd.cFileName, -1, name, 260, nullptr, nullptr );
        uint32_t nlen = str_len( name );

        if ( off + nlen + 2 < out_cap ) {
            memory::copy( output + off, name, nlen );
            off += nlen;
            output[off++] = '\n';
        }
    } while ( inst.kernel32.FindNextFileW( h_find, &fd ) );

    inst.kernel32.FindClose( h_find );

    output[off] = '\0';
    queue_response( inst, task_uuid, RESPONSE_SUCCESS, output );
    inst.heap_free( output );
}

#endif
