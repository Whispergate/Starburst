#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_ENUMDESKTOPS

using namespace stardust;
using namespace starburst;

typedef HWINSTA ( WINAPI *fn_OpenWindowStationA )( LPCSTR, BOOL, DWORD );
typedef BOOL    ( WINAPI *fn_CloseWindowStation )( HWINSTA );
typedef BOOL    ( WINAPI *fn_EnumWindowStationsA )( NAMEENUMPROCA, LPARAM );
typedef BOOL    ( WINAPI *fn_EnumDesktopsA )( HWINSTA, DESKTOPENUMPROCA, LPARAM );

struct EnumCtx {
    char*    buf;
    uint32_t off;
    uint32_t cap;
    fn_EnumDesktopsA      pEnumDesktopsA;
    fn_OpenWindowStationA pOpenWindowStationA;
    fn_CloseWindowStation pCloseWindowStation;
};

static BOOL CALLBACK declfn desk_callback( LPSTR name, LPARAM lp ) {
    auto ctx = reinterpret_cast<EnumCtx*>( lp );
    if ( !name || !ctx ) return TRUE;

    uint32_t nlen = 0;
    auto p = name;
    while ( *p ) { nlen++; p++; }

    if ( ctx->off + nlen + 16 >= ctx->cap ) return FALSE;

    ctx->buf[ctx->off++] = ' ';
    ctx->buf[ctx->off++] = ' ';

    memory::copy( ctx->buf + ctx->off, name, nlen );
    ctx->off += nlen;

    ctx->buf[ctx->off++] = '\n';
    return TRUE;
}

static BOOL CALLBACK declfn ws_callback( LPSTR name, LPARAM lp ) {
    auto ctx = reinterpret_cast<EnumCtx*>( lp );
    if ( !name || !ctx ) return TRUE;

    uint32_t nlen = 0;
    auto p = name;
    while ( *p ) { nlen++; p++; }

    if ( ctx->off + nlen + 32 >= ctx->cap ) return FALSE;

    memory::copy( ctx->buf + ctx->off, name, nlen );
    ctx->off += nlen;

    ctx->buf[ctx->off++] = '\n';

    // open the window station and enumerate desktops
    if ( ctx->pOpenWindowStationA && ctx->pEnumDesktopsA && ctx->pCloseWindowStation ) {
        HWINSTA h_ws = ctx->pOpenWindowStationA( name, FALSE, WINSTA_ENUMDESKTOPS );
        if ( h_ws ) {
            ctx->pEnumDesktopsA( h_ws, desk_callback, lp );
            ctx->pCloseWindowStation( h_ws );
        }
    }

    return TRUE;
}

auto declfn starburst::cmd_enumdesktops(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    (void)params;

    DBG_PRINT( inst, "cmd_enumdesktops\n" );

    auto h_user32 = inst.kernel32.LoadLibraryA( symbol<const char*>( "user32.dll" ) );
    if ( !h_user32 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "failed to load user32.dll" ) ) );
        return;
    }

    auto pEnumWindowStationsA = reinterpret_cast<fn_EnumWindowStationsA>(
        inst.kernel32.GetProcAddress( h_user32,
            symbol<LPCSTR>( "EnumWindowStationsA" ) ) );
    auto pEnumDesktopsA = reinterpret_cast<fn_EnumDesktopsA>(
        inst.kernel32.GetProcAddress( h_user32,
            symbol<LPCSTR>( "EnumDesktopsA" ) ) );
    auto pOpenWindowStationA = reinterpret_cast<fn_OpenWindowStationA>(
        inst.kernel32.GetProcAddress( h_user32,
            symbol<LPCSTR>( "OpenWindowStationA" ) ) );
    auto pCloseWindowStation = reinterpret_cast<fn_CloseWindowStation>(
        inst.kernel32.GetProcAddress( h_user32,
            symbol<LPCSTR>( "CloseWindowStation" ) ) );

    if ( !pEnumWindowStationsA || !pEnumDesktopsA ||
         !pOpenWindowStationA || !pCloseWindowStation ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "failed to resolve desktop APIs" ) ) );
        return;
    }

    uint32_t buf_cap = 8192;
    auto output = static_cast<char*>( inst.heap_alloc( buf_cap ) );
    if ( !output ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
        return;
    }

    EnumCtx ctx = {};
    ctx.buf = output;
    ctx.off = 0;
    ctx.cap = buf_cap;
    ctx.pEnumDesktopsA      = pEnumDesktopsA;
    ctx.pOpenWindowStationA = pOpenWindowStationA;
    ctx.pCloseWindowStation = pCloseWindowStation;

    // add header
    auto hdr = symbol<char*>( const_cast<char*>( "Window Stations and Desktops:\n" ) );
    uint32_t hdr_len = str_len( hdr );
    memory::copy( output, hdr, hdr_len );
    ctx.off = hdr_len;

    pEnumWindowStationsA( ws_callback, reinterpret_cast<LPARAM>( &ctx ) );

    output[ctx.off] = '\0';

    queue_response( inst, task_uuid, RESPONSE_SUCCESS, output );
    inst.heap_free( output );
}

#endif
