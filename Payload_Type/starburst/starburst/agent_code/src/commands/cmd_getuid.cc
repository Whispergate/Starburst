#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_GETUID

using namespace stardust;
using namespace starburst;

typedef BOOL ( WINAPI *fn_ConvertSidToStringSidA )( PSID, LPSTR* );
typedef HLOCAL ( WINAPI *fn_LocalFree )( HLOCAL );
typedef PDWORD ( WINAPI *fn_GetSidSubAuthority )( PSID, DWORD );
typedef PUCHAR ( WINAPI *fn_GetSidSubAuthorityCount )( PSID );

auto declfn starburst::cmd_getuid(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    (void)params;

    DBG_PRINT( inst, "cmd_getuid\n" );

    HANDLE h_token = nullptr;
    HANDLE h_proc = reinterpret_cast<HANDLE>( static_cast<intptr_t>( -1 ) );

    if ( !inst.advapi32.OpenProcessToken( h_proc, TOKEN_QUERY, &h_token ) ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "OpenProcessToken failed" ) ) );
        return;
    }

    uint32_t out_cap = 1024;
    auto output = static_cast<char*>( inst.heap_alloc( out_cap ) );
    if ( !output ) {
        inst.kernel32.CloseHandle( h_token );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
        return;
    }
    uint32_t off = 0;

    // --- Get username (DOMAIN\User) ---
    DWORD needed = 0;
    inst.advapi32.GetTokenInformation( h_token, TokenUser, nullptr, 0, &needed );
    if ( needed > 0 ) {
        auto tu = static_cast<TOKEN_USER*>( inst.heap_alloc( needed ) );
        if ( tu && inst.advapi32.GetTokenInformation( h_token, TokenUser, tu, needed, &needed ) ) {
            wchar_t name_w[128] = { 0 };
            DWORD name_len = 128;
            wchar_t domain_w[128] = { 0 };
            DWORD domain_len = 128;
            SID_NAME_USE snu = SidTypeUnknown;

            if ( inst.advapi32.LookupAccountSidW( nullptr, tu->User.Sid,
                    name_w, &name_len, domain_w, &domain_len, &snu ) ) {
                char domain[128] = { 0 };
                char name[128] = { 0 };
                inst.kernel32.WideCharToMultiByte( CP_ACP, 0, domain_w, -1, domain, 128, nullptr, nullptr );
                inst.kernel32.WideCharToMultiByte( CP_ACP, 0, name_w, -1, name, 128, nullptr, nullptr );

                str_copy( output + off, domain );
                off += str_len( domain );
                output[off++] = '\\';
                str_copy( output + off, name );
                off += str_len( name );
            }

            // --- Get SID string ---
            auto k32 = inst.kernel32.handle;
            auto h_advapi = inst.advapi32.handle;

            auto pConvertSidToStringSidA = reinterpret_cast<fn_ConvertSidToStringSidA>(
                inst.kernel32.GetProcAddress( (HMODULE)h_advapi,
                    symbol<LPCSTR>( "ConvertSidToStringSidA" ) ) );
            auto pLocalFree = reinterpret_cast<fn_LocalFree>(
                inst.kernel32.GetProcAddress( (HMODULE)k32,
                    symbol<LPCSTR>( "LocalFree" ) ) );

            if ( pConvertSidToStringSidA && pLocalFree ) {
                LPSTR sid_str = nullptr;
                if ( pConvertSidToStringSidA( tu->User.Sid, &sid_str ) && sid_str ) {
                    str_copy( output + off, symbol<char*>( const_cast<char*>( " (SID: " ) ) );
                    off += 7;
                    uint32_t slen = str_len( sid_str );
                    if ( slen > 200 ) slen = 200;
                    memory::copy( output + off, sid_str, slen );
                    off += slen;
                    output[off++] = ')';
                    pLocalFree( sid_str );
                }
            }

            if ( tu ) inst.heap_free( tu );
        }
    }

    // --- Get integrity level ---
    auto h_advapi2 = inst.advapi32.handle;
    auto pGetSidSubAuthority = reinterpret_cast<fn_GetSidSubAuthority>(
        inst.kernel32.GetProcAddress( (HMODULE)h_advapi2,
            symbol<LPCSTR>( "GetSidSubAuthority" ) ) );
    auto pGetSidSubAuthorityCount = reinterpret_cast<fn_GetSidSubAuthorityCount>(
        inst.kernel32.GetProcAddress( (HMODULE)h_advapi2,
            symbol<LPCSTR>( "GetSidSubAuthorityCount" ) ) );

    needed = 0;
    inst.advapi32.GetTokenInformation( h_token, TokenIntegrityLevel, nullptr, 0, &needed );
    if ( needed > 0 && pGetSidSubAuthority && pGetSidSubAuthorityCount ) {
        auto til = static_cast<TOKEN_MANDATORY_LABEL*>( inst.heap_alloc( needed ) );
        if ( til && inst.advapi32.GetTokenInformation( h_token, TokenIntegrityLevel, til, needed, &needed ) ) {
            PUCHAR p_count = pGetSidSubAuthorityCount( til->Label.Sid );
            DWORD* sub_auth = nullptr;
            if ( p_count && *p_count > 0 ) {
                sub_auth = pGetSidSubAuthority( til->Label.Sid, (DWORD)( *p_count - 1 ) );
            }

            str_copy( output + off, symbol<char*>( const_cast<char*>( " [Integrity: " ) ) );
            off += 13;

            if ( sub_auth ) {
                DWORD level = *sub_auth;
                if ( level >= 0x4000 ) {
                    str_copy( output + off, symbol<char*>( const_cast<char*>( "System" ) ) );
                    off += 6;
                } else if ( level >= 0x3000 ) {
                    str_copy( output + off, symbol<char*>( const_cast<char*>( "High" ) ) );
                    off += 4;
                } else if ( level >= 0x2000 ) {
                    str_copy( output + off, symbol<char*>( const_cast<char*>( "Medium" ) ) );
                    off += 6;
                } else if ( level >= 0x1000 ) {
                    str_copy( output + off, symbol<char*>( const_cast<char*>( "Low" ) ) );
                    off += 3;
                } else {
                    str_copy( output + off, symbol<char*>( const_cast<char*>( "Untrusted" ) ) );
                    off += 9;
                }
            } else {
                str_copy( output + off, symbol<char*>( const_cast<char*>( "Unknown" ) ) );
                off += 7;
            }

            output[off++] = ']';

            if ( til ) inst.heap_free( til );
        }
    }

    // --- Get elevation status ---
    TOKEN_ELEVATION te = {};
    needed = sizeof( TOKEN_ELEVATION );
    if ( inst.advapi32.GetTokenInformation( h_token, TokenElevation, &te, sizeof( te ), &needed ) ) {
        str_copy( output + off, symbol<char*>( const_cast<char*>( " [Elevated: " ) ) );
        off += 12;

        if ( te.TokenIsElevated ) {
            str_copy( output + off, symbol<char*>( const_cast<char*>( "Yes" ) ) );
            off += 3;
        } else {
            str_copy( output + off, symbol<char*>( const_cast<char*>( "No" ) ) );
            off += 2;
        }

        output[off++] = ']';
    }

    output[off] = '\0';

    inst.kernel32.CloseHandle( h_token );
    queue_response( inst, task_uuid, RESPONSE_SUCCESS, output );
    inst.heap_free( output );
}

#endif
