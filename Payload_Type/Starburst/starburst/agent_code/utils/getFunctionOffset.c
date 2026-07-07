/*
 * getFunctionOffset - Starburst call stack spoof profile utility.
 *
 * Calculates function offsets for use in spoof_profiles.h custom frame
 * definitions. Similar to Cobalt Strike's getFunctionOffset utility.
 *
 * USAGE:
 *   getFunctionOffset.exe <dll> <function> <offset_in_func>
 *   getFunctionOffset.exe ntdll.dll TpReleasePool 0x402
 *   getFunctionOffset.exe kernel32.dll BaseThreadInitThunk 0x14
 *
 * OUTPUT:
 *   Prints frame entry code for pasting into spoof_profiles.h in both
 *   function+offset format (portable) and module RVA format (exact).
 *
 * BUILD:
 *   cl.exe /nologo /O2 getFunctionOffset.c /Fe:getFunctionOffset.exe
 *   or:
 *   x86_64-w64-mingw32-gcc -O2 getFunctionOffset.c -o getFunctionOffset.exe
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

/* FNV-1a hash matching Starburst's expr::hash_string (case-insensitive) */
static DWORD fnv1a_hash(const char* str) {
    DWORD hash = 0x811c9dc5;
    while (*str) {
        unsigned char byte = (unsigned char)*str++;
        if (byte >= 'a')
            byte -= 0x20;
        hash ^= byte;
        hash *= 0x01000193;
    }
    return hash;
}

/* FNV-1a wide string hash matching expr::hash_string<wchar_t> */
static DWORD fnv1a_hash_w(const wchar_t* str) {
    DWORD hash = 0x811c9dc5;
    while (*str) {
        unsigned char byte = (unsigned char)(unsigned short)*str++;
        if (byte >= 'a')
            byte -= 0x20;
        hash ^= byte;
        hash *= 0x01000193;
    }
    return hash;
}

static void print_usage(const char* prog) {
    printf("Starburst getFunctionOffset - call stack spoof profile utility\n\n");
    printf("Usage: %s <dll> <function> <offset_in_func>\n\n", prog);
    printf("  dll              DLL name (e.g. ntdll.dll, kernel32.dll)\n");
    printf("  function         Exported function name (e.g. TpReleasePool)\n");
    printf("  offset_in_func   Hex offset within the function (e.g. 0x402)\n\n");
    printf("Examples:\n");
    printf("  %s ntdll.dll TpReleasePool 0x402\n", prog);
    printf("  %s kernel32.dll BaseThreadInitThunk 0x14\n", prog);
    printf("  %s ntdll.dll RtlUserThreadStart 0x21\n", prog);
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        print_usage(argv[0]);
        return 1;
    }

    const char* dll_name   = argv[1];
    const char* func_name  = argv[2];
    DWORD offset_in_func   = (DWORD)strtoul(argv[3], NULL, 0);

    /* load DLL */
    HMODULE lib = LoadLibraryA(dll_name);
    if (!lib) {
        fprintf(stderr, "Error: failed to load %s (GetLastError=%lu)\n",
                dll_name, GetLastError());
        return 1;
    }

    /* resolve function */
    void* func_addr = (void*)GetProcAddress(lib, func_name);
    if (!func_addr) {
        fprintf(stderr, "Error: function '%s' not found in %s\n",
                func_name, dll_name);
        FreeLibrary(lib);
        return 1;
    }

    /* calculate offsets */
    DWORD func_rva = (DWORD)((char*)func_addr - (char*)lib);
    DWORD target_rva = func_rva + offset_in_func;

    /* compute hashes */
    DWORD func_hash = fnv1a_hash(func_name);

    /* convert DLL name to wide for module hash */
    wchar_t dll_wide[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, dll_name, -1, dll_wide, MAX_PATH);
    DWORD mod_hash = fnv1a_hash_w(dll_wide);

    printf("\n");
    printf("  DLL:               %s\n", dll_name);
    printf("  Function:          %s\n", func_name);
    printf("  Function base:     0x%p\n", func_addr);
    printf("  Module base:       0x%p\n", (void*)lib);
    printf("  Function RVA:      0x%lx\n", func_rva);
    printf("  Offset in func:    0x%lx\n", offset_in_func);
    printf("  Target RVA:        0x%lx\n", target_rva);
    printf("  Module hash:       0x%08lx\n", mod_hash);
    printf("  Function hash:     0x%08lx\n", func_hash);
    printf("\n");

    printf("=== spoof_profiles.h entries ===\n\n");

    printf("// Function + offset (portable across Windows builds):\n");
    printf("    frames[i].module_hash = expr::hash_string<wchar_t>( L\"%s\" );\n", dll_name);
    printf("    frames[i].func_hash   = expr::hash_string( \"%s\" );\n", func_name);
    printf("    frames[i].offset      = 0x%lx;\n", offset_in_func);
    printf("    i++;\n\n");

    printf("// Module RVA (exact for this OS build, no function resolution):\n");
    printf("    frames[i].module_hash = expr::hash_string<wchar_t>( L\"%s\" );\n", dll_name);
    printf("    frames[i].func_hash   = 0;\n");
    printf("    frames[i].offset      = 0x%lx;\n", target_rva);
    printf("    i++;\n\n");

    printf("// Pre-computed hashes (if you want to avoid consteval in profile):\n");
    printf("    frames[i].module_hash = 0x%08lx;  // %s\n", mod_hash, dll_name);
    printf("    frames[i].func_hash   = 0x%08lx;  // %s\n", func_hash, func_name);
    printf("    frames[i].offset      = 0x%lx;\n", offset_in_func);
    printf("    i++;\n");

    FreeLibrary(lib);
    return 0;
}
