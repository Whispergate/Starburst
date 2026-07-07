+++
title = "Evasion Features"
chapter = false
weight = 5
+++

## Built-in Evasion

Starburst includes several evasion features that operate transparently during agent execution.

### Indirect Syscalls

The agent resolves syscall numbers (SSNs) at runtime by walking the ntdll export address table. Syscalls are executed via a `syscall; ret` trampoline gadget found in ntdll's `.text` section, ensuring the return address on the call stack points to ntdll memory rather than unbacked executable regions.

**Detection surface reduced:**
- No direct `syscall` instructions in agent memory
- Call stack appears to originate from ntdll
- SSN resolution avoids hardcoded values that change across Windows versions

**Limitations:**
- Syscall table limited to 16 entries (covers core Nt* functions)
- Only `Nt`-prefixed exports are resolved (skips `Ntdll`-internal helpers)
- If ntdll `.text` is heavily hooked (all stubs patched), SSN extraction may fail for those entries

### Sleep Data Masking

Before each sleep cycle, the agent masks sensitive data using a configurable sleep mask module. The mask type is selected at build time via the `sleep_mask` build parameter or the `SLEEP_MASK_TYPE` define in `config.h`. All masks use a random RC4 key generated at initialization via `BCryptGenRandom`.

**Available Sleep Masks:**

| Mask | Build Parameter | What It Masks |
|------|----------------|---------------|
| **Default** | `sleep_mask = default` | AES256 session key (32 bytes), Callback UUID (36 bytes), Payload UUID (36 bytes) - ~104 bytes total |
| **Full Image** | `sleep_mask = full_image` | Entire shellcode image XOR'd via `VirtualProtect` RW↔RX flip. Defeats YARA rules and string matching during sleep |
| **Heap** | `sleep_mask = heap` | All `PROCESS_HEAP_ENTRY_BUSY` blocks via `HeapWalk` + sensitive fields. Catches dynamic allocations (task data, downloaded files) |
| **Custom** | `sleep_mask = custom` | Operator-defined. Edit `MASK_CUSTOM` in [`include/evasion/sleep_masks.h`](https://github.com/Whispergate/Starburst.ArsenalKit). Baseline `xor_sensitive_data()` included |

Data is unmasked immediately after sleep returns. This ensures that memory scanners examining the process during sleep intervals cannot extract cryptographic keys or identifiers in plaintext.

The sleep mask module is part of the [Starburst Arsenal Kit](https://github.com/Whispergate/Starburst.ArsenalKit) - operators can swap or extend masks without modifying core agent code.

**Limitations:**
- The RC4 key itself remains in memory (16 bytes in the instance struct)
- Instance struct metadata (sleep interval, jitter, module handles) is not masked
- Full Image mask generates `VirtualProtect` ETW events for the RW↔RX flip
- Heap mask skips blocks smaller than 16 bytes and skips the block containing the RC4 key itself
- Ekko/Zilean-style ROP masking (timer queue based) requires modifying the beacon loop directly - see Arsenal Kit for reference

### Call Stack Spoofing (Draugr)

Before sleeping, the agent forges a synthetic call stack using the Draugr stack spoofing system. This ensures that when `NtDelayExecution` is called, the return addresses on the thread's stack point to legitimate system DLL frames rather than the agent's shellcode region.

**Spoof Profiles:**

| Profile | Spoofed Chain | Build Parameter |
|---------|--------------|-----------------|
| Thread | `BaseThreadInitThunk` → `RtlUserThreadStart` | `spoof_profile = thread` |
| Worker | `TppWorkerThread` → `RtlUserThreadStart` | `spoof_profile = worker` |
| Custom | Operator-defined N-frame stack | `spoof_profile = custom` |

**Custom Profiles:**

Operators can define custom call stack spoof profiles by editing `agent_code/include/evasion/spoof_profiles.h`. This works like Cobalt Strike's `set_callstack()` in the sleep mask kit - operators specify the exact frame sequence they want to present during sleep. The spoof profiles module is part of the [Starburst Arsenal Kit](https://github.com/Whispergate/Starburst.ArsenalKit).

The included `getFunctionOffset.exe` utility (in `agent_code/utils/`) calculates the correct offsets for any target Windows version:

```
getFunctionOffset.exe ntdll.dll TpReleasePool 0x402
getFunctionOffset.exe kernel32.dll BaseThreadInitThunk 0x14
getFunctionOffset.exe ntdll.dll RtlUserThreadStart 0x21
```

Custom profiles support up to 10 frames and two resolution modes: function+offset (portable across Windows builds) and direct module RVA (exact for a specific OS version).

**Implementation:**
- Supports N arbitrary frames (up to 10) defined at compile time via `spoof_profiles.h`
- Parses `RUNTIME_FUNCTION` and `UNWIND_INFO` structures to calculate exact stack frame sizes for each spoofed function
- Pre-computes all frame return addresses and stack sizes at initialization (performance improvement over per-call resolution)
- Scans KernelBase.dll `.text` section for `JMP [RBX]` gadgets to use as ROP trampolines
- ASM stub builds frames in a loop - no hardcoded frame count limit
- Applies to `NtDelayExecution` during the sleep cycle

**Detection surface reduced:**
- Sleep-time thread stack inspection sees legitimate kernel32/ntdll frames
- Defeats stack-based thread scanning that flags threads sleeping from unbacked memory
- Gadget-based execution avoids direct calls from shellcode addresses
- Custom profiles allow operators to mimic specific thread patterns observed in the target environment

**Limitations:**
- Only applies during sleep (NtDelayExecution), not to all API calls during active execution
- KernelBase.dll must be loaded for gadget discovery (loaded by default on all modern Windows)
- Spoof profile is selected at build time, not runtime-configurable
- Frames using `UWOP_SET_FPREG` (frame pointer register) are calculated but RBP chain walking is not yet fully spoofed

### API Call Obfuscation

All Windows API calls are resolved dynamically at runtime via FNV-1a hash-based resolution. No import table entries exist in the shellcode. API function pointers are stored in module sub-structs within the instance structure and resolved by walking the PEB loaded module list and each module's export address table.

**Detection surface reduced:**
- No static imports to scan
- No `GetProcAddress` calls (custom hash-based resolution)
- API names never appear as strings in the binary

### Arsenal Kit

Starburst's evasion modules are designed as operator-swappable headers following the [Arsenal Kit](https://github.com/Whispergate/Starburst.ArsenalKit) pattern. Each module uses compile-time `#if` preprocessor selection with a matching Mythic build parameter:

| Module | Header | Build Parameter | Options |
|--------|--------|----------------|---------|
| Injection Technique | `evasion/injection_techniques.h` | `injection_technique` | `crt`, `apc`, `section`, `custom` |
| Sleep Mask | `evasion/sleep_masks.h` | `sleep_mask` | `default`, `full_image`, `heap`, `custom` |
| Call Stack Spoof Profile | `evasion/spoof_profiles.h` | `spoof_profile` | `thread`, `worker`, `custom` |

Every module includes a `CUSTOM` slot with a working fallback implementation. Operators edit the custom block in the corresponding header to implement their own technique - the rest of the agent calls it transparently through the shared interface.

**Injection techniques** control how `shinject` and `migrate` deliver shellcode to remote processes. The selected technique applies to both commands automatically.

**Sleep masks** control what data is masked during sleep cycles. Higher-coverage masks (Full Image, Heap) provide better evasion at the cost of additional API calls or ETW telemetry.

**Spoof profiles** control the synthetic call stack presented during `NtDelayExecution` sleep calls. Custom profiles should match thread patterns observed in the target environment.

See the [Arsenal Kit repository](https://github.com/Whispergate/Starburst.ArsenalKit) for standalone examples, documentation, and community contributions.

## Build-Time Considerations

### Debug vs Release

| Feature | Debug Build | Release Build |
|---------|------------|---------------|
| `DbgPrint` output | Enabled | Disabled |
| Size | ~60-70KB | ~44KB |
| String literals | May contain debug messages | Minimal |
| Optimization | `-Os` | `-Os` |

{{% notice warning %}}
Debug builds contain `DbgPrint` format strings that reveal internal function names, state transitions, and protocol details. Never deploy debug builds outside controlled test environments.
{{% /notice %}}

### PIC Constraints

All code resides in the `.text` section. No `.data`, `.bss`, or `.rodata` sections are present in the final shellcode. This means:

- No file-scope `static` variables
- No raw string literals (use `symbol<>()` or character-by-character comparison)
- All mutable state lives on the stack (instance struct) or the heap
- Function pointers are resolved at runtime, not link time
