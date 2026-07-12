# Starburst

A Position-Independent Code (PIC) agent for [Mythic](https://github.com/its-a-feature/Mythic), built on the [Stardust](https://github.com/Cracked5pider/Stardust) shellcode framework.

Starburst compiles to raw x64/x86 shellcode that runs entirely from memory with no PE on disk. It uses FNV1a hash-based API resolution, AES256-CBC encrypted comms, and a compact binary TLV wire protocol.

## Features

- **True PIC shellcode** - runs from any memory allocation, no loader required (x64 and x86)
- **[CrystalKit](Payload_Type/starburst/loaders/crystal-palace/README.md)** - Crystal Palace integration with custom UDRL and post-ex loader support, compatible with third-party Crystal Palace kits (Picollo, etc.)
- **Modular command system** - commands included/excluded at compile time via `#ifdef` guards
- **Binary TLV protocol** - compact serialization between agent and translation container
- **AES256-CBC + HMAC-SHA256** - encryption via Windows BCrypt APIs
- **Evasion** - indirect syscall table (HellsGate/HalosGate), sleep-time data masking, Draugr N-frame call stack spoofing with operator-customizable profiles
- **Arsenal Kit** - modular, operator-swappable injection techniques, sleep masks, and call stack spoof profiles via compile-time selection headers
- **Multiple transports** - HTTP (WinHTTP), HTTPX (malleable C2), GitHub (issue comments), SMB (named pipes), TCP (raw sockets)
- **Multiple output formats** - raw shellcode (.bin), executable (.exe), DLL (.dll), Windows service (.exe)

## Architecture

```
Payload_Type/Starburst/
  starburst/
    agent_code/           C++ agent source (Stardust framework)
      include/            Headers (instance class, config, macros)
      src/                Core logic (main, crypto, checkin, parser)
        commands/         Command handlers (one file per command)
        transport/        C2 transports (http, github, smb)
        evasion/          Evasion modules (syscalls, sleep masking, draugr)
        asm/              NASM entry stubs (x64, x86), Draugr ASM stub
      scripts/            Linker script
      loaders/            Output format wrappers (exe, dll, svc)
      utils/              Operator tools (getFunctionOffset)
    agent_functions/      Mythic command definitions (Python)
    browser_scripts/      Mythic UI scripts
  translator/             Binary TLV <-> Mythic JSON translation container
```

### Agent Internals

Starburst follows Stardust conventions:

- All mutable state lives in a stack-allocated `instance` struct passed by reference
- API function pointers resolved at init from PEB and stored on the instance
- String literals relocated at runtime via `symbol<T>()` using `RipData()`/`RipStart()` assembly stubs
- Functions placed in `.text$B` via `declfn` macro for inclusion in final shellcode
- No CRT, no exceptions, no imports - fully self-contained

### Wire Protocol

The agent uses a compact binary TLV format. A translation container converts between the agent's binary messages and Mythic's JSON API. This avoids embedding a JSON parser in the shellcode.

```
Agent <--[Binary TLV over HTTPS]--> C2 Profile <--[JSON]--> Translation Container <--[JSON]--> Mythic
```

## Installation

Install the agent into Mythic:

```bash
sudo ./mythic-cli install github https://github.com/Whispergate/Starburst
```

Or for local development, run the payload container directly:

```bash
cd Payload_Type/Starburst
python main.py
```

## Supported C2 Profiles

| Profile | Transport | Notes |
|---------|-----------|-------|
| HTTP | WinHTTP | Standard HTTPS callback |
| HTTPX | WinHTTP | Malleable C2 with transforms |
| GitHub | WinINet | C2 via GitHub issue comments |
| SMB | Named Pipes | Peer-to-peer |
| TCP | Raw TCP Sockets | Peer-to-peer |

## Call Stack Spoofing (Draugr)

Starburst includes the Draugr call stack spoofing system, which forges synthetic call stacks during sleep to defeat thread-based stack scanning. Operators can define custom frame sequences - similar to Cobalt Strike's `set_callstack()` in the sleep mask kit.

### Built-in Profiles

| Profile | Frames | Build Option |
|---------|--------|-------------|
| Thread | `BaseThreadInitThunk` → `RtlUserThreadStart` | `spoof_profile = thread` |
| Worker | `TppWorkerThread` → `RtlUserThreadStart` | `spoof_profile = worker` |
| Custom | Operator-defined N-frame stack (up to 10) | `spoof_profile = custom` |

### Custom Profiles

Edit `agent_code/include/evasion/spoof_profiles.h` to define your own frame sequence. The included `getFunctionOffset` utility calculates correct offsets for any target Windows version:

```
agent_code/utils/getFunctionOffset.exe ntdll.dll TpReleasePool 0x402
agent_code/utils/getFunctionOffset.exe kernel32.dll BaseThreadInitThunk 0x14
agent_code/utils/getFunctionOffset.exe ntdll.dll RtlUserThreadStart 0x21
```

Two resolution modes: function+offset (portable across Windows builds) and direct module RVA (exact for a specific OS version).

## Arsenal Kit

Starburst ships with an [Arsenal Kit](https://github.com/Whispergate/Starburst.ArsenalKit) - operator customization kit providing delivery templates, injection techniques, sleep evasion profiles, artifact wrappers, and operator utilities.

### Kit Overview

| Kit | Purpose | Key Files |
|-----|---------|-----------|
| **sleep-mask-kit** | Call stack spoof profiles + sleep masking customization | `profiles/*.h` |
| **artifact-kit** | EXE/DLL/SVC wrappers with evasion bypass techniques | `src/*.c`, `bypass/*.c` |
| **loader-kit** | Module stomping and DLL sideloading loaders | `stomper/`, `sideload/` |
| **injection-kit** | Alternative process injection techniques for shinject/migrate | `techniques/*.c` |
| **resource-kit** | Delivery stagers (PowerShell, HTA, VBS, Python, C#, MSBuild) | Per-language subdirectories |
1| **utils** | Operator tools (hash generator, offset calculator, encoder) | Per-tool subdirectories |

### Agent-Side Modules

Evasion behavior is controlled at compile time via operator-editable headers. Each module uses preprocessor `#if` selection with a Mythic build parameter, built-in implementations, and a `CUSTOM` slot for operator-defined logic.

| Module | Header | Build Parameter | Options |
|--------|--------|----------------|---------|
| Injection Technique | `include/evasion/injection_techniques.h` | `injection_technique` | `crt`, `apc`, `section`, `custom` |
| Sleep Mask | `include/evasion/sleep_masks.h` | `sleep_mask` | `default`, `full_image`, `heap`, `custom` |
| Call Stack Spoof Profile | `include/evasion/spoof_profiles.h` | `spoof_profile` | `thread`, `worker`, `custom` |

### Injection Kit

Reference implementations of process injection techniques. Each file is standalone and compilable, with OPSEC commentary. Adapt into Starburst's PIC codebase for `shinject`/`migrate`.

| Technique | File | OPSEC | New Thread? |
|-----------|------|-------|-------------|
| **CreateRemoteThread** | `inject_crt.c` | Low | Yes |
| **Early Bird APC** | `inject_apc.c` | Medium | No (APC on existing) |
| **Section Mapping** | `inject_section.c` | Medium-High | Yes |
| **Module Stomping** | `inject_stomp.c` | High | Yes (x2) |
| **Thread Hijack** | `inject_threadhijack.c` | Medium-High | No |

Recommended combinations for maximum OPSEC:
- **Section Mapping + Thread Hijack** - section-backed memory + no thread creation callback
- **Module Stomping + Thread Hijack** - image-backed memory (passes VAD scans) + no new thread
- **Early Bird APC + PPID Spoofing** - clean process context + legitimate parent-child relationship

### Sleep Mask Kit

Pre-built call stack spoofing profiles for Draugr. Copy a profile to `agent_code/include/evasion/spoof_profiles.h` and build with `spoof_profile = custom`.

| Profile | File | Frames | Pattern |
|---------|------|--------|---------|
| Standard thread | `thread_2frame.h` | 2 | Most common idle thread |
| Thread pool worker | `worker_2frame.h` | 2 | Services and background workers |
| Thread pool + TpReleasePool | `threadpool_3frame.h` | 3 | .NET and COM applications |
| COM RPC worker | `combase_4frame.h` | 4 | Uses RVA mode for combase.dll internals |
| WMI provider host | `wmi_3frame.h` | 3 | Mimics WmiPrvSE.exe worker threads |

Use `utils/getFunctionOffset` to calculate correct offsets for your target Windows version.

### Sleep Masks

| Mask | Description | OPSEC |
|------|-------------|-------|
| **Default** | XOR-masks AES key + UUIDs (~104 bytes) | Lightweight; agent code remains in plaintext |
| **Full Image** | XOR entire shellcode image with `VirtualProtect` RW↔RX flip | Defeats YARA/signature scans during sleep; generates `VirtualProtect` ETW events |
| **Heap** | XOR all heap blocks via `HeapWalk` + sensitive field masking | Catches dynamic allocations (task data, downloads); no `VirtualProtect` needed |
| **Custom** | Operator-defined masking with `xor_sensitive_data()` baseline | Edit the `MASK_CUSTOM` block in `sleep_masks.h` |

### Artifact Kit

Standalone C source files for EXE, DLL, and Windows Service wrappers that embed and execute Starburst shellcode. Each wrapper pairs with a bypass technique.

**Wrappers:** `main_exe.c` (EXE), `main_dll.c` (DLL), `main_svc.c` (Windows Service)

| Bypass | File | Description |
|--------|------|-------------|
| **Named Pipe** | `bypass_pipe.c` | XOR-encoded shellcode over random named pipe; never decoded in original PE image |
| **Fiber** | `bypass_fiber.c` | Fiber-based execution; no `CreateThread` call |
| **Self-APC** | `bypass_apc_self.c` | `NtTestAlert`-triggered APC to current thread; no thread creation or remote injection |
| **Callback** | `bypass_callback.c` | Shellcode via legitimate Windows callbacks (`EnumWindows`, `CreateTimerQueueTimer`, etc.) |

All bypass techniques use RW→RX page transitions (never RWX). Swap bypass modules at link time without modifying wrapper source.

### Loader Kit

Two complementary techniques for executing Starburst shellcode from disk:

| Technique | Description | Best Against |
|-----------|-------------|--------------|
| **Module Stomping** (`stomper/`) | Load legitimate signed DLL, overwrite `.text` with shellcode. Image-backed memory, thread start points to signed module. | VAD scanning, thread start heuristics |
| **DLL Sideloading** (`sideload/`) | Proxy DLL masquerading as dependency of a signed application. Forwards real exports, executes shellcode on `DLL_PROCESS_ATTACH`. | Process tree heuristics, application whitelisting |

Combine both for maximum OPSEC: sideloading for initial execution from trusted process, then module stomping for payload memory.

### Resource Kit

Delivery stagers for loading Starburst shellcode (.bin) payloads:

| Language | Stagers | OPSEC Range |
|----------|---------|-------------|
| **PowerShell** | VirtualAlloc+CreateThread, Delegate invoke, Download cradle, AES-encrypted staged | Low → High |
| **C#** | P/Invoke VirtualAlloc, NtCreateSection+NtMapViewOfSection, D/Invoke manual syscalls | Low-Medium → Very High |
| **HTA** | Drop and execute, Hidden PowerShell launch | Low → Low-Medium |
| **VBScript** | COM object execution chains | Low-Medium |
| **Python** | ctypes local VirtualAlloc, ctypes remote injection | Medium |
| **MSBuild** | Inline task (application whitelisting bypass) | High |

### Utils

| Tool | Description |
|------|-------------|
| `getFunctionOffset` | Calculate function offsets for call stack spoof profiles |
| `hashGenerator` | Generate FNV-1a / ROR13 hashes for API resolution |
| `xor_encoder.py` | XOR-encode payloads |
| `rc4_encoder.py` | RC4-encode payloads |

### Customization

Each agent-side module's `CUSTOM` slot contains a working fallback implementation. To add your own:

1. Select `custom` for the relevant build parameter in the Mythic payload dialog (or set the define in `config.h` for manual builds)
2. Edit the corresponding header under `agent_code/include/evasion/`
3. Your implementation must match the module's function signature - the rest of the agent calls it transparently

See the [Arsenal Kit repository](https://github.com/Whispergate/Starburst.ArsenalKit) for standalone examples, documentation, and community contributions.
