# Starburst

A Position-Independent Code (PIC) agent for [Mythic](https://github.com/its-a-feature/Mythic), built on the [Stardust](https://github.com/Cracked5pider/Stardust) shellcode framework.

Starburst compiles to raw x64 shellcode that runs entirely from memory with no PE on disk. It uses FNV1a hash-based API resolution, AES256-CBC encrypted comms, and a compact binary TLV wire protocol.

## Features

- **True PIC shellcode** - runs from any memory allocation, no loader required
- **Crystal Palace compatible** - entry at offset 0, fully position-independent
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

Starburst ships with an [Arsenal Kit](https://github.com/Whispergate/Starburst.ArsenalKit) - a set of operator-editable headers that control evasion behavior at compile time. Each module follows the same pattern: preprocessor `#if` selection with a Mythic build parameter, a set of built-in implementations, and a `CUSTOM` slot for operator-defined logic.

### Modules

| Module | Header | Build Parameter | Options |
|--------|--------|----------------|---------|
| Injection Technique | `include/evasion/injection_techniques.h` | `injection_technique` | `crt`, `apc`, `section`, `custom` |
| Sleep Mask | `include/evasion/sleep_masks.h` | `sleep_mask` | `default`, `full_image`, `heap`, `custom` |
| Call Stack Spoof Profile | `include/evasion/spoof_profiles.h` | `spoof_profile` | `thread`, `worker`, `custom` |

### Injection Techniques

| Technique | Description | OPSEC |
|-----------|-------------|-------|
| **CRT** (default) | `VirtualAllocEx` → `WriteProcessMemory` → `VirtualProtectEx` → `CreateRemoteThread` | Baseline - generates ETW events for all four APIs |
| **APC** | Early Bird pattern - suspended thread + `QueueUserAPC` + `ResumeThread` | No `CreateRemoteThread` event; APC harder to attribute |
| **Section** | `NtCreateSection` + `NtMapViewOfSection` (local RW write, remote RX map) | No `VirtualAllocEx`/`WriteProcessMemory` telemetry; shared section blends with legit memory |
| **Custom** | Operator-defined injection logic with CRT fallback | Edit the `INJECT_CUSTOM` block in `injection_techniques.h` |

### Sleep Masks

| Mask | Description | OPSEC |
|------|-------------|-------|
| **Default** | XOR-masks AES key + UUIDs (~104 bytes) | Lightweight; agent code remains in plaintext |
| **Full Image** | XOR entire shellcode image with `VirtualProtect` RW↔RX flip | Defeats YARA/signature scans during sleep; generates `VirtualProtect` ETW events |
| **Heap** | XOR all heap blocks via `HeapWalk` + sensitive field masking | Catches dynamic allocations (task data, downloads); no `VirtualProtect` needed |
| **Custom** | Operator-defined masking with `xor_sensitive_data()` baseline | Edit the `MASK_CUSTOM` block in `sleep_masks.h` |

### Customization

Each module's `CUSTOM` slot contains a working fallback implementation. To add your own:

1. Select `custom` for the relevant build parameter in the Mythic payload dialog (or set the define in `config.h` for manual builds)
2. Edit the corresponding header under `agent_code/include/evasion/`
3. Your implementation must match the module's function signature - the rest of the agent calls it transparently

See the [Arsenal Kit repository](https://github.com/Whispergate/Starburst.ArsenalKit) for standalone examples, documentation, and community contributions.
