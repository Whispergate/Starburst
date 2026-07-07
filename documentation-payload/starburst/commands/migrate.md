+++
title = "migrate"
chapter = false
weight = 300
+++

## Summary

Migrate the agent into another process via process injection. Spawns a new process (or targets an existing one), allocates RWX memory, writes shellcode, and starts a remote thread.

- **Needs Admin:** False (True if targeting a higher-integrity process)
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `pid` | Number | No | None | Target an existing process by PID. If omitted, a new process is spawned. |
| `target` | String | No | `notepad.exe` | Path to the executable to spawn as the migration target. Ignored if `pid` is provided. |

### Usage

```
migrate -target "C:\Windows\System32\RuntimeBroker.exe"
```

```
migrate -pid 4728
```

**Example Output:**

```
[*] Spawning new process: C:\Windows\System32\notepad.exe
[*] Target PID: 8412
[*] Allocated RWX memory at 0x00007FF6A0010000
[*] Wrote 12288 bytes of shellcode
[*] Remote thread started successfully
[+] Migration complete
```

## Detailed Summary

Opens the target process with `OpenProcess` (PROCESS_ALL_ACCESS) and injects the agent's own shellcode using the configured injection technique. The injection technique is selected at build time via the `injection_technique` build parameter - part of the [Starburst Arsenal Kit](https://github.com/Whispergate/Starburst.ArsenalKit).

When a `pid` is provided, injection proceeds directly into the existing process. This requires sufficient privileges to open a handle to the target process. On success, the current agent instance exits (`inst.agent.running = false`).

### Available Injection Techniques

| Technique | Build Value | Method |
|-----------|------------|--------|
| **CreateRemoteThread** (default) | `crt` | `VirtualAllocEx(RW)` → `WriteProcessMemory` → `VirtualProtectEx(RX)` → `CreateRemoteThread` |
| **APC Early Bird** | `apc` | Same alloc/write/protect + suspended thread + `QueueUserAPC` + `ResumeThread` |
| **NtCreateSection** | `section` | `NtCreateSection` → `NtMapViewOfSection` (local RW) → copy → `NtMapViewOfSection` (remote RX) → `CreateRemoteThread` |
| **Custom** | `custom` | Operator-defined - edit `INJECT_CUSTOM` in `include/evasion/injection_techniques.h` |

### APIs Used (CRT - default)

| API | Purpose |
|-----|---------|
| `OpenProcess` | Open target process |
| `VirtualAllocEx` | Allocate memory in target process |
| `WriteProcessMemory` | Write shellcode into allocated memory |
| `VirtualProtectEx` | Change memory protection RW → RX |
| `CreateRemoteThread` | Execute shellcode in target |
| `CloseHandle` | Clean up process and thread handles |

## MITRE ATT&CK Mapping

- **T1055** - Process Injection
