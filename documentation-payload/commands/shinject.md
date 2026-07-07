+++
title = "shinject"
chapter = false
weight = 103
+++

## Summary

Inject shellcode into a remote process.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

- **pid** (Number, required) - Target process ID to inject into.
- **file** (File, required) - Shellcode file to inject. Supports raw PIC or Crystal Palace output.

### Usage

```
shinject -pid 1234
```

A file dialog will appear to select the shellcode file.

## Detailed Summary

Opens the target process with `OpenProcess` (PROCESS_ALL_ACCESS) and injects shellcode using the configured injection technique. The injection technique is selected at build time via the `injection_technique` build parameter - part of the [Starburst Arsenal Kit](https://github.com/Whispergate/Starburst.ArsenalKit).

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
| `VirtualAllocEx` | Allocate memory in target |
| `WriteProcessMemory` | Write shellcode to target |
| `VirtualProtectEx` | Change memory protection |
| `CreateRemoteThread` | Execute shellcode in target |
| `CloseHandle` | Clean up handles |

## MITRE ATT&CK Mapping

- **T1055.001** - Process Injection: Dynamic-link Library Injection

{{% notice info %}}
The injection technique is configurable via the Arsenal Kit. Switching from `crt` to `section` eliminates `VirtualAllocEx` and `WriteProcessMemory` telemetry. Switching to `apc` eliminates `CreateRemoteThread` events. See the [Arsenal Kit](https://github.com/Whispergate/Starburst.ArsenalKit) for details.
{{% /notice %}}

## OPSEC Considerations

- **CRT**: Cross-process `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` is heavily monitored - generates Sysmon Event ID 8
- **APC**: No `CreateRemoteThread` event but `QueueUserAPC` cross-process is monitored by some EDRs
- **Section**: No `VirtualAllocEx`/`WriteProcessMemory` telemetry - shared section blends with legitimate memory; `NtMapViewOfSection` cross-process is still observable
- **Custom**: Detection surface depends on implementation
- Target process selection matters - injecting into system processes requires elevation
- Consider using BOFs for less detectable alternatives when possible
