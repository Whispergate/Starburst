+++
title = "shinject"
chapter = false
weight = 103
+++

## Summary

Inject shellcode into a remote process.

- **Needs Admin:** False
- **Version:** 2
- **Author:** @Lavender-exe

### Arguments

#### Parameter Group: Default

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| `pid` | Number | Yes | Target process ID to inject into. |
| `shellcode_name` | ChooseOne | Yes | Previously uploaded shellcode to inject (dynamic list of `.bin`, `.pic`, `.raw` files). |

#### Parameter Group: New

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| `pid` | Number | Yes | Target process ID to inject into. |
| `shellcode_file` | File | Yes | Upload new shellcode to inject. After uploading, reuse via the Default tab. |

### Usage

```
shinject -PID 1234 -Shellcode <shellcode.bin>
```

Select from previously uploaded shellcode files on the Default tab, or upload a new file on the New tab.

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
