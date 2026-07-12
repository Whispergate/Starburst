+++
title = "dcomexec"
chapter = false
weight = 103
+++

## Summary
Execute a command on a remote host via DCOM MMC20.Application ExecuteShellCommand (no file staging).
- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| hostname | String | Yes | - | Target hostname or IP |
| command | String | Yes | - | Command to execute via DCOM MMC20.Application (wrapped in cmd.exe /c) |

### Usage
```
dcomexec -hostname TARGET -command whoami
```

```
dcomexec -hostname 10.0.0.5 -command "net user /domain"
```

## Detailed Summary

Executes a command on a remote host using the DCOM lateral movement technique via the MMC20.Application COM object. The command is wrapped in `cmd.exe /c` and executed through the `ExecuteShellCommand` method with a hidden window state.

The implementation performs the following steps:

1. Dynamically loads `ole32.dll` and `oleaut32.dll` via `LoadLibraryA` and resolves COM API functions via `GetProcAddress`
2. Initializes COM via `CoInitializeEx` and configures security via `CoInitializeSecurity` (authentication level: Packet Privacy, impersonation level: Impersonate)
3. Converts the hostname to a wide string and creates a `COSERVERINFO` structure pointing to the remote host
4. Instantiates the MMC20.Application COM object (CLSID `{49B2791A-B1AE-4C90-9B8E-E860BA07F889}`) remotely via `CoCreateInstanceEx` with `CLSCTX_REMOTE_SERVER`
5. Navigates the COM object hierarchy using `IDispatch::GetIDsOfNames` and `IDispatch::Invoke`:
   - Gets the `Document` property from the Application object
   - Gets the `ActiveView` property from the Document object
   - Resolves the `ExecuteShellCommand` method on the ActiveView
6. Calls `ExecuteShellCommand` with four BSTR arguments: Command (`cmd.exe`), Directory (empty), Parameters (`/c <user command>`), and WindowState (`7` = hidden)
7. Releases all COM interfaces and calls `CoUninitialize` to clean up

### APIs Used

| API | Purpose |
|-----|---------|
| `LoadLibraryA` | Dynamically load ole32.dll and oleaut32.dll |
| `GetProcAddress` | Resolve COM API function pointers |
| `CoInitializeEx` | Initialize COM runtime |
| `CoInitializeSecurity` | Configure COM security settings |
| `CoCreateInstanceEx` | Create MMC20.Application on the remote host |
| `IDispatch::GetIDsOfNames` | Resolve property/method DISPIDs (Document, ActiveView, ExecuteShellCommand) |
| `IDispatch::Invoke` | Get properties and call ExecuteShellCommand |
| `SysAllocString` | Allocate BSTR strings for COM parameters |
| `SysFreeString` | Free BSTR strings |
| `MultiByteToWideChar` | Convert hostname and command to wide strings |
| `CoUninitialize` | Clean up COM runtime |

## MITRE ATT&CK Mapping
- **T1021.003** - Remote Services: Distributed Component Object Model
