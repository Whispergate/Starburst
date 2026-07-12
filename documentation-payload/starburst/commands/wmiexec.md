+++
title = "wmiexec"
chapter = false
weight = 103
+++

## Summary
Execute a command on a remote host via WMI Win32_Process.Create (no file staging).
- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| hostname | String | Yes | - | Target hostname or IP |
| command | String | Yes | - | Command to execute via WMI Win32_Process.Create (wrapped in cmd.exe /c) |

### Usage
```
wmiexec -hostname TARGET -command whoami
```

```
wmiexec -hostname 10.0.0.5 -command "net user /domain"
```

## Detailed Summary

Executes a command on a remote host using Windows Management Instrumentation (WMI) by calling the `Win32_Process.Create` method. The command is prefixed with `cmd.exe /c` before execution.

The implementation performs the following steps:

1. Dynamically loads `ole32.dll` and `oleaut32.dll` via `LoadLibraryA` and resolves COM/WMI API functions via `GetProcAddress`
2. Initializes COM via `CoInitializeEx` and configures security via `CoInitializeSecurity` (authentication level: Packet Privacy, impersonation level: Impersonate)
3. Creates a WMI namespace path (`\\<hostname>\root\cimv2`) as a wide string
4. Creates an `IWbemLocator` instance via `CoCreateInstance` using CLSID `{4590F811-1D3A-11D0-891F-00AA004B2E24}`
5. Connects to the remote WMI service via `IWbemLocator::ConnectServer` with the namespace path
6. Sets the proxy blanket on the WMI service connection via `CoSetProxyBlanket` (RPC_C_AUTHN_WINNT, authentication level: Packet Privacy, impersonation level: Impersonate)
7. Retrieves the `Win32_Process` class object via `IWbemServices::GetObject`
8. Gets the `Create` method's input parameter definition via `IWbemClassObject::GetMethod`
9. Spawns an instance of the input parameters and sets the `CommandLine` property to `cmd.exe /c <user command>` via the `Put` method
10. Executes the `Win32_Process.Create` method via `IWbemServices::ExecMethod`
11. Releases all COM/WMI interfaces and calls `CoUninitialize` to clean up

### APIs Used

| API | Purpose |
|-----|---------|
| `LoadLibraryA` | Dynamically load ole32.dll and oleaut32.dll |
| `GetProcAddress` | Resolve COM/WMI function pointers |
| `CoInitializeEx` | Initialize COM runtime |
| `CoInitializeSecurity` | Configure COM security settings |
| `CoCreateInstance` | Create WbemLocator instance |
| `CoSetProxyBlanket` | Configure authentication on WMI service proxy |
| `IWbemLocator::ConnectServer` | Connect to remote WMI namespace |
| `IWbemServices::GetObject` | Retrieve Win32_Process class |
| `IWbemClassObject::GetMethod` | Get Create method input parameters |
| `IWbemClassObject::SpawnInstance` | Create input parameter instance |
| `IWbemServices::ExecMethod` | Execute Win32_Process.Create |
| `SysAllocString` | Allocate BSTR strings for WMI parameters |
| `SysFreeString` | Free BSTR strings |
| `MultiByteToWideChar` | Convert command string to wide string |
| `CoUninitialize` | Clean up COM runtime |

## MITRE ATT&CK Mapping
- **T1047** - Windows Management Instrumentation
