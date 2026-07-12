+++
title = "jump_wmiexec"
chapter = false
weight = 103
+++

## Summary

Stage a payload to a remote host via ADMIN$ and execute it using WMI Win32_Process.Create.

- **Needs Admin:** False
- **Version:** 2
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| hostname | String | Yes | - | Target hostname or IP |
| payload | File | Yes | - | Payload file to stage and execute on remote host |

### Usage

```
jump_wmiexec -hostname TARGET -payload <file>
jump_wmiexec -hostname 10.0.0.5 -payload <agent.exe>
```

## Detailed Summary

The `jump_wmiexec` command performs lateral movement by staging a payload to a remote host via the ADMIN$ share and executing it through WMI's `Win32_Process.Create` method. The payload filename is randomly generated (8 hex bytes + .exe) server-side.

The command works by:

1. **Payload staging:** Writing the payload file to `\\target\ADMIN$\Temp\<random>.exe` via SMB using `CreateFileA` and `WriteFile` over the UNC path.
2. **COM initialization:** Loading `ole32.dll` and `oleaut32.dll`, resolving COM APIs, and calling `CoInitializeEx` and `CoInitializeSecurity`.
3. **WMI connection:**
   - Creating an `IWbemLocator` instance via `CoCreateInstance`.
   - Connecting to the remote host's `\\target\root\cimv2` WMI namespace via `ConnectServer`.
   - Setting the proxy blanket on the WMI service connection via `CoSetProxyBlanket` for proper authentication.
4. **Process creation:**
   - Getting the `Win32_Process` class object via `IWbemServices::GetObject`.
   - Getting the `Create` method and spawning an input parameter instance.
   - Setting the `CommandLine` parameter to the staged payload path (`C:\Windows\Temp\<filename>`).
   - Executing the method via `IWbemServices::ExecMethod`.
5. **Cleanup:** Releasing all COM/WMI interfaces. If WMI execution fails, the staged file is deleted from the remote host.

### APIs Used

| API | Purpose |
|-----|---------|
| CreateFileA | Create the payload file on the remote host via UNC path |
| WriteFile | Write payload data to the staged file |
| DeleteFileW | Clean up staged payload on failure |
| LoadLibraryA | Load ole32.dll and oleaut32.dll |
| GetProcAddress | Resolve COM and BSTR function pointers |
| CoInitializeEx | Initialize COM |
| CoInitializeSecurity | Set COM security levels |
| CoCreateInstance | Create WbemLocator object |
| IWbemLocator::ConnectServer | Connect to remote WMI namespace |
| CoSetProxyBlanket | Set authentication on WMI proxy |
| IWbemServices::GetObject | Get Win32_Process class |
| IWbemClassObject::GetMethod | Get the Create method definition |
| IWbemClassObject::SpawnInstance | Create input parameter instance |
| IWbemServices::ExecMethod | Execute Win32_Process.Create |
| SysAllocString / SysFreeString | Allocate and free BSTRs for WMI parameters |
| MultiByteToWideChar | Convert strings to wide characters |
| CloseHandle | Close file handles |

## MITRE ATT&CK Mapping

- **T1047** - Windows Management Instrumentation
- **T1021.002** - Remote Services: SMB/Windows Admin Shares

## OPSEC Considerations

{{% notice warning %}}
This command writes a payload to the remote host's ADMIN$ share and executes it via WMI, both of which are heavily monitored activities. The payload is written to `C:\Windows\Temp\` with a random filename and is not automatically cleaned up after successful execution. WMI-based lateral movement is a well-documented technique detected by most EDR solutions via WMI event subscriptions and process creation monitoring. The operation requires ADMIN$ share access and WMI permissions on the target. WMI activity generates Windows event logs (WMI-Activity/Operational) and process creation events that can be correlated.
{{% /notice %}}
