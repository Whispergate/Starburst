+++
title = "jump_wmiexec"
chapter = false
weight = 103
+++

## Summary

Execute a command on a remote host via WMI `Win32_Process.Create`.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

- **hostname** (String, required) - Target hostname or IP address.
- **command** (String, required) - Command to execute via WMI.

### Usage

```
jump_wmiexec -hostname WORKSTATION01 -command "powershell -enc JABYA..."
```

```
jump_wmiexec -hostname 10.0.0.50 -command "cmd /c whoami > C:\temp\out.txt"
```

## Detailed Summary

Uses COM to connect to the remote host's WMI service and invoke `Win32_Process.Create`:

1. Initializes COM via `CoInitializeEx`
2. Creates a `WbemLocator` instance via `CoCreateInstance`
3. Connects to `\\hostname\root\cimv2` via `IWbemLocator::ConnectServer`
4. Sets authentication on the proxy via `CoSetProxyBlanket`
5. Calls `Win32_Process.Create` with the specified command
6. Cleans up COM interfaces

### APIs Used

| API | Purpose |
|-----|---------|
| `CoInitializeEx` | Initialize COM |
| `CoCreateInstance` | Create WbemLocator |
| `IWbemLocator::ConnectServer` | Connect to remote WMI |
| `CoSetProxyBlanket` | Set authentication level |
| `IWbemServices::ExecMethod` | Call Win32_Process.Create |
| `CoUninitialize` | Clean up COM |

## MITRE ATT&CK Mapping

- **T1047** - Windows Management Instrumentation

## OPSEC Considerations

- WMI process creation generates Event ID 4688 (process creation) on the remote host
- WMI activity can be monitored via WMI Activity event log
- Does not require SMB access - uses DCOM (TCP/135 + dynamic high port)
- The command runs under the context of the user's credentials (Kerberos or NTLM)
- No file drop required for command execution
