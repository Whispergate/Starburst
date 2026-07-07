+++
title = "jump_dcomexec"
chapter = false
weight = 103
+++

## Summary

Lateral movement via DCOM (Distributed COM) object method invocation on a remote host.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

- **hostname** (String, required) - Target hostname or IP address.
- **command** (String, required) - Command to execute on the remote host.
- **method** (String, optional) - DCOM method to use. Default: `ShellBrowserWindow`. Options: `ShellBrowserWindow`, `MMC20.Application`, `ShellWindows`.

### Usage

```
jump_dcomexec -hostname WORKSTATION01 -command "powershell -enc JABYA..."
```

```
jump_dcomexec -hostname 10.0.0.50 -method MMC20.Application -command "cmd /c whoami > C:\temp\out.txt"
```

## Detailed Summary

Uses DCOM to instantiate a COM object on the remote host and invoke a method that executes a command:

### ShellBrowserWindow (default)

1. Initializes COM via `CoInitializeEx`
2. Creates a `ShellBrowserWindow` instance on the remote host via `CoCreateInstanceEx` with CLSCTX_REMOTE_SERVER
3. Navigates to the command via `IShellDispatch2::ShellExecute`
4. Cleans up COM interfaces

### MMC20.Application

1. Instantiates `MMC20.Application` on the remote host
2. Calls `Document.ActiveView.ExecuteShellCommand` to execute the command

### ShellWindows

1. Enumerates `ShellWindows` collection on the remote host
2. Obtains a `ShellFolderView` reference
3. Calls `Application.ShellExecute` to execute the command

### APIs Used

| API | Purpose |
|-----|---------|
| `CoInitializeEx` | Initialize COM |
| `CoCreateInstanceEx` | Create remote COM object |
| `CoSetProxyBlanket` | Set authentication |
| `IDispatch::Invoke` | Call methods on remote object |
| `CoUninitialize` | Clean up COM |

## MITRE ATT&CK Mapping

- **T1021.003** - Remote Services: Distributed Component Object Model

## OPSEC Considerations

- DCOM uses TCP/135 (RPC endpoint mapper) plus dynamic high ports
- Does not require SMB (TCP/445) unlike psexec/scshell
- No service creation or file drop required
- Process spawns on target under `svchost.exe -k DcomLaunch` or the COM surrogate - parent process differs from typical admin tools
- `ShellBrowserWindow` and `ShellWindows` methods spawn child processes under `explorer.exe` context which may blend better with normal activity
- `MMC20.Application` spawns under `mmc.exe` which is less common outside admin activity
- DCOM lateral movement generates Windows Security Event ID 4624 (logon type 3) and DCOM-specific ETW events
