+++
title = "jump_scshell"
chapter = false
weight = 103
+++

## Summary

Lateral movement by modifying an existing service's binary path on a remote host (SCShell technique). Executes a command without dropping any files.

- **Needs Admin:** True
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

- **hostname** (String, required) - Target hostname or IP address.
- **service_name** (String, optional) - Existing service to hijack on the remote host. Default: `SensSvc`.
- **command** (String, required) - Command to execute. Automatically wrapped in `%COMSPEC% /c`.

### Usage

```
jump_scshell -hostname DC01 -command "powershell -enc JABYA..."
```

```
jump_scshell -hostname DC01 -service_name AppMgmt -command "net user backdoor P@ss123 /add"
```

## Detailed Summary

Uses the SCShell technique to modify an existing service's binary path:

1. Connects to the remote SCM via `OpenSCManagerW`
2. Opens the target service with `OpenServiceW`
3. Queries the current service config with `QueryServiceConfigW` (saves original binary path)
4. Changes the service binary path to `%COMSPEC% /c <command>` via `ChangeServiceConfigW`
5. Starts the service with `StartServiceW` (executes the command)
6. Restores the original binary path via `ChangeServiceConfigW`

### Key Advantage

No file drop required. The command is executed by modifying an existing service configuration, then immediately restoring it. This avoids writing any binary to the remote host's filesystem.

### APIs Used

| API | Purpose |
|-----|---------|
| `OpenSCManagerW` | Connect to remote SCM |
| `OpenServiceW` | Open existing service |
| `QueryServiceConfigW` | Save original service config |
| `ChangeServiceConfigW` | Modify service binary path |
| `StartServiceW` | Trigger command execution |
| `CloseServiceHandle` | Clean up handles |

## MITRE ATT&CK Mapping

- **T1021.002** - Remote Services: SMB/Windows Admin Shares
- **T1543.003** - Create or Modify System Process: Windows Service

## OPSEC Considerations

- Requires local administrator privileges on the target host
- Service config modification generates Event ID 7040 in the System log
- The service will fail to start (exit code != 0) since cmd.exe is not a proper service binary - this is expected
- The original service config is restored, but a brief window exists where the modification is visible
- Default target `SensSvc` (System Event Notification Service) is a common choice since it's rarely monitored
