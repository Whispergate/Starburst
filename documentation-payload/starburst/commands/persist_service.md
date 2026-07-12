+++
title = "persist_service"
chapter = false
weight = 103
+++

## Summary

Install or remove a Windows service for persistence.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| action | ChooseOne (install, remove) | Yes | install | Install or remove the service |
| name | String | Yes | - | Service name |
| display_name | String | No | Same as name | Service display name (defaults to name if empty) |
| binary_path | String | No | - | Full path to service binary (required for install) |

### Usage

```
persist_service -action install -name "WinSvcHelper" -binary_path "C:\Windows\Temp\svc.exe"
persist_service -action install -name "UpdateSvc" -display_name "Windows Update Service" -binary_path "C:\Users\Public\agent.exe"
persist_service -action remove -name "WinSvcHelper"
```

## Detailed Summary

The `persist_service` command manages persistence by creating or deleting Windows services through the Service Control Manager (SCM) API.

**Install:**
1. Opens the SCM with `SC_MANAGER_CREATE_SERVICE` access.
2. Calls `CreateServiceW` to create a new service with the following configuration:
   - Service type: `SERVICE_WIN32_OWN_PROCESS`
   - Start type: `SERVICE_AUTO_START` (starts automatically at boot)
   - Error control: `SERVICE_ERROR_NORMAL`
   - Access: `SERVICE_ALL_ACCESS`
3. If no display name is provided, the service name is used as the display name.

**Remove:**
1. Opens the SCM with `SC_MANAGER_ALL_ACCESS`.
2. Opens the target service with `DELETE` access via `OpenServiceW`.
3. Calls `DeleteService` to mark the service for deletion.

All string arguments are converted from ANSI to wide character format via `MultiByteToWideChar` before being passed to the W-variant SCM APIs.

### APIs Used

| API | Purpose |
|-----|---------|
| OpenSCManagerW | Open the Service Control Manager |
| CreateServiceW | Create a new auto-start service (install) |
| OpenServiceW | Open an existing service for deletion (remove) |
| DeleteService | Mark the service for deletion (remove) |
| CloseServiceHandle | Close SCM and service handles |
| MultiByteToWideChar | Convert strings to wide characters |

## MITRE ATT&CK Mapping

- **T1543.003** - Create or Modify System Process: Windows Service

## OPSEC Considerations

{{% notice warning %}}
Service creation requires administrator privileges (despite `needs_admin` being set to False in the Mythic definition). Windows Security Event ID 4697 (A service was installed in the system) and System Event ID 7045 are generated on service creation. Sysmon Event ID 1 logs the service binary execution. EDR products heavily monitor SCM API calls including `OpenSCManager`, `CreateService`, and `DeleteService`. The service binary path is stored in the registry under `HKLM\SYSTEM\CurrentControlSet\Services\<name>` and is trivially discoverable via `sc query` or the Services MMC snap-in. Auto-start services persist across reboots and run as SYSTEM by default.
{{% /notice %}}
