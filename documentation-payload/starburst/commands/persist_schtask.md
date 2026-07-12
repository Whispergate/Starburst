+++
title = "persist_schtask"
chapter = false
weight = 103
+++

## Summary

Create or delete a scheduled task for persistence.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| action | ChooseOne (install, remove) | Yes | install | Install or remove the scheduled task |
| name | String | Yes | - | Scheduled task name |
| command | String | No | - | Command to execute (required for install) |
| trigger | ChooseOne (logon, daily, startup) | Yes | logon | Task trigger type |

### Usage

```
persist_schtask -action install -name "SystemHealthCheck" -command "C:\Users\Public\payload.exe" -trigger logon
persist_schtask -action install -name "DailyMaintenance" -command "C:\Temp\svc.exe" -trigger daily
persist_schtask -action install -name "StartupTask" -command "C:\Windows\Temp\agent.exe" -trigger startup
persist_schtask -action remove -name "SystemHealthCheck"
```

## Detailed Summary

The `persist_schtask` command manages persistence via Windows Scheduled Tasks by invoking `schtasks.exe` as a child process. It supports two actions:

**Install:**
1. Maps the trigger argument to the corresponding `schtasks.exe /SC` value:
   - `logon` maps to `ONLOGON`
   - `daily` maps to `DAILY`
   - `startup` maps to `ONSTART`
2. Builds the command: `schtasks.exe /Create /TN "<name>" /TR "<command>" /SC <trigger> /F`
3. Spawns the process with output captured via an anonymous pipe (`CreatePipe`).
4. The command runs asynchronously in a background thread that waits up to 30 seconds, reads stdout/stderr, and reports the result back to the Mythic server.

**Remove:**
1. Builds the command: `schtasks.exe /Delete /TN "<name>" /F`
2. Spawns and monitors the process using the same pipe-and-thread mechanism.

The child process is created hidden with `CREATE_NO_WINDOW` and `SW_HIDE`. Stdout and stderr are redirected through inherited pipe handles and collected by a reader thread. The task is tracked in the agent's job table.

### APIs Used

| API | Purpose |
|-----|---------|
| MultiByteToWideChar | Convert command line to wide string |
| CreatePipe | Create anonymous pipe for stdout/stderr capture |
| CreateProcessW | Launch schtasks.exe with hidden window |
| WaitForSingleObject | Wait for schtasks.exe to complete (30s timeout) |
| ReadFile | Read output from the pipe |
| TerminateProcess | Kill process if it exceeds timeout |
| CreateThread | Spawn background thread for async execution |
| CloseHandle | Clean up process and pipe handles |

## MITRE ATT&CK Mapping

- **T1053.005** - Scheduled Task/Job: Scheduled Task

## OPSEC Considerations

{{% notice warning %}}
This command spawns `schtasks.exe` as a child process, which is visible in process creation logs (Sysmon Event ID 1) and has a well-known command line signature. Scheduled task creation generates Windows Security Event ID 4698 and Sysmon Event ID 11. The `/F` flag forces overwrite of existing tasks which may trigger additional alerts. EDR products commonly monitor for `schtasks.exe /Create` command lines. The `startup` trigger requires administrator privileges. Task Scheduler artifacts are also enumerable via `schtasks /Query` and the Task Scheduler MMC snap-in.
{{% /notice %}}
