+++
title = "runas"
chapter = false
weight = 103
+++

## Summary

Execute a command as a different user using explicit credentials.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| domain | String | No | . | Domain name (use `.` for local) |
| username | String | Yes | - | Username to run as |
| password | String | Yes | - | Password for the user |
| command | String | Yes | - | Command to execute |

### Usage

```
runas -domain . -username admin -password P@ssw0rd -command "whoami"
runas -domain CORP -username svc_account -password Secret123 -command "cmd.exe /c ipconfig"
runas -username localadmin -password Welcome1 -command "powershell.exe -c Get-Process"
```

## Detailed Summary

The `runas` command spawns a new process under a different user context by using explicit credentials. It performs the following steps:

1. Parses the domain, username, password, and command arguments from the task parameters.
2. Loads `advapi32.dll` via `LoadLibraryA` and dynamically resolves `CreateProcessWithLogonW` using `GetProcAddress`.
3. Converts all ANSI string arguments (domain, username, password, command) to wide character format using `MultiByteToWideChar`.
4. Calls `CreateProcessWithLogonW` with:
   - `LOGON_WITH_PROFILE` flag to load the target user's profile.
   - `CREATE_NO_WINDOW` to suppress any visible window.
   - The domain parameter is passed as `nullptr` if empty.
5. On success, returns the new process PID in the format `Process created as <domain>\<username> PID: <pid>`.
6. Closes both the process and thread handles after creation.

The spawned process runs independently; the command does not wait for it to complete or capture its output.

### APIs Used

| API | Purpose |
|-----|---------|
| LoadLibraryA | Load advapi32.dll for logon API access |
| GetProcAddress | Resolve CreateProcessWithLogonW dynamically |
| CreateProcessWithLogonW | Create a process under specified user credentials |
| MultiByteToWideChar | Convert ANSI strings to wide characters |
| CloseHandle | Close process and thread handles |

## MITRE ATT&CK Mapping

- **T1134.002** - Access Token Manipulation: Create Process with Token

## OPSEC Considerations

{{% notice warning %}}
`CreateProcessWithLogonW` generates a Type 9 (NewCredentials) logon event (Windows Security Event ID 4624) and an explicit credential use event (Event ID 4648). The target process creation is logged via Sysmon Event ID 1. Credentials are passed in plaintext through the API call. EDR products monitor for `CreateProcessWithLogonW` calls as they are commonly used for lateral movement and privilege escalation. The Secondary Logon service (`seclogon`) must be running for this API to succeed.
{{% /notice %}}
