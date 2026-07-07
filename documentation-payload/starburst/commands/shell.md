+++
title = "shell"
chapter = false
weight = 103
+++

## Summary

Execute a shell command via `cmd.exe /c` and return the combined stdout/stderr output.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

- **command** (String, required) - The command string to execute.

### Usage

```
shell whoami /all
```

```
shell dir C:\Users /s /b
```

```
shell net user /domain
```

## Detailed Summary

The shell command spawns `cmd.exe /c <command>` using `CreateProcessW` with anonymous pipes for stdout and stderr capture. The output is collected and returned as a single response.

The command creates two pipes (stdout and stderr), configures `STARTUPINFO` to redirect handles, and waits for the process to complete before reading the output.

### APIs Used

| API | Purpose |
|-----|---------|
| `CreatePipe` | Create anonymous pipes for output capture |
| `CreateProcessW` | Spawn cmd.exe with redirected handles |
| `ReadFile` | Read from pipe handles |
| `WaitForSingleObject` | Wait for process completion |
| `CloseHandle` | Clean up pipe and process handles |

## MITRE ATT&CK Mapping

- **T1059.003** - Command and Scripting Interpreter: Windows Command Shell

## OPSEC Considerations

{{% notice warning %}}
This command spawns `cmd.exe` as a child process, which is a well-known indicator. EDR products commonly monitor for `cmd.exe` process creation, especially from unusual parent processes. Prefer `execute_coff` with a BOF for stealthier alternatives.
{{% /notice %}}

- Creates a child `cmd.exe` process visible in process listings
- Parent-child process relationship may be flagged (e.g., shellcode host -> cmd.exe)
- Command line arguments are logged by Sysmon Event ID 1 and Windows Security Event 4688
