+++
title = "run"
chapter = false
weight = 207
+++

## Summary

Execute a command directly without `cmd.exe`.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

- **command** (String, required) - The full command line to execute.

### Usage

```
run whoami.exe /all
```

```
run net.exe user /domain
```

```
run ipconfig.exe /all
```

## Detailed Summary

The run command executes a program directly using `CreateProcessW` without spawning `cmd.exe` as an intermediary. The command string is passed directly to `CreateProcessW`, which resolves the executable from the system PATH. Output is captured via anonymous pipes and returned.

This avoids the `cmd.exe` parent-child process relationship that is commonly monitored by EDR.

### APIs Used

| API | Purpose |
|-----|---------|
| `CreateProcessW` | Spawn the target process directly |
| `CreatePipe` | Create anonymous pipes for output capture |
| `ReadFile` | Read stdout/stderr from the process |
| `WaitForSingleObject` | Wait for process completion |
| `CloseHandle` | Clean up handles |

## MITRE ATT&CK Mapping

- **T1106** - Native API

## OPSEC Considerations

- No `cmd.exe` child process is created, reducing detection surface
- Command line arguments are still logged by Sysmon Event ID 1 and Windows Security Event 4688
- The parent-child process relationship (agent process -> target executable) is still observable
