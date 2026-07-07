+++
title = "kill"
chapter = false
weight = 206
+++

## Summary

Terminate a process by PID.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

- **pid** (Number, required) - The process ID to terminate.

### Usage

```
kill 1234
```

## Detailed Summary

The kill command terminates a target process by opening a handle to it with `OpenProcess` and calling `TerminateProcess`. The process is terminated with exit code 0.

Killing processes owned by other users or elevated processes requires `SeDebugPrivilege`.

### APIs Used

| API | Purpose |
|-----|---------|
| `OpenProcess` | Obtain a handle to the target process |
| `TerminateProcess` | Terminate the target process |
| `CloseHandle` | Clean up the process handle |

## MITRE ATT&CK Mapping

- **T1489** - Service Stop

## OPSEC Considerations

- Process termination is logged by EDR products and may generate alerts
- Terminating security-related processes (AV, EDR agents) will likely trigger immediate alerts
