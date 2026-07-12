+++
title = "ppid_spoof"
chapter = false
weight = 103
+++

## Summary

Set or clear the parent PID for child process spoofing.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| ppid | Number | Yes | 0 | Parent PID to spoof (0 to disable) |

### Usage

```
ppid_spoof -ppid 1234
ppid_spoof -ppid 0
```

## Detailed Summary

The `ppid_spoof` command configures the agent's internal parent PID spoofing setting, which affects how future child processes are created. It does not immediately spawn any process; instead, it sets a stored PPID value that is used by other commands when they create child processes.

**Setting a PPID:**
1. Validates that the target PID is accessible by calling `OpenProcess` with `PROCESS_QUERY_INFORMATION` access.
2. If the process cannot be opened (e.g., it does not exist or access is denied), the command fails with an error.
3. On success, closes the validation handle and stores the PID in `inst.ppid_spoof` for use by subsequent process creation operations.

**Clearing (PID 0):**
1. Sets `inst.ppid_spoof` to 0, which disables parent PID spoofing.
2. Future child processes will inherit the agent's actual parent normally.

This is a configuration command -- it does not immediately spawn any processes but modifies how subsequent process-creating commands behave.

### APIs Used

| API | Purpose |
|-----|---------|
| OpenProcess | Validate that the target parent PID exists and is accessible |
| CloseHandle | Close the validation process handle |

## MITRE ATT&CK Mapping

- **T1134.004** - Access Token Manipulation: Parent PID Spoofing
