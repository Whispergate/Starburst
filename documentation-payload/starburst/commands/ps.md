+++
title = "ps"
chapter = false
weight = 103
+++

## Summary

List running processes with PID, PPID, and process name.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

No arguments required.

### Usage

```
ps
```

## Detailed Summary

Enumerates all running processes using `NtQuerySystemInformation` with `SystemProcessInformation` class. This is a lower-level approach than the `CreateToolhelp32Snapshot` alternative and avoids loading additional libraries.

For each process, returns:
- Process ID (PID)
- Parent Process ID (PPID)
- Process name (from `ImageName` field)

Results are returned as structured JSON for Mythic's process browser integration.

### APIs Used

| API | Purpose |
|-----|---------|
| `NtQuerySystemInformation` | Enumerate all process entries |

## MITRE ATT&CK Mapping

- **T1057** - Process Discovery
