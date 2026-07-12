+++
title = "uptime"
chapter = false
weight = 103
+++

## Summary

Get system uptime and approximate boot time.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

No arguments required.

### Usage

```
uptime
```

## Detailed Summary

The `uptime` command retrieves the system's uptime duration and calculates an approximate boot time.

The agent resolves `GetSystemTime` and the appropriate tick count function from `kernel32.dll`. On x64 builds, it uses `GetTickCount64` for accurate uptime beyond 49.7 days; on x86 builds, it falls back to `GetTickCount` (which wraps after approximately 49.7 days).

The tick count (in milliseconds) is converted to seconds, then broken down into days, hours, minutes, and seconds. The command also retrieves the current UTC system time via `GetSystemTime` and subtracts the uptime to compute an approximate boot timestamp, handling borrows across seconds, minutes, hours, days, months, and years.

The output includes two lines:
- **Uptime** - formatted as `Xd Xh Xm Xs` (e.g., `3d 12h 45m 30s`)
- **Boot** - approximate boot time in `YYYY-MM-DD HH:MM:SS` format (UTC)

### APIs Used

| API | Purpose |
|-----|---------|
| GetProcAddress | Resolve system time and tick count functions |
| GetTickCount64 | Retrieve system uptime in milliseconds (x64) |
| GetTickCount | Retrieve system uptime in milliseconds (x86) |
| GetSystemTime | Get current UTC system time for boot time calculation |

## MITRE ATT&CK Mapping

- **T1082** - System Information Discovery
