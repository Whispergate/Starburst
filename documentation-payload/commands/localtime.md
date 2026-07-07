+++
title = "localtime"
chapter = false
weight = 305
+++

## Summary

Get the local system date and time.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

No arguments required.

### Usage

```
localtime
```

**Example Output:**

```
2025-03-15 14:32:07 (Saturday)
```

## Detailed Summary

Calls `GetLocalTime` to retrieve the current local date and time from the system clock. Returns the result formatted as a human-readable timestamp with the day of the week. Useful for understanding the target's timezone and verifying time synchronization across hosts.

### APIs Used

| API | Purpose |
|-----|---------|
| `GetLocalTime` | Retrieve the current local system time |

## MITRE ATT&CK Mapping

- **T1124** - System Time Discovery
