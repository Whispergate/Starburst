+++
title = "idletime"
chapter = false
weight = 306
+++

## Summary

Get the time elapsed since the user's last keyboard or mouse input.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

No arguments required.

### Usage

```
idletime
```

**Example Output:**

```
User idle for: 0h 7m 32s
```

## Detailed Summary

Uses `GetLastInputInfo` to retrieve the tick count of the last user input event, then compares it to the current tick count from `GetTickCount` to calculate the idle duration. This is useful for determining whether a user is actively at their workstation before performing interactive actions such as keylogging or screenshots.

### APIs Used

| API | Purpose |
|-----|---------|
| `GetLastInputInfo` | Get the tick count of the last input event |
| `GetTickCount` | Get the current system tick count |

## MITRE ATT&CK Mapping

- **T1082** - System Information Discovery
