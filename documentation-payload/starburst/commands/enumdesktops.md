+++
title = "enumdesktops"
chapter = false
weight = 303
+++

## Summary

Enumerate all window stations and their associated desktops on the system.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

No arguments required.

### Usage

```
enumdesktops
```

**Example Output:**

```
Window Station: WinSta0
  Desktop: Default
  Desktop: Disconnect
  Desktop: Winlogon

Window Station: Service-0x0-3e7$
  Desktop: Default
```

## Detailed Summary

Enumerates all window stations in the current session using `EnumWindowStationsW`, then for each window station enumerates all desktops using `EnumDesktopsW`. This is useful for identifying available desktops for injection or interaction, and for understanding the session layout on a target system.

### APIs Used

| API | Purpose |
|-----|---------|
| `EnumWindowStationsW` | Enumerate all window stations in the current session |
| `EnumDesktopsW` | Enumerate all desktops within each window station |

## MITRE ATT&CK Mapping

- **T1010** - Application Window Discovery
