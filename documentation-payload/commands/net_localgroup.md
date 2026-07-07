+++
title = "net_localgroup"
chapter = false
weight = 213
+++

## Summary

List local groups on a host.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

- **hostname** (String, optional) - The target hostname. Defaults to the local machine if not specified.

### Usage

```
net_localgroup
```

```
net_localgroup -hostname WORKSTATION01
```

## Detailed Summary

The net_localgroup command enumerates all local groups on the specified host using `NetLocalGroupEnum`. If no hostname is provided, it queries the local machine. The function returns the name and comment for each local group.

### APIs Used

| API | Purpose |
|-----|---------|
| `NetLocalGroupEnum` | Enumerate local groups on the target host |
| `NetApiBufferFree` | Free the buffer allocated by the API |

## MITRE ATT&CK Mapping

- **T1069.001** - Permission Groups Discovery: Local Groups
