+++
title = "net_localgroup_member"
chapter = false
weight = 214
+++

## Summary

List members of a local group on a host.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

- **hostname** (String, optional) - The target hostname. Defaults to the local machine if not specified.
- **group** (String, required) - The name of the local group to enumerate.

### Usage

```
net_localgroup_member -group Administrators
```

```
net_localgroup_member -hostname WORKSTATION01 -group "Remote Desktop Users"
```

## Detailed Summary

The net_localgroup_member command enumerates all members of a specified local group on the target host using `NetLocalGroupGetMembers`. It returns the name and SID usage type (user, group, or well-known group) for each member.

### APIs Used

| API | Purpose |
|-----|---------|
| `NetLocalGroupGetMembers` | Enumerate members of the specified local group |
| `NetApiBufferFree` | Free the buffer allocated by the API |

## MITRE ATT&CK Mapping

- **T1069.001** - Permission Groups Discovery: Local Groups
