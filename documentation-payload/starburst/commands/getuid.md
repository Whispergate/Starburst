+++
title = "getuid"
chapter = false
weight = 307
+++

## Summary

Get the current user identity including SID, integrity level, and elevation status.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

No arguments required.

### Usage

```
getuid
```

**Example Output:**

```
User:       CORP\jsmith
SID:        S-1-5-21-3623811015-3361044348-30300820-1013
Integrity:  Medium
Elevated:   False
```

## Detailed Summary

Opens the current process token with `OpenProcessToken` and queries it using `GetTokenInformation` to retrieve the token user SID, integrity level, and elevation status. The SID is resolved to a `DOMAIN\username` string via `LookupAccountSidW`. The integrity level is determined from the token's mandatory label (Low, Medium, High, or System). Elevation status is queried from the `TokenElevation` information class.

This provides a more comprehensive identity picture than `whoami`, which only returns the username.

### APIs Used

| API | Purpose |
|-----|---------|
| `OpenProcessToken` | Open the current process token |
| `GetTokenInformation` | Query token user SID, integrity level, and elevation type |
| `LookupAccountSidW` | Resolve SID to domain and username |

## MITRE ATT&CK Mapping

- **T1033** - System Owner/User Discovery
