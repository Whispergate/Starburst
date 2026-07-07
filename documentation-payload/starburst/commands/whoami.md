+++
title = "whoami"
chapter = false
weight = 103
+++

## Summary

Get the current user identity in `DOMAIN\username` format.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

No arguments required.

### Usage

```
whoami
```

**Example Output:**

```
CORP\jsmith
```

## Detailed Summary

Retrieves the current username via `GetUserNameW` and performs a domain lookup using `LookupAccountSidW` to get the full `DOMAIN\username` string. Uses token information from the current process token.

### APIs Used

| API | Purpose |
|-----|---------|
| `GetUserNameW` | Get current username |
| `OpenProcessToken` | Open process token for SID lookup |
| `GetTokenInformation` | Retrieve token user SID |
| `LookupAccountSidW` | Resolve SID to domain and username |

## MITRE ATT&CK Mapping

- **T1033** - System Owner/User Discovery
