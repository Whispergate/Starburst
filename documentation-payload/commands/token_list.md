+++
title = "token_list"
chapter = false
weight = 103
+++

## Summary

Enumerate process tokens across all accessible processes, showing PID, username, integrity level, and process name.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

No arguments required.

### Usage

```
token_list
```

**Example Output:**

```
PID     User              Integrity   Process
4       -                 Untrusted   System
1234    CORP\jsmith       Medium      explorer.exe
5678    NT AUTHORITY\SYSTEM High      svchost.exe
```

## Detailed Summary

Enumerates all processes using `NtQuerySystemInformation`, then for each accessible process:

1. Opens the process with `OpenProcess`
2. Opens the process token with `OpenProcessToken`
3. Queries token user SID via `GetTokenInformation`
4. Resolves the SID to a domain\username via `LookupAccountSidW`
5. Queries integrity level from the token

Processes that cannot be opened (insufficient privileges) are listed with `-` for the user field.

## MITRE ATT&CK Mapping

- **T1057** - Process Discovery
- **T1134** - Access Token Manipulation
