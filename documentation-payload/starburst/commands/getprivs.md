+++
title = "getprivs"
chapter = false
weight = 208
+++

## Summary

List token privileges for the current process.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

No arguments required.

### Usage

```
getprivs
```

## Detailed Summary

The getprivs command enumerates all privileges assigned to the current process token. It opens the process token with `OpenProcessToken`, retrieves the privilege information using `GetTokenInformation` with the `TokenPrivileges` class, and resolves each privilege LUID to a human-readable name using `LookupPrivilegeNameW`.

Each privilege is reported with its name and current state (enabled, disabled, or removed).

### APIs Used

| API | Purpose |
|-----|---------|
| `OpenProcessToken` | Open a handle to the current process token |
| `GetTokenInformation` | Retrieve privilege information from the token |
| `LookupPrivilegeNameW` | Resolve privilege LUIDs to names |

## MITRE ATT&CK Mapping

- **T1134** - Access Token Manipulation
