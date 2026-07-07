+++
title = "steal_token"
chapter = false
weight = 211
+++

## Summary

Steal and impersonate a token from a running process.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

- **pid** (Number, required) - The process ID to steal the token from.

### Usage

```
steal_token 4820
```

## Detailed Summary

The steal_token command opens a handle to the target process, opens its primary token, duplicates it as an impersonation token, and applies it to the current thread. This allows the agent to perform actions using the security context of the target process.

The token is duplicated with `SecurityImpersonation` level, enabling both local and network resource access under the stolen identity.

### APIs Used

| API | Purpose |
|-----|---------|
| `OpenProcess` | Obtain a handle to the target process |
| `OpenProcessToken` | Open the target process token |
| `DuplicateTokenEx` | Create an impersonation token copy |
| `ImpersonateLoggedOnUser` | Apply the duplicated token to the current thread |
| `CloseHandle` | Clean up handles |

## MITRE ATT&CK Mapping

- **T1134.001** - Access Token Manipulation: Token Impersonation/Theft

## OPSEC Considerations

{{% notice warning %}}
Stealing tokens from processes owned by other users requires `SeDebugPrivilege`, which is typically only available in elevated contexts. The `OpenProcess` call with `PROCESS_QUERY_INFORMATION` access on cross-user processes is monitored by some EDR products.
{{% /notice %}}
