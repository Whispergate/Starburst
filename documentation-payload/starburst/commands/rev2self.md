+++
title = "rev2self"
chapter = false
weight = 212
+++

## Summary

Revert to the original process token, dropping any impersonated token.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

No arguments required.

### Usage

```
rev2self
```

## Detailed Summary

The rev2self command reverts the current thread's security context to the original process token by calling `RevertToSelf`. This drops any impersonation token that was applied via `make_token` or `steal_token`, restoring the agent to its original identity.

### APIs Used

| API | Purpose |
|-----|---------|
| `RevertToSelf` | Revert the thread to the process token |

## MITRE ATT&CK Mapping

- **T1134** - Access Token Manipulation
