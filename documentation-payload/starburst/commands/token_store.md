+++
title = "token_store"
chapter = false
weight = 103
+++

## Summary

Manage stored access tokens for impersonation.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| action | ChooseOne (list, use, remove) | Yes | list | Action to perform on the token store |
| token_id | Number | No | 0 | Token ID to use or remove (0 for list) |

### Usage

```
token_store -action list
token_store -action use -token_id 2
token_store -action remove -token_id 2
```

## Detailed Summary

The `token_store` command manages an internal store of up to 8 Windows access tokens that have been captured (e.g., via `steal_token`). It supports three actions:

**list:** Enumerates all active tokens in the store, displaying a table with columns for ID, Username, PID (source process), and Active status.

**use:** Activates impersonation using a stored token by calling `ImpersonateLoggedOnUser`. If a previous impersonation token exists, it is closed first. The selected token becomes the agent's active impersonation context, affecting subsequent operations that respect thread tokens.

**remove:** Removes a token from the store. If the token being removed is the currently active impersonation token, `RevertToSelf` is called first to drop the impersonation context. The token handle is closed and the slot is cleared.

The token store is a fixed-size array of `TokenEntry` structures, each containing the token handle, source PID, username string, and an active flag. The maximum capacity is 8 entries.

### APIs Used

| API | Purpose |
|-----|---------|
| ImpersonateLoggedOnUser | Apply a stored token for thread-level impersonation (use action) |
| RevertToSelf | Revert impersonation before removing the active token (remove action) |
| CloseHandle | Close token handles when removing entries or replacing active tokens |

## MITRE ATT&CK Mapping

- **T1134.001** - Access Token Manipulation: Token Impersonation/Theft
