+++
title = "unlink_webshell"
chapter = false
weight = 203
+++

## Summary

Disconnect from a linked Ariadne webshell.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

- **link_info** (LinkInfo, required) - The callback info identifying the linked webshell to disconnect from.

### Usage

```
unlink_webshell
```

Use the UI to select the linked webshell callback to disconnect.

## Detailed Summary

The unlink_webshell command disconnects from a previously linked Ariadne webshell. It locates the webshell link by matching the agent UUID provided in the LinkInfo parameter, removes it from the internal linked list, and frees all associated resources (URL, auth credentials, AES key). After unlinking, the webshell will no longer receive tasking through this callback and no further polling will occur.

### Disconnection Flow

1. The agent receives the target agent UUID from the task parameters
2. It walks the webshell link list to find the matching entry
3. An `ACTION_LINK_REMOVE` message is queued, notifying Mythic to remove the P2P graph edge
4. All heap-allocated resources for the link are freed (URL, agent_id, auth_name, auth_value, aes_key, param_name)
5. The link node is removed from the linked list
6. On the Mythic side, `process_response` sends a "remove" edge message via RPC and removes the graph edge via GraphQL

### APIs Used

No additional Windows APIs are called. The command operates entirely on internal agent data structures.

## MITRE ATT&CK Mapping

None.

### Example Output

```
webshell unlinked
```

On failure (agent UUID not found in link list):

```
agent not found in webshell links
```

## OPSEC Considerations

- The unlink operation is silent from a network perspective — no HTTP requests are made to the webshell during disconnection
- The webshell itself is not notified of the disconnect; it continues running and will respond to future link attempts
- Memory for auth credentials and AES keys is freed but not zeroed; sensitive material may persist in the process heap until overwritten
