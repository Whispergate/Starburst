+++
title = "disconnect"
chapter = false
weight = 310
+++

## Summary

Disconnect from a TCP-linked peer-to-peer (P2P) agent.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `link_info` | LinkInfo | Yes | N/A | The callback UUID of the linked agent to disconnect. Uses the `callback_table:disconnect` UI feature. |

### Usage

Use the Mythic UI `callback_table:disconnect` button to disconnect from a linked P2P agent.

```
disconnect -link_info {"callback_uuid": "abc12345-6789-0abc-def0-123456789abc"}
```

**Example Output:**

```
[*] Disconnecting from callback abc12345-6789-0abc-def0-123456789abc
[+] TCP connection closed
```

## Detailed Summary

Closes the TCP socket connection to a previously linked P2P agent using `closesocket`. The linked agent will no longer have its traffic routed through this agent. The child callback in Mythic will show as disconnected until a new connection is established.

### APIs Used

| API | Purpose |
|-----|---------|
| `closesocket` (ws2_32) | Close the TCP socket to the linked agent |

## MITRE ATT&CK Mapping

- **T1570** - Lateral Tool Transfer
