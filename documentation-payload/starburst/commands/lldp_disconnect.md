+++
title = "lldp_disconnect"
chapter = false
weight = 311
+++

## Summary

Disconnect from a linked LLDP P2P agent. Tears down the Layer 2 link and removes the edge from the Mythic callback graph.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `agent_uuid` | String | Yes | N/A | The UUID of the linked P2P agent to disconnect |

### Usage

```
lldp_disconnect -agent_uuid 706f2005-ce4a-411c-904b-959453e6dd6a
```

**Example Output:**

```
LLDP link disconnected
```

## Detailed Summary

Removes the specified LLDP link from the egress agent's link list. Any in-progress reassembly state for that link is freed. An `ACTION_LINK_REMOVE` message is queued for the next beacon, which tells Mythic to remove the edge from the callback graph. The child agent will no longer be able to communicate through this egress agent.

## MITRE ATT&CK Mapping

- **T1095** - Non-Application Layer Protocol
