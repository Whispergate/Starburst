+++
title = "connect"
chapter = false
weight = 309
+++

## Summary

Connect to a peer-to-peer (P2P) agent over a TCP socket. Similar to `link` but uses TCP instead of SMB named pipes.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `connection_info` | ConnectionInfo | Yes | N/A | Host and port details sourced from the C2 profile configuration. Uses the `callback_table:connect` UI feature. |

### Usage

Use the Mythic UI `callback_table:connect` button to initiate a TCP connection to a P2P agent.

```
connect -connection_info {"host": "10.10.5.20", "c2_profile": {"name": "tcp", "parameters": {"port": "7443"}}}
```

**Example Output:**

```
Connected to 10.10.5.20:7443
Agent: abc12345-6789-0abc-def0-123456789abc
```

## Detailed Summary

Establishes a TCP socket connection to a remote P2P agent using the `ws2_32` socket API. The command creates a socket, connects to the specified host and port, reads the P2P agent's initial checkin, and establishes a delegate relay. Data is exchanged using length-prefixed framing over blocking `send` and `recv` calls, with the beacon loop polling linked TCP peers each cycle.

Once connected, the child agent's traffic is routed through the parent agent's C2 channel back to the Mythic server, enabling communication with agents that do not have direct egress.

### APIs Used

| API | Purpose |
|-----|---------|
| `socket` (ws2_32) | Create TCP socket |
| `connect` (ws2_32) | Connect to remote P2P agent |
| `send` (ws2_32) | Send data to linked agent |
| `recv` (ws2_32) | Receive data from linked agent |
| `htons` (ws2_32) | Port byte-order conversion |
| `inet_addr` (ws2_32) | Address string to binary |

## MITRE ATT&CK Mapping

- **T1570** - Lateral Tool Transfer
- **T1572** - Protocol Tunneling
