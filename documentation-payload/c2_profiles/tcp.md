+++
title = "TCP"
chapter = false
weight = 25
+++

## Summary

Peer-to-peer (P2P) communication profile using TCP sockets. TCP agents do not communicate directly with the Mythic server - they relay traffic through an egress agent (HTTP/HTTPX/GitHub) via the `connect` and `disconnect` commands.

## Configuration Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Port | Integer | 7000 | TCP port to bind and listen on |
| Callback Interval | Integer | 10 | Beacon interval in seconds (used internally) |
| Callback Jitter | Integer | 23 | Jitter percentage (0-100) |
| Kill Date | Date | - | Agent self-termination date |

## Architecture

```
[Mythic Server] <--HTTP--> [Egress Agent] <--TCP--> [P2P Agent]
```

The P2P agent creates a TCP socket, binds to the configured port, and listens for an incoming connection from an egress agent. Once connected, the egress agent relays messages between the P2P agent and the Mythic server as delegate messages.

## Wire Format

All messages over the TCP connection use a framed protocol:

```
[uint32 big-endian size] [base64(UUID + AES_CBC(TLV) + HMAC-SHA256)]
```

Length-prefixed framing ensures message boundaries are preserved over the stream-oriented TCP transport.

## TCP Configuration

- Transport: TCP stream socket
- Mode: Bind and listen on configured port
- Connections: Single active connection at a time
- The P2P agent listens; the egress agent initiates the connection

## Connect/Disconnect Commands

### Connecting

From the egress agent, use the `connect` command to establish a TCP connection to a P2P agent:

1. Egress agent connects to `<hostname>:<port>` via TCP
2. P2P agent's checkin data is read from the socket
3. Egress agent forwards the checkin to Mythic as a delegate message
4. Mythic registers the P2P agent as a new callback with an edge to the egress agent
5. Each beacon cycle, the egress agent polls connected TCP sockets and relays delegate messages

### Disconnecting

Use the `disconnect` command to tear down the TCP connection to a linked P2P agent. The socket is closed and the link edge is removed from the Mythic graph.

## Delegate Message Flow

Each egress agent beacon cycle:

1. **Uplink (P2P -> Mythic)**: Poll all connected TCP sockets for pending messages. Collected messages are included as `ACTION_LINK_MSG` delegates in the get_tasking request.
2. **Downlink (Mythic -> P2P)**: After receiving tasking, any delegate messages from Mythic are relayed down to the appropriate TCP connection by matching agent UUID.

## OPSEC Notes

- TCP connections are more generic than named pipes - less OS-specific telemetry is generated compared to SMB pipe activity
- Port listening is detectable via local port enumeration (e.g., `netstat`, EDR telemetry)
- Choose ports that blend with the environment - common service ports or ephemeral ranges depending on context
- TCP traffic between hosts may be flagged if the network baseline does not include direct host-to-host connections on the chosen port
- No Windows-specific logon events (unlike SMB pipe connections which generate Event ID 4624 type 3)
