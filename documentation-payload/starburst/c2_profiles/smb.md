+++
title = "SMB"
chapter = false
weight = 20
+++

## Summary

Peer-to-peer (P2P) communication profile using Windows named pipes. SMB agents do not communicate directly with the Mythic server - they relay traffic through an egress agent (HTTP/HTTPX/GitHub) via the `link` and `unlink` commands.

## Configuration Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Pipe Name | String | starburst | Named pipe name (without `\\.\pipe\` prefix) |
| Callback Interval | Integer | 10 | Beacon interval in seconds (used internally) |
| Callback Jitter | Integer | 23 | Jitter percentage (0-100) |
| Kill Date | Date | - | Agent self-termination date |

## Architecture

```
[Mythic Server] <--HTTP--> [Egress Agent] <--SMB Pipe--> [P2P Agent]
```

The P2P agent creates a named pipe (`\\.\pipe\<pipename>`) with an Everyone DACL and waits for an egress agent to connect. Once linked, the egress agent relays messages between the P2P agent and the Mythic server as delegate messages.

## Wire Format

All messages over the pipe use a framed protocol:

```
[uint32 big-endian size] [base64(UUID + AES_CBC(TLV) + HMAC-SHA256)]
```

## Pipe Configuration

- Access: `PIPE_ACCESS_DUPLEX`
- Mode: `PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT`
- Instances: `PIPE_UNLIMITED_INSTANCES`
- Buffer: 64KB per direction
- Security: Everyone DACL (required for cross-session access)

## Link/Unlink Commands

### Linking

From the egress agent, use the `link` command to connect to a P2P agent:

1. Egress agent connects to `\\<hostname>\pipe\<pipename>` via `CreateFileA`
2. P2P agent's checkin data is read from the pipe
3. Egress agent forwards the checkin to Mythic as a delegate message
4. Mythic registers the P2P agent as a new callback with an edge to the egress agent
5. Each beacon cycle, the egress agent polls linked pipes and relays delegate messages

### Unlinking

Use the `unlink` command to disconnect from a linked P2P agent. The pipe handle is closed and the link edge is removed from the Mythic graph.

## Delegate Message Flow

Each egress agent beacon cycle:

1. **Uplink (P2P -> Mythic)**: Poll all linked pipes for pending messages. Collected messages are included as `ACTION_LINK_MSG` delegates in the get_tasking request.
2. **Downlink (Mythic -> P2P)**: After receiving tasking, any delegate messages from Mythic are relayed down to the appropriate linked pipe by matching agent UUID.

Maximum 30 delegate messages polled per linked agent per beacon cycle (`MAX_SMB_PKTS_PER_LOOP`).

## OPSEC Notes

- Named pipes are enumerable via `\\.\pipe\*` - choose pipe names that blend with the environment
- Pipe connections generate network logon events (Event ID 4624 type 3) when connecting to remote hosts
- SMB traffic is typically allowed within corporate networks - leverages existing infrastructure
- The Everyone DACL allows any user to connect to the pipe, which is necessary for cross-user operation but increases the pipe's attack surface
- Consider pipe names that mimic legitimate applications (e.g., browser IPC patterns, RPC endpoints)
