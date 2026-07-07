+++
title = "socks"
chapter = false
weight = 311
+++

## Summary

Start or stop a SOCKS5 proxy through the agent, enabling the operator to tunnel network traffic through the compromised host.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `action` | ChooseOne | Yes | N/A | `start` or `stop` the SOCKS5 proxy. |
| `port` | Number | Yes | N/A | Port for the SOCKS5 proxy on the Mythic server side. |

### Usage

```
socks -action start -port 1080
```

```
socks -action stop -port 1080
```

**Example Output:**

```
[+] SOCKS5 proxy started on port 1080
[!] Agent sleep set to 0 for low-latency proxying
```

## Detailed Summary

Starts a SOCKS5 proxy that tunnels TCP connections from the Mythic server through the agent. When started, the agent registers with Mythic's SOCKS infrastructure and begins relaying connection requests. All proxied traffic flows through the agent's existing C2 channel.

The agent uses `ws2_32` socket functions to establish outbound connections to target hosts on behalf of the SOCKS client, and relays data bidirectionally between the client and the destination.

### OPSEC Warning

When SOCKS is active, the agent's **sleep interval is set to 0** to ensure low-latency proxying. This significantly changes the agent's network profile and may increase detection risk. The sleep interval is restored when SOCKS is stopped.

### APIs Used

| API | Purpose |
|-----|---------|
| `socket` (ws2_32) | Create outbound TCP connections to target hosts |
| `connect` (ws2_32) | Connect to SOCKS destination |
| `send` (ws2_32) | Send data to destination |
| `recv` (ws2_32) | Receive data from destination |
| `select` (ws2_32) | Non-blocking I/O for multiplexing connections |

## MITRE ATT&CK Mapping

- **T1090** - Proxy
