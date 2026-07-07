+++
title = "netstat"
chapter = false
weight = 204
+++

## Summary

List active TCP connections on the local host.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

No arguments required.

### Usage

```
netstat
```

## Detailed Summary

The netstat command retrieves the TCP connection table using `GetTcpTable` from `iphlpapi.dll`. For each connection, it returns the protocol, local address and port, remote address and port, connection state, and owning process ID (PID).

Results are rendered in the Mythic UI using a browser script that displays the connections in a table with color-coded connection states (e.g., ESTABLISHED, LISTEN, TIME_WAIT).

### APIs Used

| API | Purpose |
|-----|---------|
| `GetTcpTable` | Retrieve the TCP connection table |

## MITRE ATT&CK Mapping

- **T1049** - System Network Connections Discovery
