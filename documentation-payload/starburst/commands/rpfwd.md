+++
title = "rpfwd"
chapter = false
weight = 313
+++

## Summary

Start or stop a reverse port forward. Opens a listening port on the agent's host and tunnels incoming connections back through the Mythic C2 channel to a specified destination.

- **Needs Admin:** False (True if binding to a privileged port)
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `action` | ChooseOne | Yes | `start` | `start` or `stop` the reverse port forward. |
| `port` | Number | Yes | `8080` | Port for Mythic to listen on (operator-side). |
| `remote_ip` | String | Yes | `127.0.0.1` | Target IP the agent connects to for each forwarded connection. |
| `remote_port` | Number | Yes | `80` | Target port the agent connects to for each forwarded connection. |

### Usage

```
rpfwd -action start -port 8443 -remote_ip 127.0.0.1 -remote_port 443
```

```
rpfwd -action stop -port 8443
```

**Example Output:**

```
[+] Reverse port forward started
    Listening on 0.0.0.0:8443 (agent host)
    Forwarding to 127.0.0.1:443 (Mythic side)
```

## Detailed Summary

When started, the agent opens a TCP listening socket on the specified port using `ws2_32` socket functions. When a connection is accepted on the listening port, the connection data is tunneled through the agent's C2 channel back to the Mythic server, which then forwards it to the specified `remote_ip:remote_port` destination.

This enables access to services that are only reachable from the Mythic server's network by routing traffic through the compromised host. For example, an internal web application on the target network can be made accessible to the operator by forwarding its port through the agent.

When stopped, the listening socket is closed and no further connections are accepted.

### APIs Used

| API | Purpose |
|-----|---------|
| `socket` (ws2_32) | Create TCP listening socket |
| `bind` (ws2_32) | Bind socket to local port |
| `listen` (ws2_32) | Start listening for incoming connections |
| `accept` (ws2_32) | Accept incoming connections |

## MITRE ATT&CK Mapping

- **T1090** - Proxy
