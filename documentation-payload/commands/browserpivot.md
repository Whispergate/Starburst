+++
title = "browserpivot"
chapter = false
weight = 308
+++

## Summary

Start or stop a local HTTP proxy that uses WinINet to inherit the user's authenticated browser session. This allows the operator to browse web applications using the target user's cookies, Kerberos tickets, and NTLM credentials.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `action` | ChooseOne | Yes | N/A | `start` or `stop` the browser pivot proxy. |
| `pid` | Number | No | `0` | Browser process PID to target. Use `0` for the local user session. |
| `port` | Number | No | `8080` | Local port to listen on for the proxy. |

### Usage

```
browserpivot -action start -port 9090
```

```
browserpivot -action start -pid 5284 -port 8080
```

```
browserpivot -action stop
```

**Example Output:**

```
[+] Browser pivot proxy started on 127.0.0.1:9090
[*] Using local session WinINet credentials
[*] Configure your browser to use SOCKS proxy 127.0.0.1:9090
```

## Detailed Summary

When started, the command opens a TCP listening socket on the specified port using WinSock. Incoming HTTP requests from the operator are received, then re-issued through WinINet (`InternetOpenA`, `InternetOpenUrlA`, `InternetReadFile`) which automatically attaches the target user's session cookies, Kerberos tickets, and NTLM credentials. Responses are relayed back to the operator.

This effectively allows the operator to browse internal web applications as the target user without needing to extract credentials or tokens.

### OPSEC Warning

This command **opens a local listening port** on the target host, which may be detected by host-based firewalls or network monitoring. Choose a port that blends with expected local traffic.

### APIs Used

| API | Purpose |
|-----|---------|
| `InternetOpenA` | Initialize WinINet session |
| `InternetOpenUrlA` | Open URL using target user's session credentials |
| `InternetReadFile` | Read HTTP response data |
| `socket` | Create TCP listening socket |
| `bind` | Bind to local port |
| `listen` | Start listening for connections |
| `accept` | Accept incoming proxy connections |
| `send` | Send response data to operator |
| `recv` | Receive request data from operator |

## MITRE ATT&CK Mapping

- **T1557.001** - Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay
