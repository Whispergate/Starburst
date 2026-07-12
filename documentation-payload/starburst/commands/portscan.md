+++
title = "portscan"
chapter = false
weight = 103
+++

## Summary

TCP connect port scanner for network reconnaissance.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| hosts | String | Yes | - | Comma-separated target hosts/IPs (e.g. 10.0.0.1,10.0.0.2) |
| ports | String | Yes | - | Comma-separated ports (e.g. 22,80,443,3389,8080) |
| timeout | Number | No | 1000 | Connection timeout in milliseconds |

### Usage

```
portscan -hosts 10.0.0.1,10.0.0.2 -ports 22,80,443,3389,8080
portscan -hosts 192.168.1.1 -ports 21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,5432,5900,8080 -timeout 500
```

## Detailed Summary

The `portscan` command performs TCP connect scanning against one or more hosts and ports. It uses non-blocking sockets with `select()` to implement configurable connection timeouts.

The command works by:

1. Parsing the comma-separated hosts string (up to 32 hosts) and ports string (up to 64 ports) from the task parameters.
2. Loading `ws2_32.dll` dynamically and resolving all required Winsock function pointers.
3. Initializing Winsock via `WSAStartup`.
4. For each host/port combination:
   - Creating a TCP socket (`SOCK_STREAM`, `IPPROTO_TCP`).
   - Setting the socket to non-blocking mode via `ioctlsocket` with `FIONBIO`.
   - Initiating a `connect()` call (which returns immediately in non-blocking mode).
   - Using `select()` with the configured timeout to wait for the connection result.
   - Checking if the socket appears in the write set (connection succeeded) and not in the exception set (connection failed).
   - Closing the socket.
5. Building a tab-separated results table with Host, Port, and Status columns for all open ports.
6. Cleaning up Winsock via `WSACleanup`.

Only open ports are reported in the output. If no open ports are found, a message indicating this is returned.

### APIs Used

| API | Purpose |
|-----|---------|
| LoadLibraryA | Load ws2_32.dll for Winsock functions |
| GetProcAddress | Resolve Winsock function pointers |
| WSAStartup | Initialize Winsock |
| socket | Create TCP sockets |
| ioctlsocket | Set sockets to non-blocking mode |
| connect | Initiate TCP connections |
| select | Wait for connection results with timeout |
| inet_addr | Convert IP address strings to network byte order |
| htons | Convert port numbers to network byte order |
| closesocket | Close sockets after each probe |
| WSACleanup | Clean up Winsock |

## MITRE ATT&CK Mapping

- **T1046** - Network Service Discovery

## OPSEC Considerations

{{% notice warning %}}
This command performs active TCP connect scanning, which generates network traffic that can be detected by network monitoring solutions, IDS/IPS, and firewall logs. Each port probe establishes (or attempts) a full TCP connection. Scanning many hosts or ports in rapid succession will increase the likelihood of detection. Consider using smaller port lists and longer timeouts to reduce the scan footprint.
{{% /notice %}}
