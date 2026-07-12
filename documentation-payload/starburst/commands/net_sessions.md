+++
title = "net_sessions"
chapter = false
weight = 103
+++

## Summary

Enumerate active SMB sessions on a host.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| hostname | String | No | localhost | Target hostname to query |

### Usage

```
net_sessions
net_sessions -hostname FILESERVER01
```

## Detailed Summary

The `net_sessions` command enumerates active SMB sessions on a specified host, or localhost if no hostname is provided. The agent dynamically loads `netapi32.dll` via `LoadLibraryA` and resolves `NetSessionEnum` and `NetApiBufferFree` at runtime using `GetProcAddress`.

If a hostname argument is supplied, it is converted from a multibyte string to a wide string using `MultiByteToWideChar` for the API call. If no hostname is given, a null pointer is passed, which causes the API to query the local machine.

The command calls `NetSessionEnum` at information level 10, which returns `SESSION_INFO_10` structures containing:
- **Client Name** - the network name of the client that established the session
- **Username** - the name of the user who established the session
- **Session Time** - the number of seconds the session has been active
- **Idle Time** - the number of seconds the session has been idle

Each wide-character string field is converted to a multibyte string using `WideCharToMultiByte`. The time and idle time values are formatted as integer strings. Results are returned as a tab-delimited table with Client, User, Time, and IdleTime columns. The Net API buffer is properly freed with `NetApiBufferFree` after enumeration.

### APIs Used

| API | Purpose |
|-----|---------|
| LoadLibraryA | Dynamically load netapi32.dll |
| GetProcAddress | Resolve Net API functions |
| NetSessionEnum | Enumerate active SMB sessions at info level 10 |
| NetApiBufferFree | Free the buffer allocated by NetSessionEnum |
| MultiByteToWideChar | Convert hostname argument to wide string |
| WideCharToMultiByte | Convert wide client/user strings to ANSI |

## MITRE ATT&CK Mapping

- **T1049** - System Network Connections Discovery
