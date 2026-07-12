+++
title = "net_loggedon"
chapter = false
weight = 103
+++

## Summary

Enumerate users logged on to a host.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| hostname | String | No | localhost | Target hostname to query |

### Usage

```
net_loggedon
net_loggedon -hostname DC01
```

## Detailed Summary

The `net_loggedon` command enumerates users currently logged on to a specified host, or localhost if no hostname is provided. The agent dynamically loads `netapi32.dll` via `LoadLibraryA` and resolves `NetWkstaUserEnum` and `NetApiBufferFree` at runtime using `GetProcAddress`.

If a hostname argument is supplied, it is converted from a multibyte string to a wide string using `MultiByteToWideChar` for the API call. If no hostname is given, a null pointer is passed, which causes the API to query the local machine.

The command calls `NetWkstaUserEnum` at information level 1, which returns `WKSTA_USER_INFO_1` structures containing:
- **Username** - the name of the logged-on user
- **Logon Domain** - the domain the user authenticated against
- **Logon Server** - the server that validated the logon

Each wide-character field is converted to a multibyte string using `WideCharToMultiByte`. Results are returned as a tab-delimited table with User, Domain, and LogonServer columns. The Net API buffer is properly freed with `NetApiBufferFree` after enumeration.

### APIs Used

| API | Purpose |
|-----|---------|
| LoadLibraryA | Dynamically load netapi32.dll |
| GetProcAddress | Resolve Net API functions |
| NetWkstaUserEnum | Enumerate logged-on users at info level 1 |
| NetApiBufferFree | Free the buffer allocated by NetWkstaUserEnum |
| MultiByteToWideChar | Convert hostname argument to wide string |
| WideCharToMultiByte | Convert wide user/domain/server strings to ANSI |

## MITRE ATT&CK Mapping

- **T1033** - System Owner/User Discovery
