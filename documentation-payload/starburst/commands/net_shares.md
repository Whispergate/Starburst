+++
title = "net_shares"
chapter = false
weight = 103
+++

## Summary

Enumerate SMB shares on a host.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| hostname | String | No | localhost | Target hostname to query |

### Usage

```
net_shares
net_shares -hostname DC01
```

## Detailed Summary

The `net_shares` command enumerates SMB shares on a specified host, or localhost if no hostname is provided. The agent dynamically loads `netapi32.dll` via `LoadLibraryA` and resolves `NetShareEnum` and `NetApiBufferFree` at runtime using `GetProcAddress`.

If a hostname argument is supplied, it is converted from a multibyte string to a wide string using `MultiByteToWideChar` for the API call. If no hostname is given, a null pointer is passed, which causes the API to query the local machine.

The command calls `NetShareEnum` at information level 1, which returns `SHARE_INFO_1` structures containing:
- **Share Name** - the name of the shared resource
- **Type** - the share type, classified as Disk (0), Print (1), Device (2), IPC (3), or Unknown. Administrative/hidden shares are identified by the `0x80000000` flag in the type field and are marked with a "(Special)" suffix.
- **Remark** - an optional comment or description associated with the share

Each wide-character string field is converted to a multibyte string using `WideCharToMultiByte`. Results are returned as a tab-delimited table with Name, Type, and Remark columns. The Net API buffer is properly freed with `NetApiBufferFree` after enumeration.

### APIs Used

| API | Purpose |
|-----|---------|
| LoadLibraryA | Dynamically load netapi32.dll |
| GetProcAddress | Resolve Net API functions |
| NetShareEnum | Enumerate SMB shares at info level 1 |
| NetApiBufferFree | Free the buffer allocated by NetShareEnum |
| MultiByteToWideChar | Convert hostname argument to wide string |
| WideCharToMultiByte | Convert wide share name/remark strings to ANSI |

## MITRE ATT&CK Mapping

- **T1135** - Network Share Discovery
