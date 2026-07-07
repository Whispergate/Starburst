+++
title = "ifconfig"
chapter = false
weight = 203
+++

## Summary

List network adapter information for the local host.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

No arguments required.

### Usage

```
ifconfig
```

## Detailed Summary

The ifconfig command enumerates all network adapters on the local system using `GetAdaptersInfo` from `iphlpapi.dll`. For each adapter, it returns the adapter name, description, MAC address, IP address, subnet mask, default gateway, and DHCP status.

Results are rendered in the Mythic UI using a browser script that formats the adapter data into a structured table.

### APIs Used

| API | Purpose |
|-----|---------|
| `GetAdaptersInfo` | Retrieve network adapter configuration information |

## MITRE ATT&CK Mapping

- **T1016** - System Network Configuration Discovery
