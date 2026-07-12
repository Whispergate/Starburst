+++
title = "arp"
chapter = false
weight = 103
+++

## Summary

Enumerate the ARP table to discover hosts on the local network.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

No arguments required.

### Usage

```
arp
```

## Detailed Summary

The `arp` command enumerates the system's ARP (Address Resolution Protocol) table to reveal IP-to-MAC address mappings of hosts that have been communicated with on the local network.

Internally, the agent dynamically loads `iphlpapi.dll` and resolves `GetIpNetTable` at runtime via `LoadLibraryA` and `GetProcAddress`. It first calls `GetIpNetTable` with a null buffer to determine the required buffer size, allocates heap memory for the table, then retrieves the full ARP table sorted by IP address.

For each entry in the table, the command extracts and formats:
- **IP Address** - converted from a DWORD to dotted-decimal notation
- **MAC Address** - formatted as colon-separated hex bytes (XX:XX:XX:XX:XX:XX)
- **Type** - classified as Other, Invalid, Dynamic, Static, or Unknown based on the `dwType` field
- **Interface** - the network interface index associated with the entry

Results are returned as a tab-delimited table with a header row.

### APIs Used

| API | Purpose |
|-----|---------|
| LoadLibraryA | Dynamically load iphlpapi.dll |
| GetProcAddress | Resolve GetIpNetTable function |
| GetIpNetTable | Retrieve the ARP table entries |

## MITRE ATT&CK Mapping

- **T1018** - Remote System Discovery
