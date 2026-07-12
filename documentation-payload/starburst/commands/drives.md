+++
title = "drives"
chapter = false
weight = 103
+++

## Summary

Enumerate logical drives and their types.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

No arguments required.

### Usage

```
drives
```

## Detailed Summary

The `drives` command enumerates all logical drives present on the system and identifies their types (e.g., fixed disk, removable, network, CD-ROM).

The agent resolves `GetLogicalDriveStringsW` and `GetDriveTypeW` from `kernel32.dll` via `GetProcAddress`. It calls `GetLogicalDriveStringsW` to retrieve a double-null-terminated list of drive root paths (e.g., `C:\`, `D:\`), then iterates through each drive string and queries its type with `GetDriveTypeW`.

Drive types are classified as:
- **Removable** (type 2) - USB drives, floppy disks
- **Fixed** (type 3) - Local hard drives, SSDs
- **Remote** (type 4) - Network/mapped drives
- **CDROM** (type 5) - CD/DVD drives
- **RAMDisk** (type 6) - RAM disks
- **Unknown** (default) - Unrecognized drive type

Each drive letter is converted from wide to narrow characters using `WideCharToMultiByte`. Results are returned as a tab-delimited table with Drive and Type columns.

### APIs Used

| API | Purpose |
|-----|---------|
| GetProcAddress | Resolve drive enumeration functions |
| GetLogicalDriveStringsW | Retrieve list of all logical drive root paths |
| GetDriveTypeW | Determine the type of each drive |
| WideCharToMultiByte | Convert wide drive strings to ANSI |

## MITRE ATT&CK Mapping

- **T1082** - System Information Discovery
