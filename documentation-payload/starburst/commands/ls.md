+++
title = "ls"
chapter = false
weight = 103
+++

## Summary

List files and directories at the specified path with metadata (name, size, type).

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

- **path** (String, optional) - Directory path to list. Default: current directory (`.`).

### Usage

```
ls C:\Users
```

```
ls
```

Lists the current working directory.

## Detailed Summary

Enumerates the target directory using `FindFirstFileW` / `FindNextFileW`. For each entry, returns the file name, size (via `GetFileSizeEx` for files), and whether it is a file or directory.

Results are returned as structured JSON for Mythic's file browser integration.

### APIs Used

| API | Purpose |
|-----|---------|
| `FindFirstFileW` | Begin directory enumeration |
| `FindNextFileW` | Continue enumeration |
| `FindClose` | Clean up search handle |

## MITRE ATT&CK Mapping

- **T1083** - File and Directory Discovery
- **T1106** - Native API
