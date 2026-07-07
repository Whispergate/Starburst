+++
title = "cat"
chapter = false
weight = 103
+++

## Summary

Read and display the contents of a file (up to 1MB).

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

- **path** (String, required) - Full path of the file to read.

### Usage

```
cat C:\Windows\win.ini
```

**Example Output:**

```
; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
```

## Detailed Summary

Opens the target file with `CreateFileW` (read-only access), reads up to 1MB of content via `ReadFile`, and returns the raw bytes as the response. Files larger than 1MB are truncated. For binary files, use `download` instead.

### APIs Used

| API | Purpose |
|-----|---------|
| `CreateFileW` | Open file for reading |
| `GetFileSizeEx` | Determine file size |
| `ReadFile` | Read file contents |
| `CloseHandle` | Close file handle |

## MITRE ATT&CK Mapping

- **T1005** - Data from Local System

## Limitations

- Maximum file size: 1MB. Larger files are truncated.
- Returns raw bytes - binary files will produce unreadable output. Use `download` for binary files.
