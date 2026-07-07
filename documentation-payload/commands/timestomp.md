+++
title = "timestomp"
chapter = false
weight = 304
+++

## Summary

Copy file timestamps (creation, last access, last write) from a source file to a target file. Used to blend a dropped file with legitimate system files.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `path` | String | Yes | N/A | Path to the target file whose timestamps will be modified. |
| `source` | String | No | `C:\Windows\System32\notepad.exe` | Path to the reference file whose timestamps will be copied. |

### Usage

```
timestomp -path "C:\Users\jsmith\AppData\Local\Temp\payload.exe"
```

```
timestomp -path "C:\malware.dll" -source "C:\Windows\System32\kernel32.dll"
```

**Example Output:**

```
[*] Source timestamps (C:\Windows\System32\notepad.exe):
    Created:      2023-09-07 09:41:23
    Last Access:  2023-09-07 09:41:23
    Last Write:   2023-09-07 09:41:23
[+] Timestamps applied to C:\Users\jsmith\AppData\Local\Temp\payload.exe
```

## Detailed Summary

Opens the source file with `CreateFileA` to read its creation, last access, and last write timestamps via `GetFileTime`. Then opens the target file and applies all three timestamps using `SetFileTime`. This makes the target file appear to have the same age as the source file, helping it blend in with legitimate system binaries during forensic analysis.

### APIs Used

| API | Purpose |
|-----|---------|
| `CreateFileA` | Open file handles for source and target files |
| `GetFileTime` | Read timestamps from the source file |
| `SetFileTime` | Apply timestamps to the target file |

## MITRE ATT&CK Mapping

- **T1070.006** - Indicator Removal: Timestomp
