+++
title = "listpipes"
chapter = false
weight = 205
+++

## Summary

Enumerate named pipes on the local system.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

No arguments required.

### Usage

```
listpipes
```

## Detailed Summary

The listpipes command enumerates all named pipes on the local system by performing a directory listing of `\\.\pipe\*` using `FindFirstFileA` and `FindNextFileA`. Each discovered pipe name is returned in the output.

Results are rendered in the Mythic UI using a browser script that highlights known C2 and implant pipe name patterns (e.g., Cobalt Strike, Meterpreter, default pipe names) for quick identification during operations.

### APIs Used

| API | Purpose |
|-----|---------|
| `FindFirstFileA` | Begin enumerating named pipes |
| `FindNextFileA` | Continue enumerating named pipes |
| `FindClose` | Close the search handle |

## MITRE ATT&CK Mapping

- **T1057** - Process Discovery
