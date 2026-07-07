+++
title = "upload"
chapter = false
weight = 103
+++

## Summary

Upload a file from the Mythic server to the target host.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

- **file** (File, required) - File to upload (selected from Mythic's file browser or uploaded inline).
- **remote_path** (String, required) - Full destination path on the target, including filename.

### Usage

```
upload
```

A file dialog will appear in the Mythic UI to select the file and specify the remote path.

## Detailed Summary

Implements the Mythic multi-step upload protocol:

1. **Request** - The agent receives the `file_id` and destination path from the task parameters
2. **Chunk fetch** - The agent requests chunk 1 from Mythic, which responds with the chunk data and total chunk count
3. **Write** - Each chunk is written to disk via `CreateFileW` / `WriteFile`
4. **Continue** - The agent requests subsequent chunks until all are received
5. **Complete** - The file handle is closed

### APIs Used

| API | Purpose |
|-----|---------|
| `CreateFileW` | Create destination file |
| `WriteFile` | Write chunk data to file |
| `CloseHandle` | Close file handle |

## MITRE ATT&CK Mapping

- **T1105** - Ingress Tool Transfer
- **T1132** - Data Encoding
