+++
title = "rm"
chapter = false
weight = 103
+++

## Summary

Remove a file or empty directory.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

- **path** (String, required) - Path to the file or directory to remove.

### Usage

```
rm C:\Users\Public\staging\payload.exe
```

```
rm C:\Users\Public\staging
```

Removes an empty directory.

## Detailed Summary

Checks whether the target is a file or directory using `GetFileAttributesW`. Files are deleted with `DeleteFileW`, directories with `RemoveDirectoryW`. Directories must be empty - `RemoveDirectoryW` does not perform recursive deletion.

## MITRE ATT&CK Mapping

- **T1070.004** - Indicator Removal: File Deletion

## OPSEC Considerations

- File deletion events may be logged by Sysmon (Event ID 23/26) or EDR file monitoring
