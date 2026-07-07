+++
title = "mkdir"
chapter = false
weight = 103
+++

## Summary

Create a new directory.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

- **path** (String, required) - Full path of the directory to create.

### Usage

```
mkdir C:\Users\Public\staging
```

## Detailed Summary

Creates a directory using `CreateDirectoryW`. Returns success or error message. Does not create intermediate directories - all parent directories must already exist.

## MITRE ATT&CK Mapping

- **T1106** - Native API
