+++
title = "cp"
chapter = false
weight = 103
+++

## Summary

Copy a file to a new location.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

- **source** (String, required) - Source file path.
- **destination** (String, required) - Destination file path.

### Usage

```
cp C:\Users\Public\data.db C:\Users\Public\data.db.bak
```

## Detailed Summary

Copies a file using `CopyFileW`. The destination file is overwritten if it already exists.

## MITRE ATT&CK Mapping

- **T1106** - Native API
