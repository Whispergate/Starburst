+++
title = "cd"
chapter = false
weight = 103
+++

## Summary

Change the agent's current working directory.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

- **path** (String, required) - Directory path to change to.

### Usage

```
cd C:\Users\Public
```

```
cd ..
```

## Detailed Summary

Calls `SetCurrentDirectoryW` with the provided path. Returns the new working directory on success.

## MITRE ATT&CK Mapping

None.
