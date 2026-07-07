+++
title = "pwd"
chapter = false
weight = 103
+++

## Summary

Print the agent's current working directory.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

No arguments required.

### Usage

```
pwd
```

**Example Output:**

```
C:\Users\jsmith\Desktop
```

## Detailed Summary

Calls `GetCurrentDirectoryW` and returns the full path as a UTF-8 string.

## MITRE ATT&CK Mapping

- **T1083** - File and Directory Discovery
