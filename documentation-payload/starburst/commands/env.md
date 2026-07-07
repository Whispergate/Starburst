+++
title = "env"
chapter = false
weight = 103
+++

## Summary

List all environment variables for the current process.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

No arguments required.

### Usage

```
env
```

**Example Output:**

```
COMPUTERNAME=WORKSTATION01
USERNAME=jsmith
USERDOMAIN=CORP
PATH=C:\Windows\system32;C:\Windows;...
```

## Detailed Summary

Retrieves the environment block using `GetEnvironmentStringsW` and parses the null-delimited wide string array into individual `KEY=VALUE` pairs. The block is freed with `FreeEnvironmentStringsW` after processing.

## MITRE ATT&CK Mapping

- **T1082** - System Information Discovery
