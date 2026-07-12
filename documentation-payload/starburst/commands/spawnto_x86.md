+++
title = "spawnto_x86"
chapter = false
weight = 103
+++

## Summary

Change the default x86 binary used as the sacrifice process for post-exploitation jobs.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| application | String | Yes | C:\Windows\SysWOW64\rundll32.exe | Path to the x86 application to use as spawnto |
| arguments | String | No | "" | Arguments to pass to the spawnto application |

### Usage

```
spawnto_x86 C:\Windows\SysWOW64\RuntimeBroker.exe
spawnto_x86 C:\Windows\SysWOW64\svchost.exe -k netsvcs
spawnto_x86 -Application C:\Windows\SysWOW64\dllhost.exe -Arguments /Processid:{GUID}
```

## Detailed Summary

The `spawnto_x86` command updates the agent's internal configuration for which x86 (WoW64) binary is spawned as a sacrifice process during post-exploitation jobs that target 32-bit contexts.

The command works by:

1. Parsing the application path string from the task parameters.
2. Copying the application path into the agent instance's `spawnto.x86` field (up to 259 characters).
3. Parsing the optional arguments string.
4. If arguments are provided, copying them into `spawnto.x86_args` (up to 259 characters). Otherwise, clearing the arguments field.
5. Returning a success message confirming the new spawnto path and arguments.

The change takes effect immediately and persists for the lifetime of the agent session. It does not modify any files on disk.

### APIs Used

No external Windows APIs are called. This command only modifies internal agent state by copying strings into the instance configuration structure.

## MITRE ATT&CK Mapping

- **T1055** - Process Injection
