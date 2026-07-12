+++
title = "reg_create_key"
chapter = false
weight = 103
+++

## Summary

Create a new registry key.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| hive | ChooseOne (HKLM, HKCU, HKCR, HKU) | Yes | - | Registry hive |
| key | String | Yes | - | Registry subkey path to create |

### Usage

```
reg_create_key -hive HKLM -key SOFTWARE\NewKey
reg_create_key -hive HKCU -key SOFTWARE\MyApp\Settings
```

## Detailed Summary

The `reg_create_key` command creates a new registry key under the specified hive and subkey path.

The command works by:

1. Parsing the hive name and subkey path strings from the task parameters.
2. Mapping the hive string to the corresponding predefined registry handle (`HKEY_LOCAL_MACHINE`, `HKEY_CURRENT_USER`, `HKEY_CLASSES_ROOT`, or `HKEY_USERS`).
3. Calling `RegCreateKeyExA` with `REG_OPTION_NON_VOLATILE` and `KEY_ALL_ACCESS` to create the key. If the key already exists, the call succeeds and returns a handle to the existing key.
4. Closing the key handle via `RegCloseKey`.
5. Returning a success message with the full key path (e.g., `Created key: HKLM\SOFTWARE\NewKey`).

### APIs Used

| API | Purpose |
|-----|---------|
| RegCreateKeyExA | Create the registry key (or open if it already exists) |
| RegCloseKey | Close the registry key handle |

## MITRE ATT&CK Mapping

- **T1112** - Modify Registry
