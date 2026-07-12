+++
title = "reg_delete"
chapter = false
weight = 103
+++

## Summary

Delete a registry key or value.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| hive | ChooseOne (HKLM, HKCU, HKCR, HKU) | Yes | - | Registry hive |
| key | String | Yes | - | Registry subkey path |
| value_name | String | No | "" | Value name to delete (leave empty to delete the key itself) |

### Usage

```
reg_delete -hive HKLM -key SOFTWARE\Test
reg_delete -hive HKCU -key SOFTWARE\MyApp -value_name MyValue
```

## Detailed Summary

The `reg_delete` command deletes either a registry value or an entire registry key, depending on whether the `value_name` argument is provided.

**Deleting a value (value_name provided):**

1. Parses the hive, key path, and value name from the task parameters.
2. Maps the hive string to the corresponding predefined handle.
3. Opens the key via `RegOpenKeyExA` with `KEY_SET_VALUE` access.
4. Resolves `RegDeleteValueA` dynamically via `GetProcAddress` from advapi32.
5. Calls `RegDeleteValueA` to remove the specified value.
6. Closes the key handle.

**Deleting a key (no value_name):**

1. Parses the hive and key path from the task parameters.
2. Maps the hive string to the corresponding predefined handle.
3. Resolves `RegDeleteKeyA` dynamically via `GetProcAddress` from advapi32.
4. Calls `RegDeleteKeyA` to delete the key. Note: the key must have no subkeys for this to succeed.

### APIs Used

| API | Purpose |
|-----|---------|
| RegOpenKeyExA | Open the registry key for value deletion |
| RegDeleteValueA | Delete a specific registry value |
| RegDeleteKeyA | Delete a registry key |
| RegCloseKey | Close the registry key handle |
| GetProcAddress | Dynamically resolve RegDeleteValueA and RegDeleteKeyA |

## MITRE ATT&CK Mapping

- **T1112** - Modify Registry
