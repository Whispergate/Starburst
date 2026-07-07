+++
title = "reg_query"
chapter = false
weight = 103
+++

## Summary

Query a Windows registry key, listing its values and subkeys.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

- **hive** (ChooseOne, required) - Registry hive. Choices: `HKLM`, `HKCU`, `HKCR`, `HKU`.
- **key** (String, required) - Registry subkey path (e.g., `SOFTWARE\Microsoft\Windows NT\CurrentVersion`).

### Usage

```
reg_query -hive HKLM -key SOFTWARE\Microsoft\Windows NT\CurrentVersion
```

**Example Output:**

```
Subkeys:
  Accessibility
  AppCompatFlags
  ...
Values:
  ProductName: Windows 10 Pro
  CurrentBuild: 19045
  ...
```

## Detailed Summary

Opens the specified registry key using `RegOpenKeyExA`, then enumerates subkeys with `RegEnumKeyExA` and reads values with `RegQueryValueExA`. The key is closed with `RegCloseKey` after enumeration.

Only queries values directly under the specified key - does not recurse into subkeys.

### APIs Used

| API | Purpose |
|-----|---------|
| `RegOpenKeyExA` | Open registry key |
| `RegQueryValueExA` | Read value data |
| `RegEnumKeyExA` | Enumerate subkeys |
| `RegCloseKey` | Close registry handle |

## MITRE ATT&CK Mapping

- **T1012** - Query Registry
