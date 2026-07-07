+++
title = "reg_write_value"
chapter = false
weight = 209
+++

## Summary

Write a value to the Windows registry.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

- **hive** (String, optional, default: "HKLM") - The registry hive (HKLM, HKCU, HKCR, HKU, HKCC).
- **key** (String, required) - The registry key path.
- **name** (String, required) - The value name to write.
- **value** (String, required) - The data to write.
- **type** (Number, optional, default: 1) - The registry value type (1 = REG_SZ, 2 = REG_EXPAND_SZ, 3 = REG_BINARY, 4 = REG_DWORD).

### Usage

```
reg_write_value -hive HKCU -key "Software\Microsoft\Windows\CurrentVersion\Run" -name "MyApp" -value "C:\app.exe"
```

## Detailed Summary

The reg_write_value command writes a value to the specified registry key. It uses `RegCreateKeyExA` with `KEY_SET_VALUE` access, which creates the key if it does not already exist (unlike `RegOpenKeyExA` which only opens existing keys). It then writes the value with `RegSetValueExA`. The value type is specified by the `type` argument and defaults to `REG_SZ` (string).

Writing to HKLM or other machine-wide hives typically requires administrator privileges.

### APIs Used

| API | Purpose |
|-----|---------|
| `RegCreateKeyExA` | Open or create the target registry key |
| `RegSetValueExA` | Write the value data to the key |
| `RegCloseKey` | Close the registry key handle |

## MITRE ATT&CK Mapping

- **T1112** - Modify Registry

## OPSEC Considerations

{{% notice warning %}}
Registry writes are logged by Sysmon Event ID 13 (RegistryEvent - Value Set). Writing to common persistence locations such as `Run` keys will generate high-fidelity alerts in most EDR products.
{{% /notice %}}
