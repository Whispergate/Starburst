+++
title = "persist_run"
chapter = false
weight = 103
+++

## Summary

Install or remove a Windows Registry Run key for persistence.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| action | ChooseOne (install, remove) | Yes | install | Install or remove the run key |
| name | String | Yes | - | Registry value name for the run key entry |
| command | String | No | - | Command/path to execute on logon (required for install) |
| hkcu | Boolean | Yes | True | Use HKCU (True) or HKLM (False) |

### Usage

```
persist_run -action install -name "WindowsUpdate" -command "C:\Users\Public\payload.exe" -hkcu true
persist_run -action install -name "SvcHost" -command "C:\Windows\Temp\svc.exe" -hkcu false
persist_run -action remove -name "WindowsUpdate" -hkcu true
```

## Detailed Summary

The `persist_run` command manages persistence through the Windows Registry `Run` key located at `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`. It supports two actions:

**Install:**
1. Opens the Run key under either `HKEY_CURRENT_USER` or `HKEY_LOCAL_MACHINE` (based on the `hkcu` parameter) with `KEY_SET_VALUE` access.
2. Writes the specified command as a `REG_SZ` value using `RegSetValueExA` with the provided value name.
3. The command will execute automatically at user logon (HKCU) or system startup (HKLM).

**Remove:**
1. Opens the Run key with `KEY_SET_VALUE` access.
2. Resolves `RegDeleteValueA` dynamically via `GetProcAddress` from advapi32.dll.
3. Deletes the named registry value.

Using `HKCU` does not require administrator privileges. Using `HKLM` requires elevated privileges.

### APIs Used

| API | Purpose |
|-----|---------|
| RegOpenKeyExA | Open the Run registry key |
| RegSetValueExA | Write the persistence value (install) |
| RegDeleteValueA | Remove the persistence value (remove) |
| RegCloseKey | Close the registry key handle |
| GetProcAddress | Dynamically resolve RegDeleteValueA |

## MITRE ATT&CK Mapping

- **T1547.001** - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder

## OPSEC Considerations

{{% notice warning %}}
Registry Run keys are one of the most well-known persistence mechanisms and are heavily monitored. Sysmon Event ID 13 (RegistryEvent - Value Set) will log writes to Run keys. Most EDR products generate high-fidelity alerts on modifications to `CurrentVersion\Run`. Writing to HKLM requires administrator privileges and is more conspicuous than HKCU. The value data (command path) is stored in plaintext and is trivially enumerable via `reg query` or autoruns.
{{% /notice %}}
