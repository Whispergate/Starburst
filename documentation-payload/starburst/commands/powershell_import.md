+++
title = "powershell_import"
chapter = false
weight = 103
+++

## Summary

Import a PowerShell script into memory for use with subsequent `powerpick` commands. Functions and variables defined in the imported script become available to all future `powerpick` invocations. Importing a new script replaces any previously imported script.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| file | File | Yes | - | PowerShell .ps1 script to load into memory for use with powerpick |

### Usage

```
powershell_import <script.ps1>
```

Upload a PowerShell module such as PowerView, then use its functions via `powerpick`:

```
powershell_import PowerView.ps1
powerpick -Script "Get-DomainUser -Identity admin"
```

Import a custom recon script:

```
powershell_import recon.ps1
powerpick -Script "Invoke-CustomScan -Target 10.0.0.0/24"
```

Replace the currently imported script with a different one:

```
powershell_import SharpHound.ps1
```

## Detailed Summary

The `powershell_import` command is a **server-side only** command that stores a PowerShell script in the Mythic file system for later use by `powerpick`. No data is sent to the agent; the command completes entirely within the Mythic server.

When executed, the command:

1. Retrieves the uploaded `.ps1` file content from the Mythic file store.
2. Validates the file is non-empty and decodes it as UTF-8 (with BOM handling).
3. Deletes any previously stored `psimport_active.ps1` files from the Mythic file system.
4. Registers the new script under the filename `psimport_active.ps1` in the Mythic file system.

When a subsequent `powerpick` command is issued, the `powerpick` server-side handler searches for `psimport_active.ps1`, reads its contents, and prepends it to the user's script before sending the combined script to the agent. This means the imported script's functions and variables are defined in the same PowerShell runspace before the user's command runs.

### Relationship with powerpick

The import mechanism is entirely transparent to the agent. From the agent's perspective, it receives a single PowerShell script that happens to contain function definitions followed by the user's command. The agent does not need to be aware of the import system.

Only one script can be imported at a time. Importing a new script replaces the previous one. To import multiple modules, combine them into a single `.ps1` file before importing.

## MITRE ATT&CK Mapping

- **T1059.001** - Command and Scripting Interpreter: PowerShell

## OPSEC Considerations

{{% notice info %}}
This command has no OPSEC impact on its own since it executes entirely server-side. No network traffic is generated and no agent interaction occurs. The OPSEC considerations of the imported script apply when it is subsequently executed via `powerpick`.
{{% /notice %}}

- The imported script is stored in the Mythic file system, not on the target host
- Larger imported scripts increase the size of subsequent `powerpick` task payloads sent to the agent
- The combined script (import + command) is subject to the same CLR hosting and AMSI considerations as a regular `powerpick` command
