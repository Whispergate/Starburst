+++
title = "hashdump"
chapter = false
weight = 103
+++

## Summary

Dump SAM database hashes from the registry by saving the SAM and SYSTEM hives to temporary files.

- **Needs Admin:** True
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

No arguments required.

### Usage

```
hashdump
```

## Detailed Summary

The `hashdump` command extracts local account password hashes by saving the SAM and SYSTEM registry hives to disk. It performs the following steps:

1. Enables `SeBackupPrivilege` and `SeRestorePrivilege` on the current process token to gain the necessary access rights for registry save operations.
2. Resolves a temporary directory path via `GetTempPathA`.
3. Executes `reg.exe save HKLM\SAM <temp>\s.tmp /y` to save the SAM hive.
4. Executes `reg.exe save HKLM\SYSTEM <temp>\y.tmp /y` to save the SYSTEM hive.
5. Returns the file paths for both saved hives. The operator can then use the `download` command to retrieve them for offline hash extraction (e.g., with secretsdump or similar tools).
6. On failure, any partially written files are cleaned up via `DeleteFileA`.

Child processes (`reg.exe`) are spawned hidden with `CREATE_NO_WINDOW` and `SW_HIDE`, and the command waits up to 15 seconds for each to complete.

### APIs Used

| API | Purpose |
|-----|---------|
| OpenProcessToken | Open the current process token for privilege adjustment |
| LookupPrivilegeValueW | Resolve privilege name to LUID |
| AdjustTokenPrivileges | Enable SeBackupPrivilege and SeRestorePrivilege |
| GetTempPathA | Retrieve the temporary directory path |
| CreateProcessW | Execute `reg.exe save` commands in a hidden window |
| WaitForSingleObject | Wait for `reg.exe` to finish (15s timeout) |
| GetExitCodeProcess | Check reg.exe exit status |
| DeleteFileA | Clean up temp files on failure |

## MITRE ATT&CK Mapping

- **T1003.002** - OS Credential Dumping: Security Account Manager

## OPSEC Considerations

{{% notice warning %}}
This command spawns `reg.exe` as a child process twice to save the SAM and SYSTEM hives. This is a well-known credential dumping technique that is heavily signatured by EDR products and Windows Defender. The `reg.exe save HKLM\SAM` command line is a high-fidelity detection indicator. Additionally, enabling SeBackupPrivilege on a non-backup process may generate security telemetry. The saved hive files are written to the temp directory and must be manually cleaned up after retrieval.
{{% /notice %}}
