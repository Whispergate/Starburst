+++
title = "lsass_dump"
chapter = false
weight = 103
+++

## Summary

Dump LSASS process memory for credential extraction using either MiniDumpWriteDump or comsvcs.dll.

- **Needs Admin:** True
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| method | ChooseOne (minidump, comsvcs) | Yes | minidump | Dump method: MiniDumpWriteDump API or comsvcs.dll rundll32 |
| dump_path | String | No | Auto-generated | Output file path for the dump (auto-generated in temp directory if empty) |

### Usage

```
lsass_dump -method minidump
lsass_dump -method comsvcs
lsass_dump -method minidump -dump_path C:\Windows\Temp\out.dmp
```

## Detailed Summary

The `lsass_dump` command dumps the memory of the LSASS process for offline credential extraction. It supports two dump methods:

**Common setup (both methods):**
1. Enables `SeDebugPrivilege` on the current process token to allow cross-process memory access.
2. Locates the LSASS process by enumerating running processes via `CreateToolhelp32Snapshot` with `TH32CS_SNAPPROCESS`, iterating with `Process32First`/`Process32Next`, and performing a case-insensitive match on `lsass.exe`.
3. If no dump path is provided, defaults to `<temp_dir>\d.dmp`.

**Method: minidump**
1. Opens the LSASS process with `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`.
2. Loads `dbghelp.dll` and resolves `MiniDumpWriteDump`.
3. Creates the output file and calls `MiniDumpWriteDump` with `MiniDumpWithFullMemory` (type 2) to write a full memory dump.

**Method: comsvcs**
1. Builds a command line: `rundll32.exe C:\windows\system32\comsvcs.dll, MiniDump <pid> <path> full`.
2. Spawns the command as a hidden process with `CREATE_NO_WINDOW`.
3. Waits up to 30 seconds for completion and checks the exit code.

### APIs Used

| API | Purpose |
|-----|---------|
| OpenProcessToken | Open the current process token for privilege adjustment |
| LookupPrivilegeValueW | Resolve SeDebugPrivilege name to LUID |
| AdjustTokenPrivileges | Enable SeDebugPrivilege |
| CreateToolhelp32Snapshot | Snapshot running processes to find LSASS |
| Process32First / Process32Next | Enumerate process list |
| OpenProcess | Open LSASS process handle (minidump method) |
| LoadLibraryA | Load dbghelp.dll (minidump method) |
| MiniDumpWriteDump | Write full memory dump of LSASS (minidump method) |
| CreateFileA | Create the output dump file (minidump method) |
| CreateProcessW | Spawn rundll32.exe for comsvcs method |
| WaitForSingleObject | Wait for dump completion |
| GetTempPathA | Resolve default dump path |

## MITRE ATT&CK Mapping

- **T1003.001** - OS Credential Dumping: LSASS Memory

## OPSEC Considerations

{{% notice warning %}}
Both methods are high-risk from a detection standpoint. The **minidump** method calls `MiniDumpWriteDump` against the LSASS process, which is monitored by most EDR solutions via kernel callbacks and ETW providers. The **comsvcs** method spawns `rundll32.exe` with a command line referencing `comsvcs.dll, MiniDump` which is a well-known signature. Opening LSASS with `PROCESS_VM_READ` and enabling `SeDebugPrivilege` are also commonly monitored indicators. The dump file is written to disk and must be retrieved and cleaned up manually. Consider the target environment's detection capabilities when choosing a method.
{{% /notice %}}
