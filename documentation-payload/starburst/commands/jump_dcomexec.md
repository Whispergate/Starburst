+++
title = "jump_dcomexec"
chapter = false
weight = 103
+++

## Summary

Stage a payload to a remote host via ADMIN$ and execute it using DCOM MMC20.Application.

- **Needs Admin:** False
- **Version:** 2
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| hostname | String | Yes | - | Target hostname or IP |
| payload | File | Yes | - | Payload file to stage and execute on remote host |

### Usage

```
jump_dcomexec -hostname TARGET -payload <file>
jump_dcomexec -hostname 10.0.0.5 -payload <agent.exe>
```

## Detailed Summary

The `jump_dcomexec` command performs lateral movement by staging a payload to a remote host and executing it via DCOM. The payload filename is randomly generated (8 hex bytes + .exe) server-side for each execution.

The command works by:

1. **Payload staging:** Writing the payload file to `\\target\ADMIN$\Temp\<random>.exe` via SMB using `CreateFileA` and `WriteFile` over the UNC path.
2. **COM initialization:** Loading `ole32.dll` and `oleaut32.dll`, resolving COM APIs, and calling `CoInitializeEx` and `CoInitializeSecurity`.
3. **DCOM object creation:** Using `CoCreateInstanceEx` to instantiate the `MMC20.Application` COM object (CLSID `49B2791A-B1AE-4C90-...`) on the remote host via `COSERVERINFO`.
4. **Method invocation chain:**
   - Obtaining the `Document` property from the MMC20 Application object via `IDispatch::GetIDsOfNames` and `Invoke`.
   - Obtaining the `ActiveView` property from the Document object.
   - Calling `ExecuteShellCommand` on the ActiveView with four parameters: the command path (`C:\Windows\Temp\<filename>`), empty directory, empty parameters, and window state "7" (hidden).
5. **Cleanup:** Releasing all COM interfaces. If DCOM execution fails, the staged file is deleted from the remote host.

### APIs Used

| API | Purpose |
|-----|---------|
| CreateFileA | Create the payload file on the remote host via UNC path |
| WriteFile | Write payload data to the staged file |
| DeleteFileW | Clean up staged payload on failure |
| LoadLibraryA | Load ole32.dll and oleaut32.dll |
| GetProcAddress | Resolve COM and BSTR function pointers |
| CoInitializeEx | Initialize COM |
| CoInitializeSecurity | Set COM security levels |
| CoCreateInstanceEx | Create MMC20.Application on the remote host |
| IDispatch::GetIDsOfNames | Resolve method/property DISPIDs |
| IDispatch::Invoke | Call Document, ActiveView, and ExecuteShellCommand |
| SysAllocString / SysFreeString | Allocate and free BSTRs for COM parameters |
| MultiByteToWideChar | Convert strings to wide characters for COM |
| CloseHandle | Close file handles |

## MITRE ATT&CK Mapping

- **T1021.003** - Remote Services: Distributed Component Object Model

## OPSEC Considerations

{{% notice warning %}}
This command writes a payload to the remote host's ADMIN$ share and executes it via DCOM, both of which generate significant forensic artifacts. The payload is written to `C:\Windows\Temp\` with a random filename and is not automatically cleaned up after successful execution. DCOM lateral movement via MMC20.Application is a well-known technique that is monitored by many EDR solutions. The operation requires ADMIN$ share access and DCOM permissions on the target, which typically requires administrator-level credentials. Network-level detections may trigger on the DCOM/RPC traffic patterns.
{{% /notice %}}
