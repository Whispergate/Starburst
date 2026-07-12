+++
title = "powerpick"
chapter = false
weight = 103
+++

## Summary

Execute PowerShell scripts in-process via CLR hosting without spawning powershell.exe.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| script | String | Yes | - | PowerShell script to execute via CLR-hosted runspace (no powershell.exe) |

### Usage

```
powerpick -Script "Get-Process | Select-Object -First 5"
powerpick -Script "Get-ADUser -Filter * | Select Name,Enabled"
powerpick -Script "[System.Environment]::OSVersion"
```

## Detailed Summary

The `powerpick` command executes PowerShell scripts entirely in-process by hosting the .NET CLR runtime within the agent process. It avoids spawning `powershell.exe`, which is a common detection vector.

The command works by:

1. Loading `oleaut32.dll` and resolving SAFEARRAY/BSTR APIs for COM interop.
2. Optionally patching AMSI (if compiled with AMSI evasion on x64 builds) to prevent script scanning.
3. Loading `mscoree.dll` and calling `CLRCreateInstance` to obtain an `ICLRMetaHost` interface.
4. Requesting the .NET v4.0.30319 runtime via `GetRuntime` and obtaining an `ICorRuntimeHost` interface.
5. Starting the CLR and retrieving the default AppDomain.
6. Loading an embedded PSRunner .NET assembly (a small C# helper) into the AppDomain via `_AppDomain::Load_3`.
7. Retrieving the assembly's entry point via `_Assembly::get_EntryPoint`.
8. Redirecting stdout/stderr to a persistent named pipe for output capture. The pipe is reused across invocations to avoid stale handle issues from .NET's cached TextWriter.
9. Converting the PowerShell script string to a wide BSTR and invoking the runner assembly's entry point via `_MethodInfo::Invoke_3`, passing the script as an argument.
10. Reading captured output from the pipe via `PeekNamedPipe`/`ReadFile` and returning it as the command response.

The PSRunner assembly internally creates a `System.Management.Automation.Runspace` and `PowerShell` object to execute the script, collecting output, errors, and warnings.

### APIs Used

| API | Purpose |
|-----|---------|
| LoadLibraryA | Load oleaut32.dll and mscoree.dll |
| GetProcAddress | Resolve SAFEARRAY, BSTR, CLR, and SetStdHandle functions |
| CLRCreateInstance | Initialize the .NET CLR hosting interfaces |
| ICLRMetaHost::GetRuntime | Obtain the .NET 4.0 runtime info |
| ICLRRuntimeInfo::GetInterface | Get the ICorRuntimeHost interface |
| ICorRuntimeHost::Start | Start the CLR |
| ICorRuntimeHost::GetDefaultDomain | Get the default AppDomain |
| _AppDomain::Load_3 | Load the PSRunner assembly from a byte array |
| _Assembly::get_EntryPoint | Get the assembly entry point MethodInfo |
| _MethodInfo::Invoke_3 | Invoke the entry point with the script argument |
| SafeArrayCreate / SafeArrayCreateVector | Create SAFEARRAYs for COM interop |
| SafeArrayAccessData / SafeArrayUnaccessData | Access SAFEARRAY data buffers |
| SafeArrayPutElement / SafeArrayDestroy | Populate and clean up SAFEARRAYs |
| SysAllocString / SysFreeString | Allocate and free BSTRs |
| SetStdHandle | Redirect stdout/stderr to capture pipe |
| CreatePipe | Create anonymous pipe for output capture |
| PeekNamedPipe / ReadFile | Read captured output from the pipe |
| MultiByteToWideChar | Convert script string to wide characters |

## MITRE ATT&CK Mapping

- **T1059.001** - Command and Scripting Interpreter: PowerShell

## OPSEC Considerations

{{% notice warning %}}
This command loads the .NET CLR and System.Management.Automation into the agent process. While it avoids spawning powershell.exe, EDR solutions may detect CLR loading in unexpected processes, assembly loading via the CLR hosting APIs, or PowerShell script block logging if enabled via Group Policy. The AMSI bypass (when compiled in) patches amsi.dll in-process, which may be detected by tamper-protection mechanisms.
{{% /notice %}}
