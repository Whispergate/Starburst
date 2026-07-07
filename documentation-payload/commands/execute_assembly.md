+++
title = "execute_assembly"
chapter = false
weight = 103
+++

## Summary

Execute a .NET assembly in-process via CLR (Common Language Runtime) hosting.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

- **file** (File, required) - .NET assembly file (.exe) to execute.
- **arguments** (String, optional) - Command-line arguments to pass to the assembly. Default: empty.

### Usage

```
execute_assembly
```

A file dialog will appear to select the .NET assembly. Arguments can be specified in the arguments field.

## Detailed Summary

Loads and executes a .NET assembly entirely in-memory:

1. Loads `mscoree.dll` and calls `CLRCreateInstance` to initialize the CLR
2. Enumerates installed runtimes and starts the latest available version
3. Gets an `ICorRuntimeHost` interface
4. Creates a new AppDomain for isolation
5. Loads the assembly bytes into the AppDomain via `SAFEARRAY`
6. Invokes the assembly's entry point with the provided arguments
7. Captures stdout/stderr output via redirected console handles

The CLR is loaded into the current process. This is a one-way operation - the CLR cannot be unloaded once initialized.

### APIs Used

| API | Purpose | Library |
|-----|---------|---------|
| `CLRCreateInstance` | Initialize CLR metadata host | mscoree |
| `ICLRMetaHost::EnumerateInstalledRuntimes` | Find available .NET versions | CLR |
| `ICLRRuntimeInfo::GetInterface` | Get runtime host interface | CLR |
| `ICorRuntimeHost::CreateDomain` | Create isolated AppDomain | CLR |
| `_AppDomain::Load_3` | Load assembly from byte array | CLR |
| `_MethodInfo::Invoke_3` | Invoke assembly entry point | CLR |

## MITRE ATT&CK Mapping

- **T1059.001** - Command and Scripting Interpreter: PowerShell

{{% notice warning %}}
Loading the CLR into a process is a well-known indicator. Once loaded, the CLR cannot be unloaded. EDR products commonly detect CLR loading in unmanaged processes via ETW events and `clrjit.dll` module loads.
{{% /notice %}}

## OPSEC Considerations

- Loads `mscoree.dll`, `clrjit.dll`, and related .NET DLLs into the process
- CLR initialization generates ETW events detectable by EDR
- The assembly is loaded from memory (no disk drop) but the CLR load itself is the indicator
- Consider process context - loading CLR into `notepad.exe` is more suspicious than into `powershell.exe`
- The CLR persists for the lifetime of the process after first use

## Limitations

- .NET assemblies only - native executables are not supported
- Assembly must have a standard entry point (`static void Main`)
- CLR version depends on what is installed on the target
