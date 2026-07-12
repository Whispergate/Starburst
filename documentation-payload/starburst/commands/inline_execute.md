+++
title = "inline_execute"
chapter = false
weight = 103
+++

## Summary

Execute position-independent code (PIC/shellcode) inline within the agent process.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| pic_file | File | Yes | - | PIC/shellcode file to execute |
| arguments | String | No | "" | Arguments to pass to the PIC |

### Usage

```
inline_execute -pic_file <shellcode.bin> -arguments "arg1 arg2"
inline_execute -pic_file <shellcode.bin>
```

## Detailed Summary

The `inline_execute` command runs raw position-independent code (shellcode) directly within the agent's process memory space. This is useful for executing custom PIC payloads without spawning a new process.

The command works by:

1. Parsing the uploaded PIC bytes and optional argument string from the task parameters.
2. Copying arguments to a stack buffer (up to 1023 bytes).
3. Allocating memory with `VirtualAlloc` using `PAGE_READWRITE` permissions.
4. Copying the PIC into the allocated memory region.
5. Changing the memory protection to `PAGE_EXECUTE_READ` via `VirtualProtect` (RW then RX pattern).
6. Casting the memory to a function pointer with the signature `void(char* args, int len)` and calling it, passing the arguments buffer and its length.
7. Freeing the allocated memory with `VirtualFree` after execution completes.

The PIC must conform to the calling convention expected: it receives a `char*` pointer to the arguments and an `int` length parameter.

### APIs Used

| API | Purpose |
|-----|---------|
| VirtualAlloc | Allocate RW memory for the PIC |
| VirtualProtect | Change memory protection from RW to RX before execution |
| VirtualFree | Free the allocated memory after execution |
| GetProcAddress | Resolve VirtualProtect dynamically |

## MITRE ATT&CK Mapping

- **T1059** - Command and Scripting Interpreter

## OPSEC Considerations

{{% notice warning %}}
This command allocates executable memory and runs arbitrary shellcode inside the agent process. The RW-to-RX memory protection change pattern is a well-known indicator. EDR solutions may flag VirtualAlloc/VirtualProtect sequences with executable permissions. If the PIC crashes or behaves unexpectedly, it will take down the agent process. There is no sandboxing or exception handling around the PIC execution.
{{% /notice %}}
