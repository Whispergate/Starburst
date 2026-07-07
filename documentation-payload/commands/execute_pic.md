+++
title = "execute_pic"
chapter = false
weight = 103
+++

## Summary

Execute PIC (Position-Independent Code) shellcode in the current process via a new thread.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

- **file** (File, required) - PIC shellcode file to execute. Supports raw PIC or Crystal Palace output.

### Usage

```
execute_pic
```

A file dialog will appear to select the shellcode file.

## Detailed Summary

1. Allocates RW memory via `VirtualAlloc`
2. Copies the shellcode into the allocation
3. Changes memory protection to RX via `VirtualProtect`
4. Creates a new thread pointing to the shellcode via `CreateThread`
5. Waits for the thread to complete

The shellcode runs in the same process as the agent but in a separate thread.

### APIs Used

| API | Purpose |
|-----|---------|
| `VirtualAlloc` | Allocate memory for shellcode |
| `VirtualProtect` | Change memory protection RW -> RX |
| `CreateThread` | Execute shellcode in new thread |
| `WaitForSingleObject` | Wait for execution to complete |
| `VirtualFree` | Free shellcode memory |

## MITRE ATT&CK Mapping

- **T1106** - Native API

## OPSEC Considerations

- Memory allocation + protection change pattern (RW -> RX) is a common detection signal
- Thread creation from non-image-backed memory may be flagged
- Crystal Palace payloads are preferred as they follow the same PIC conventions
