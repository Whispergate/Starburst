+++
title = "execute_pic"
chapter = false
weight = 103
+++

## Summary

Execute PIC (Position-Independent Code) shellcode in the current process via a new thread.

- **Needs Admin:** False
- **Version:** 2
- **Author:** @Lavender-exe

### Arguments

#### Default Group

- **pic_name** (ChooseOne, required) - Previously uploaded PIC shellcode to execute. Dynamically populated from uploaded files with `.bin`, `.pic`, or `.raw` extensions.

#### New Group

- **pic_file** (File, required) - Upload new PIC shellcode. After uploading, reuse via the Default tab.

### Usage

```
execute_pic -PIC <shellcode.bin>
```

Select a previously uploaded PIC file from the dropdown (Default group), or upload a new PIC file (New group).

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
