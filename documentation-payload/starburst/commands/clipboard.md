+++
title = "clipboard"
chapter = false
weight = 103
+++

## Summary

Read the current clipboard text contents.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

No arguments required.

### Usage

```
clipboard
```

## Detailed Summary

The `clipboard` command reads the current text contents of the Windows clipboard. It only retrieves Unicode text data (CF_UNICODETEXT format).

The agent dynamically loads `user32.dll` via `LoadLibraryA` and resolves the clipboard-related APIs (`OpenClipboard`, `CloseClipboard`, `GetClipboardData`, `IsClipboardFormatAvailable`) from it. `GlobalLock` and `GlobalUnlock` are resolved from `kernel32.dll`.

The command follows this sequence:
1. Opens the clipboard with `OpenClipboard(NULL)` (not associated with any window)
2. Checks if Unicode text format is available via `IsClipboardFormatAvailable(CF_UNICODETEXT)`
3. Retrieves the clipboard data handle with `GetClipboardData`
4. Locks the global memory object with `GlobalLock` to obtain a pointer to the wide-character string
5. Converts the wide string to a multi-byte (ANSI) string using `WideCharToMultiByte`
6. Properly unlocks and closes the clipboard before returning the result

If no text data is available on the clipboard, the command returns "No text data" as a success response.

### APIs Used

| API | Purpose |
|-----|---------|
| LoadLibraryA | Dynamically load user32.dll |
| GetProcAddress | Resolve clipboard API functions |
| OpenClipboard | Open the system clipboard |
| IsClipboardFormatAvailable | Check for CF_UNICODETEXT data |
| GetClipboardData | Retrieve clipboard data handle |
| GlobalLock | Lock global memory to access text data |
| GlobalUnlock | Unlock the global memory object |
| CloseClipboard | Release the clipboard |
| WideCharToMultiByte | Convert Unicode text to ANSI |

## MITRE ATT&CK Mapping

- **T1115** - Clipboard Data
