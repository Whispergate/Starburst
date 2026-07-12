+++
title = "windows"
chapter = false
weight = 103
+++

## Summary

Enumerate visible windows with their process IDs.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

No arguments required.

### Usage

```
windows
```

## Detailed Summary

The `windows` command enumerates all visible top-level windows on the desktop, returning each window's handle, owning process ID, and title text.

The agent dynamically loads `user32.dll` and resolves `EnumWindows`, `IsWindowVisible`, `GetWindowTextW`, and `GetWindowThreadProcessId`. It uses `EnumWindows` with a callback function that iterates over every top-level window.

For each window, the callback:
1. Checks visibility with `IsWindowVisible` - invisible windows are skipped
2. Retrieves the window title with `GetWindowTextW` - windows with no title are skipped
3. Gets the owning process ID via `GetWindowThreadProcessId`
4. Formats the window handle (HWND) as a hexadecimal value prefixed with `0x`
5. Converts the wide-character title to ANSI using `WideCharToMultiByte`

Results are returned as a tab-delimited table with HWND, PID, and Title columns. The output buffer is capped at 32KB to prevent excessive memory usage.

### APIs Used

| API | Purpose |
|-----|---------|
| LoadLibraryA | Dynamically load user32.dll |
| GetProcAddress | Resolve window enumeration functions |
| EnumWindows | Iterate over all top-level windows |
| IsWindowVisible | Filter to only visible windows |
| GetWindowTextW | Retrieve window title text |
| GetWindowThreadProcessId | Get the PID that owns each window |
| WideCharToMultiByte | Convert wide window titles to ANSI |

## MITRE ATT&CK Mapping

- **T1010** - Application Window Discovery
