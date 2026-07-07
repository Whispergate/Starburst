+++
title = "keylog"
chapter = false
weight = 302
+++

## Summary

Capture keystrokes for a specified duration using `GetAsyncKeyState` polling. Returns captured keystrokes grouped by foreground window.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `duration` | Number | No | `10` | Duration in seconds to capture keystrokes. |

### Usage

```
keylog
```

```
keylog -duration 30
```

**Example Output:**

```
[Window: Untitled - Notepad]
Hello world this is a test

[Window: Google Chrome - Login]
admin@corp.local[TAB]P@ssw0rd![ENTER]
```

## Detailed Summary

The command polls all virtual key codes using `GetAsyncKeyState` in a tight loop for the specified duration. It tracks the foreground window via `GetForegroundWindow` and `GetWindowTextW`, grouping captured keystrokes by the window that was active when they were typed. Special keys (Shift, Enter, Tab, Backspace, etc.) are translated to human-readable labels.

### OPSEC Warning

This command **blocks the agent's main thread** for the entire capture duration. The agent will not beacon or respond to tasking until the keylog capture completes. Keep durations short or be aware of the impact on agent responsiveness.

### APIs Used

| API | Purpose |
|-----|---------|
| `GetAsyncKeyState` | Poll key state for each virtual key code |
| `GetForegroundWindow` | Identify the currently active window |
| `GetWindowTextW` | Retrieve the title of the foreground window |

## MITRE ATT&CK Mapping

- **T1056.001** - Input Capture: Keylogging
