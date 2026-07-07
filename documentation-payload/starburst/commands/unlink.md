+++
title = "unlink"
chapter = false
weight = 201
+++

## Summary

Disconnect from a linked P2P agent.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

- **link_info** (LinkInfo, required) - The callback info identifying the linked agent to disconnect.

### Usage

```
unlink
```

Use the UI to select the linked callback to disconnect.

## Detailed Summary

The unlink command disconnects from a previously linked P2P agent. It closes the named pipe handle associated with the linked agent and removes the connection from the internal link list. After unlinking, the P2P agent will no longer receive tasking through this callback.

### APIs Used

| API | Purpose |
|-----|---------|
| `CloseHandle` | Close the named pipe handle to the linked agent |
