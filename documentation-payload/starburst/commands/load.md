+++
title = "load"
chapter = false
weight = 103
+++

## Summary

Load a PIC module into the agent at runtime, registering new command handlers.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| module_name | ChooseOne (dynamic) | Yes (Default group) | - | Previously uploaded PIC module to load (filters for .bin, .pic, .mod, .raw files) |
| module_file | File | Yes (New group) | - | Upload a new PIC module. After uploading, reuse via the Default tab. |

### Usage

```
load -module <module.bin>
load -module_file <new_module.pic>
```

## Detailed Summary

The `load` command extends the agent at runtime by loading position-independent code (PIC) modules that register new command handlers. This enables a modular architecture where capabilities can be added on-demand without rebuilding the agent.

**Server-side processing:**

The Mythic server supports two parameter groups: "Default" (selecting a previously uploaded module by name) and "New" (uploading a fresh module file). In both cases, the module content is base64-encoded and sent to the agent. After a successful load, the server-side `process_response` handler attempts to register the new command name with Mythic via `SendMythicRPCCallbackAddCommand`, deriving the command name from the module filename.

**Agent-side execution:**

1. Parses the module data from the task parameters. The first 4 bytes contain the init function offset within the PIC.
2. Validates that the module data is non-empty and that the module count has not reached `MAX_LOADED_MODULES`.
3. Allocates RW memory via `VirtualAlloc` and copies the PIC (starting after the 4-byte header) into it.
4. Changes the memory protection to `PAGE_EXECUTE_READ` via `VirtualProtect`.
5. Verifies that command slots are available in the loaded command table.
6. Calls the module's init function at the specified offset, passing a pointer to the agent instance, a pointer to available command table entries, and the maximum number of slots. The init function has the signature `int ModuleInitFn(instance*, LoadedCommand*, int)` and returns the number of commands registered.
7. Marks the newly registered command entries as active and updates the loaded module/command counts.
8. Stores the module's base address for lifetime management.

### APIs Used

| API | Purpose |
|-----|---------|
| VirtualAlloc | Allocate RW memory for the PIC module |
| VirtualProtect | Change memory protection to RX before executing the init function |
| VirtualFree | Free module memory if initialization fails |

## MITRE ATT&CK Mapping

- **T1129** - Shared Modules

## OPSEC Considerations

{{% notice warning %}}
This command allocates executable memory and runs a module initialization function, which involves the RW-to-RX memory protection change pattern. Each loaded module consumes memory that is never freed during the agent's lifetime. The module init function executes arbitrary code -- ensure modules are trusted before loading. EDR solutions may detect the VirtualAlloc/VirtualProtect pattern used for the module memory.
{{% /notice %}}
