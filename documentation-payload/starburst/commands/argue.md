+++
title = "argue"
chapter = false
weight = 103
+++

## Summary

Set or clear fake command-line arguments for child processes.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| action | ChooseOne (set, clear) | Yes | set | Set or clear fake arguments |
| fake_args | String | No | - | Fake command-line arguments to display |

### Usage

```
argue -action set -fake_args "notepad.exe"
argue -action set -fake_args "svchost.exe -k netsvcs -p -s Schedule"
argue -action clear
```

## Detailed Summary

The `argue` command configures argument spoofing for child processes spawned by the agent. When enabled, child processes will appear in process listings with the specified fake command-line arguments instead of their real arguments. This is an evasion technique that manipulates how process arguments are presented to monitoring tools.

**Set:**
1. Parses the fake arguments string from the task parameters.
2. Frees any previously stored fake arguments buffer (`inst.argue_args`).
3. Allocates a new heap buffer and copies the fake arguments into `inst.argue_args`.
4. Stores the argument length in `inst.argue_len`.
5. Subsequent child process creations by the agent will use these fake arguments for argument spoofing.

**Clear:**
1. Frees the stored fake arguments buffer if one exists.
2. Sets `inst.argue_args` to `nullptr` and `inst.argue_len` to 0.
3. Disables argument spoofing for future child processes.

This is a configuration command that modifies how subsequent process creation operations present their command-line arguments. It does not spawn any processes itself.

### APIs Used

No direct Windows API calls are made. This command only modifies internal agent state (heap allocation and instance variable management).

## MITRE ATT&CK Mapping

- **T1564.010** - Hide Artifacts: Process Argument Spoofing
