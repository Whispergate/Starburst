+++
title = "blockdlls"
chapter = false
weight = 301
+++

## Summary

Enable non-Microsoft DLL blocking on the current process. This is a one-way operation - once enabled, it cannot be disabled for the lifetime of the process (Windows kernel enforcement via `SetProcessMitigationPolicy`).

- **Needs Admin:** False
- **Version:** 2
- **Author:** @Lavender-exe

### Arguments

None. The command takes no arguments - it enables the mitigation policy unconditionally.

### Usage

```
blockdlls
```

**Example Output:**

```
block non-Microsoft DLLs enabled
```

## Detailed Summary

This command calls `SetProcessMitigationPolicy` with `ProcessSignaturePolicy` to block any DLL that is not signed by Microsoft from being loaded into the agent process. This prevents EDR user-mode hooking DLLs from being injected.

**Important:** This is irreversible. `SetProcessMitigationPolicy` for `ProcessSignaturePolicy` is a one-way kernel enforcement - attempting to disable it returns `ERROR_ACCESS_DENIED` (5). The policy remains active until the process exits.

### APIs Used

| API | Purpose |
|-----|---------|
| `SetProcessMitigationPolicy` | Apply `ProcessSignaturePolicy` mitigation to current process |

## MITRE ATT&CK Mapping

- **T1574.001** - Hijack Execution Flow: DLL Search Order Hijacking
