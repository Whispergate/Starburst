+++
title = "jobkill"
chapter = false
weight = 202
+++

## Summary

Kill a running background job by task ID.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

- **task_id** (String, default: "") - The UUID of the background task to kill. Validated in `create_go_tasking` rather than via required-field enforcement; the agent function returns an error if the value is empty.

### Usage

```
jobkill
```

Use the `task:job_kill` UI button on an active job to terminate it.

## Detailed Summary

The jobkill command terminates a running background job thread using `TerminateThread`. It looks up the thread handle associated with the given task UUID and forcefully terminates it. The job is then removed from the internal job tracking list.

### APIs Used

| API | Purpose |
|-----|---------|
| `TerminateThread` | Forcefully terminate the background job thread |
| `CloseHandle` | Clean up the thread handle |

## OPSEC Considerations

{{% notice warning %}}
`TerminateThread` forcefully kills the thread without allowing cleanup routines to execute. This can leave resources (handles, memory, locks) in an inconsistent state. Use with caution on jobs that hold shared resources.
{{% /notice %}}
