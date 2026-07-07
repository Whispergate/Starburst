+++
title = "sleep"
chapter = false
weight = 103
+++

## Summary

Change the agent's callback interval and jitter percentage.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

- **interval** (Number, optional) - Sleep interval in seconds. Default: 10.
- **jitter** (Number, optional) - Jitter percentage (0-100). Default: 23.

### Usage

```
sleep 30 20
```

Sets the callback interval to 30 seconds with 20% jitter.

```
sleep 60
```

Sets the callback interval to 60 seconds, keeping current jitter.

## Detailed Summary

The sleep command updates the agent's `sleep_ms` and `jitter_pct` fields. The interval value provided in seconds is converted to milliseconds by the command handler before being sent to the agent.

Jitter introduces randomness to each sleep cycle. With a 60-second interval and 20% jitter, each sleep will be between 54 and 66 seconds.

The agent uses `NtDelayExecution` for sleeping rather than `kernel32!Sleep`.

## MITRE ATT&CK Mapping

None.
