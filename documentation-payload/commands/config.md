+++
title = "config"
chapter = false
weight = 103
+++

## Summary

View or modify the agent's runtime configuration (sleep interval, jitter, kill date).

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

- **sleep** (Number, optional) - New sleep interval in seconds. Use -1 for no change. Default: -1.
- **jitter** (Number, optional) - New jitter percentage (0-100). Use -1 for no change. Default: -1.
- **killdate** (Number, optional) - New kill date as Unix timestamp. Use -1 for no change. Default: -1.

### Usage

View current configuration:

```
config
```

**Example Output:**

```
sleep=5000 jitter=10 killdate=0
```

Change sleep to 30 seconds:

```
config -sleep 30
```

Change jitter to 25%:

```
config -jitter 25
```

## Detailed Summary

When all parameters are -1, the command returns current configuration values. When any parameter is >= 0, that value is updated. Sleep values are converted from seconds to milliseconds by the command handler before being sent to the agent.

A killdate of 0 means no kill date is set. When set, the agent checks the killdate against the current time at each beacon cycle and exits if the date has passed.

## MITRE ATT&CK Mapping

None.
