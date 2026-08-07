+++
title = "config"
chapter = false
weight = 103
+++

## Summary

View or modify the agent's runtime configuration (sleep, jitter, killdate, spawnto paths).

- **Needs Admin:** False
- **Version:** 2
- **Author:** @Lavender-exe

### Arguments

- **sleep** (Number, optional) - New sleep interval in seconds (-1 = no change). Default: -1.
- **jitter** (Number, optional) - New jitter percentage 0-100 (-1 = no change). Default: -1.
- **killdate** (Number, optional) - New killdate as unix timestamp (-1 = no change). Default: -1.
- **spawnto_x64** (String, optional) - x64 sacrifice binary path (empty = no change). Default: empty.
- **spawnto_x64_args** (String, optional) - x64 sacrifice binary arguments (empty = no change). Default: empty.
- **spawnto_x86** (String, optional) - x86 sacrifice binary path (empty = no change). Default: empty.
- **spawnto_x86_args** (String, optional) - x86 sacrifice binary arguments (empty = no change). Default: empty.

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

Set x64 spawnto binary:

```
config -spawnto_x64 "C:\Windows\System32\svchost.exe" -spawnto_x64_args "-k netsvcs"
```

Set x86 spawnto binary:

```
config -spawnto_x86 "C:\Windows\SysWOW64\svchost.exe" -spawnto_x86_args "-k netsvcs"
```

Change sleep and update both spawnto paths:

```
config -sleep 10 -spawnto_x64 "C:\Windows\System32\RuntimeBroker.exe" -spawnto_x86 "C:\Windows\SysWOW64\RuntimeBroker.exe"
```

## Detailed Summary

When all parameters are -1, the command returns current configuration values. When any parameter is >= 0, that value is updated. Sleep values are converted from seconds to milliseconds by the command handler before being sent to the agent.

A killdate of 0 means no kill date is set. When set, the agent checks the killdate against the current time at each beacon cycle and exits if the date has passed.

## MITRE ATT&CK Mapping

None.
