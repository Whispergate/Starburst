+++
title = "exit"
chapter = false
weight = 100
+++

## Summary

Terminates the Starburst agent. The agent stops its beacon loop, cleans up crypto providers, closes transport handles, and frees allocated memory before returning.

### Arguments

No arguments required.

### Usage

```
exit
```

### MITRE ATT&CK Mapping

None.

### OPSEC Considerations

- The host process continues running after the agent exits - the shellcode simply returns
- No artifacts are written to disk during exit
- Crypto keys and sensitive state are zeroed before cleanup
