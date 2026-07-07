+++
title = "link"
chapter = false
weight = 200
+++

## Summary

Link to a P2P agent via SMB named pipe to establish a delegate relay.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

- **connection_info** (ConnectionInfo, required) - Contains `host` (target hostname) and `c2_profile` with `pipename` (named pipe to connect to).

### Usage

```
link
```

Use the `callback_table:link` UI button to initiate the connection with the required parameters.

## Detailed Summary

The link command establishes a P2P connection to a remote agent over an SMB named pipe. It connects to the target host's named pipe using `CreateFileA` with the UNC path `\\hostname\pipe\pipename`. Once connected, it reads the P2P agent's initial checkin message and establishes a delegate relay, allowing the linked agent to communicate through the current callback.

The pipe is opened with `GENERIC_READ | GENERIC_WRITE` access for bidirectional communication.

### APIs Used

| API | Purpose |
|-----|---------|
| `CreateFileA` | Open a handle to the remote named pipe |
| `ReadFile` | Read the P2P agent's checkin data from the pipe |
| `WriteFile` | Send tasking data to the P2P agent |
| `CloseHandle` | Clean up the pipe handle |

## MITRE ATT&CK Mapping

- **T1570** - Lateral Tool Transfer
- **T1572** - Protocol Tunneling
- **T1021** - Remote Services

### Example Output

```
Linked via \\10.10.5.20\pipe\msagent_47
Agent: abc12345-6789-0abc-def0-123456789abc
```

## OPSEC Considerations

- Creates an outbound SMB named pipe connection visible in network monitoring tools
- Named pipe connections may be logged by EDR or Sysmon Event ID 17/18
- The UNC path used in the connection is observable in process telemetry
