+++
title = "ssh"
chapter = false
weight = 312
+++

## Summary

Deploy an SSH session to a remote Linux host. Creates a new Mythic callback representing the SSH session, enabling command execution on the remote host through the agent.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `hostname` | String | Yes | N/A | Target host to SSH into. |
| `port` | Number | No | `22` | SSH port on the target host. |
| `username` | String | Yes | N/A | Username for SSH authentication. |
| `credentials` | Credential | Yes | N/A | Credential for authentication (password or key from Mythic credential store). |

### Usage

```
ssh -hostname 10.10.5.50 -username admin -credentials <select from credential store>
```

```
ssh -hostname db-server.corp.local -port 2222 -username root -credentials <select from credential store>
```

**Example Output:**

```
[*] Spawning SSH session to admin@10.10.5.50:22
[+] SSH connection established
[+] New callback registered: ssh-abc12345
```

## Detailed Summary

Spawns `ssh.exe` as a child process using `CreateProcessA` with stdin/stdout/stderr redirected through anonymous pipes created with `CreatePipe`. The agent writes commands to the SSH process's stdin and reads output from its stdout, relaying the data through the Mythic C2 channel.

The SSH session is registered as a new callback in Mythic, allowing the operator to interact with the remote Linux host through the Mythic UI as if it were a separate agent. Authentication is handled through the Mythic credential store, supporting both password and key-based authentication.

### APIs Used

| API | Purpose |
|-----|---------|
| `CreateProcessA` | Spawn `ssh.exe` child process |
| `CreatePipe` | Create anonymous pipes for stdin/stdout/stderr redirection |

## MITRE ATT&CK Mapping

- **T1021.004** - Remote Services: SSH
