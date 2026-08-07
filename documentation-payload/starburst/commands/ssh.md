+++
title = "ssh"
chapter = false
weight = 312
+++

## Summary

Deploy an SSH session to a remote Linux host. Creates a new Mythic callback representing the SSH session, enabling command execution on the remote host through the agent.

- **Needs Admin:** False
- **Version:** 10
- **Author:** @Lavender-exe

### Arguments

#### Parameter Group: Password Auth

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `hostname` | String | Yes | N/A | Target hostname or IP address. |
| `port` | Number | No | `22` | SSH port. |
| `username` | String | Yes | N/A | SSH username. |
| `credential` | String | Yes | N/A | SSH password. |

#### Parameter Group: Key Auth

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `hostname` | String | Yes | N/A | Target hostname or IP address. |
| `port` | Number | No | `22` | SSH port. |
| `username` | String | Yes | N/A | SSH username. |
| `private_key` | File | Yes | N/A | SSH private key file (PEM format, unencrypted RSA). |
| `credential` | String | No | N/A | Key passphrase (if the private key is encrypted). |

### Usage

```
ssh -hostname 10.10.5.50 -username admin -credential <password>
```

```
ssh -hostname db-server.corp.local -port 2222 -username root -credential <password>
```

```
ssh -hostname 10.10.5.50 -username admin -private_key <upload key file>
```

**Example Output:**

```
admin@10.10.5.50:22 (password)
```

## Detailed Summary

Interactive SSH2 terminal. Connects to remote hosts using a built-in SSH2 protocol implementation (ECDH-P256, AES-256-CTR, HMAC-SHA2-256). Opens a PTY shell with interactive I/O through Mythic's terminal UI. Supports password and RSA private key authentication. No `ssh.exe` dependency.

When using Key Auth, the private key file is uploaded to Mythic, decrypted server-side (using the passphrase from `credential` if encrypted), and the raw key data is sent to the agent. The agent then uses the key material directly for SSH2 authentication.

## MITRE ATT&CK Mapping

- **T1021.004** - Remote Services: SSH
