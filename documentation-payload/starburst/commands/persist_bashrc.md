+++
title = "persist_bashrc"
chapter = false
weight = 103
+++

## Summary

Append a command to the user's `.bashrc` for shell login persistence, or list current rc file contents.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| action | ChooseOne | Yes | install | `install` to add a command to .bashrc, or `list` to view current contents |
| command | String | No | (empty) | Command to append to .bashrc (runs on each shell login) |

### Usage

Install persistence by appending a command to `.bashrc`:

```
persist_bashrc -action install -command "/tmp/agent"
```

Install a backgrounded callback on login:

```
persist_bashrc -action install -command "nohup /opt/.cache/updater &>/dev/null &"
```

List current `.bashrc` contents to check what's already there:

```
persist_bashrc -action list
```

## Detailed Summary

The `persist_bashrc` command provides user-level persistence on Linux by appending a command to the target user's `~/.bashrc` file. The appended command runs every time the user opens a new interactive Bash shell.

When `action` is `install`, the specified command string is appended to `~/.bashrc`. When `action` is `list`, the current contents of `~/.bashrc` are returned for inspection.

This mechanism provides user-scope persistence without requiring root privileges. The persistence survives reboots as long as the user's `.bashrc` is loaded on login.

## MITRE ATT&CK Mapping

- **T1546.004** - Event Triggered Execution: Unix Shell Configuration Modification

## OPSEC Considerations

{{% notice warning %}}
Modifications to `.bashrc` are easily discovered by users who inspect their shell configuration. File integrity monitoring (e.g., AIDE, OSSEC) will flag changes to rc files. The appended command is stored in plaintext.
{{% /notice %}}

- Changes to `.bashrc` are visible to the user and any file integrity monitoring
- The command is stored in plaintext in the rc file
- `.bashrc` is only sourced for interactive non-login shells by default (`.bash_profile` or `.profile` sources it for login shells on most distros)
- Consider obfuscating the appended command to reduce visibility during casual inspection
