+++
title = "persist_systemd"
chapter = false
weight = 103
+++

## Summary

Install, remove, or list systemd service persistence. Uses system units if root, user units otherwise.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| action | ChooseOne | Yes | install | `install`, `remove`, or `list` systemd services |
| name | String | No | (empty) | Service unit name (without .service suffix) |
| binary_path | String | No | (empty) | Full path to the binary to run as a service |

### Usage

Install a systemd service as a non-root user (user unit):

```
persist_systemd -action install -name myagent -binary_path /tmp/agent
```

Install a system-wide service (requires root):

```
persist_systemd -action install -name updater -binary_path /opt/.cache/updater
```

List installed services:

```
persist_systemd -action list
```

Remove a previously installed service:

```
persist_systemd -action remove -name myagent
```

## Detailed Summary

The `persist_systemd` command manages systemd service-based persistence on Linux. It can install new service units, list existing services, or remove previously installed units.

When `action` is `install`, a `.service` unit file is written and enabled. The command automatically determines whether to create a system unit (`/etc/systemd/system/`) or a user unit (`~/.config/systemd/user/`) based on the current privilege level.

System units (root) start at boot before any user logs in. User units start when the user's session begins and can optionally be configured with `loginctl enable-linger` to persist across logouts.

When `action` is `list`, installed systemd services are enumerated.

When `action` is `remove`, the specified service unit is stopped, disabled, and its unit file is deleted.

## MITRE ATT&CK Mapping

- **T1543.002** - Create or Modify System Process: Systemd Service

## OPSEC Considerations

{{% notice warning %}}
Systemd services are well-audited on most Linux systems. Custom service units are visible via `systemctl list-units` and `systemctl status`. Unit files on disk are inspectable. Hardened environments may use SELinux or AppArmor policies that restrict custom service creation.
{{% /notice %}}

- Service units are visible via `systemctl list-units` and `systemctl status <name>`
- Unit files are stored in plaintext on disk and can be inspected
- `journalctl -u <name>` shows service logs including start/stop events
- `auditd` may monitor writes to systemd unit directories
- System units require root; user units do not but may not survive logouts without lingering enabled
- Service failures generate journal entries that may trigger alerting
