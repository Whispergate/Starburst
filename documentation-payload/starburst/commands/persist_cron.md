+++
title = "persist_cron"
chapter = false
weight = 103
+++

## Summary

Install, list, or remove crontab persistence entries.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| action | ChooseOne | Yes | install | `install`, `list`, or `remove` crontab entries |
| schedule | String | No | `*/5 * * * *` | Cron schedule expression (e.g. `*/5 * * * *` for every 5 minutes) |
| command | String | No | (empty) | Command to execute on schedule |

### Usage

Install a cron job that runs every 5 minutes:

```
persist_cron -action install -schedule "*/5 * * * *" -command "/tmp/agent"
```

Install with a custom schedule (every hour):

```
persist_cron -action install -schedule "0 * * * *" -command "/opt/.cache/updater"
```

List current crontab entries:

```
persist_cron -action list
```

Remove installed crontab entries:

```
persist_cron -action remove
```

## Detailed Summary

The `persist_cron` command manages crontab-based persistence on Linux. It can install new cron jobs, list existing entries, or remove previously installed entries.

When `action` is `install`, a new crontab entry is created with the specified schedule and command. The default schedule of `*/5 * * * *` runs the command every 5 minutes.

When `action` is `list`, the current user's crontab is displayed for inspection.

When `action` is `remove`, previously installed crontab entries are removed.

Crontab persistence does not require root privileges (uses the current user's crontab) and survives reboots, making it a reliable user-scope persistence mechanism on Linux.

## MITRE ATT&CK Mapping

- **T1053.003** - Scheduled Task/Job: Cron

## OPSEC Considerations

{{% notice warning %}}
Crontab entries are easily discovered via `crontab -l`. System administrators and monitoring tools routinely audit cron jobs. Some environments use `cron.allow`/`cron.deny` to restrict crontab access.
{{% /notice %}}

- Crontab entries are visible to the user via `crontab -l` and to root via `crontab -l -u <user>`
- Cron execution is logged by syslog (typically `/var/log/cron` or `/var/log/syslog`)
- `auditd` rules may monitor `crontab` command usage and changes to `/var/spool/cron/`
- The command is stored in plaintext in the crontab
- Failed executions generate error emails to the user (unless output is redirected)
