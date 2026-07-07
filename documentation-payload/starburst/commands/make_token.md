+++
title = "make_token"
chapter = false
weight = 210
+++

## Summary

Create a new logon token with the specified credentials.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

- **domain** (String, optional, default: ".") - The domain or computer name for the logon.
- **username** (String, required) - The username to authenticate as.
- **password** (String, required) - The password for authentication.

### Usage

```
make_token -domain CORP -username admin -password P@ssw0rd!
```

```
make_token -username localadmin -password Summer2024!
```

## Detailed Summary

The make_token command creates a new logon token using `LogonUserW` with `LOGON32_LOGON_NEW_CREDENTIALS` logon type, which creates a token suitable for accessing remote network resources. The resulting token is then applied to the current thread using `ImpersonateLoggedOnUser`.

This is equivalent to `runas /netonly` and only affects network authentication. Local operations continue using the original process token.

### APIs Used

| API | Purpose |
|-----|---------|
| `LogonUserW` | Create a new logon token with the provided credentials |
| `ImpersonateLoggedOnUser` | Apply the new token to the current thread |

## MITRE ATT&CK Mapping

- **T1134.001** - Access Token Manipulation: Token Impersonation/Theft

## OPSEC Considerations

{{% notice warning %}}
`LogonUserW` generates a logon event (Event ID 4624, logon type 9 - NewCredentials). This logon event is visible in Windows Security logs and may be correlated by SIEM products.
{{% /notice %}}
