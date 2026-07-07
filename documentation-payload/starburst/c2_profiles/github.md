+++
title = "GitHub"
chapter = false
weight = 15
+++

## Summary

C2 communication via GitHub issue comments. Messages are posted as comments on designated issues, using the GitHub REST API over HTTPS.

## Configuration Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| Personal Access Token | String | GitHub PAT with `repo` scope |
| Owner | String | Repository owner (user or org) |
| Repository | String | Repository name |
| Server Issue | Integer | Issue number for server-to-agent messages |
| Client Issue | Integer | Issue number for agent-to-server messages |
| Callback Interval | Integer | Polling interval in seconds |
| Callback Jitter | Integer | Jitter percentage |
| Kill Date | Date | Agent self-termination date |

## Message Flow

### Sending (Agent to Server)

```
POST /repos/{owner}/{repo}/issues/{client_issue}/comments
Authorization: token {PAT}
Content-Type: application/json

{"body": "<base64(UUID + AES(TLV))>"}
```

### Receiving (Server to Agent)

```
GET /repos/{owner}/{repo}/issues/{server_issue}/comments
Authorization: token {PAT}
```

Agent polls server issue comments, processes new messages, deletes consumed comments for cleanup.

## Transport Implementation

- Uses WinINet APIs (`InternetOpenA`, `InternetConnectA`, `HttpOpenRequestA`) for HTTPS to `api.github.com`
- Minimal JSON handling - string scanner extracts `"body"` field values without full JSON parser
- Agent deletes its own comments after server acknowledges receipt
- Server-side comments are deleted by the C2 profile after agent consumes them

## Setup Requirements

1. Create a GitHub repository (can be private)
2. Create two issues: one for server-to-agent, one for agent-to-server
3. Generate a PAT with `repo` scope
4. Configure the C2 profile with these values

## OPSEC Notes

- All traffic goes to `api.github.com` over HTTPS (port 443) - blends with developer tool traffic
- GitHub is rarely blocked in corporate environments
- PAT is embedded in the payload - if recovered, attacker gains repo access; use a dedicated throwaway account
- Comment creation/deletion generates GitHub audit log entries
- Polling interval should be conservative to avoid GitHub API rate limits (5000 req/hr authenticated)
- Repository should appear legitimate with realistic commit history
- Consider using a private repository to limit exposure of C2 traffic in comment history
