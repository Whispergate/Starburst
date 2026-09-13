+++
title = "link_webshell"
chapter = false
weight = 202
+++

## Summary

Link to an Ariadne webshell via HTTP, creating a P2P delegate connection.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

- **connection_info** (ConnectionInfo, required) - Contains `host` (target hostname) and `c2_profile` with parameters: `url` (webshell URL), `auth_method` (cookie/header/parameter), `auth_name`, `auth_value`, `aes_key` (32-byte key, base64), `param_name` (POST parameter name).

### Usage

```
link_webshell
```

Use the `callback_table:link` UI button to initiate the connection. Select the Ariadne webshell payload and configure the connection parameters.

## Detailed Summary

The link_webshell command establishes a P2P delegate connection to a deployed Ariadne webshell over HTTP. Unlike the `link` command which uses SMB named pipes, this command communicates with the webshell via HTTP POST requests using WinHTTP, making it suitable for reaching webshells on web servers that are not accessible via SMB.

### Connection Flow

1. The agent parses the connection parameters (URL, auth method, auth credentials, AES key, POST parameter name)
2. WinHTTP is dynamically loaded and initialized via `LoadLibraryA` / `GetProcAddress`
3. A `poll_p2p|heartbeat` message is sent to the webshell URL to verify connectivity
4. The webshell responds with its P2P checkin data (UUID, hostname, OS, user, etc.)
5. The agent extracts the webshell's payload UUID from the checkin response
6. An `ACTION_LINK_ADD` message is queued, registering the new P2P link with Mythic
7. The agent begins polling the webshell on each beacon interval, relaying delegate messages between Mythic and the webshell

### Transport Protocol

All messages to the webshell are:
1. Optionally encrypted with AES-256-CBC (if an AES key is configured)
2. Base64 encoded (standard encoding)
3. URL-encoded for safe form POST transmission
4. Sent as `application/x-www-form-urlencoded` POST body (`param_name=encoded_data`)

Responses are extracted from a `<span id="r">` element in the HTML response, then base64 decoded and optionally AES decrypted.

### Authentication Methods

| Method | Behavior |
|--------|----------|
| Cookie | Sends `Cookie: auth_name=auth_value` header |
| Header | Sends `auth_name: auth_value` as a custom HTTP header |
| Parameter | Appends `&auth_name=auth_value` to the POST body |

### Delegate Message Relay

Once linked, the agent relays messages between Mythic and the webshell each beacon cycle:

- **Outbound (Mythic → webshell):** The StarburstTranslator strips the callback UUID prefix from Mythic's delegate message and passes the raw pipe-format command to the agent, which POSTs it to the webshell
- **Inbound (webshell → Mythic):** The agent polls the webshell with `poll_p2p|heartbeat`, receives pipe-format responses, and queues them as `ACTION_LINK_MSG` delegate messages for the translator to convert back to Mythic JSON

### APIs Used

| API | Purpose |
|-----|---------|
| `LoadLibraryA` | Dynamically load winhttp.dll |
| `GetProcAddress` | Resolve WinHTTP function pointers |
| `WinHttpOpen` | Create a WinHTTP session |
| `WinHttpConnect` | Connect to the webshell host |
| `WinHttpOpenRequest` | Create an HTTP POST request |
| `WinHttpAddRequestHeaders` | Add authentication and content-type headers |
| `WinHttpSetOption` | Disable SSL certificate validation |
| `WinHttpSendRequest` | Send the encrypted POST body |
| `WinHttpReceiveResponse` | Receive the HTTP response |
| `WinHttpQueryDataAvailable` | Check for available response data |
| `WinHttpReadData` | Read the response body |
| `WinHttpCloseHandle` | Clean up request and connection handles |

## MITRE ATT&CK Mapping

- **T1570** - Lateral Tool Transfer
- **T1572** - Protocol Tunneling
- **T1071.001** - Application Layer Protocol: Web Protocols

### Example Output

```
Linked webshell: http://10.10.5.30/uploads/ariadne.php
Agent: 9f93658e-d16f-47ba-bdf0-b8526bd4cd96
```

## OPSEC Considerations

- Creates outbound HTTP/HTTPS connections from the host to the webshell URL, visible in network monitoring and proxy logs
- WinHTTP is loaded dynamically at runtime; the `LoadLibraryA("winhttp.dll")` call may be observed by EDR
- POST requests to the webshell URL follow a predictable pattern (`param_name=base64_data`) that could be signatured
- Authentication credentials (cookie or header values) are sent in cleartext over HTTP; use HTTPS where possible
- The polling interval matches the agent's beacon interval, creating regular traffic patterns
- SSL certificate validation is disabled for HTTPS connections, which may trigger security alerts
- The webshell URL is stored in agent memory for the lifetime of the link
