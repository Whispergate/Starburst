+++
title = "HTTPX"
chapter = false
weight = 10
+++

## Summary

Malleable HTTP/HTTPS profile with configurable transforms, headers, and message placement. Extends the base HTTP profile with C2 profile flexibility.

## Configuration Parameters

Inherits all HTTP profile parameters plus:

| Parameter | Type | Description |
|-----------|------|-------------|
| Raw C2 Config | JSON | Full malleable profile configuration |

## Malleable Transforms

HTTPX supports a transform pipeline applied to messages before transmission:

| Transform | Direction | Description |
|-----------|-----------|-------------|
| `base64` | Encode/Decode | Standard base64 encoding |
| `base64url` | Encode/Decode | URL-safe base64 encoding |
| `netbios` | Encode/Decode | NetBIOS encoding |
| `netbiosu` | Encode/Decode | NetBIOS uppercase encoding |
| `xor` | Encode/Decode | XOR with configurable key |
| `prepend` | Add/Remove | Prepend static bytes |
| `append` | Add/Remove | Append static bytes |

## Message Placement

Messages can be placed in different HTTP locations:

- **Body** - Standard POST/response body
- **Cookie** - HTTP Cookie header value
- **Header** - Custom HTTP header value
- **Query Parameter** - URL query parameter value

## Variations

HTTPX supports multiple profile variations for domain rotation:

- **Round Robin** - Cycle through domains sequentially
- **Fail Over** - Use next domain on connection failure
- **Random** - Random domain selection per callback

## OPSEC Notes

- Malleable profiles allow traffic to mimic legitimate web applications
- Transform pipeline ensures messages don't have obvious base64 patterns in traffic
- Domain rotation and custom headers help evade network signatures
- Profile should be designed to match traffic patterns of the target environment
