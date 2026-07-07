+++
title = "screenshot"
chapter = false
weight = 103
+++

## Summary

Capture a screenshot of the current desktop.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

No arguments required.

### Usage

```
screenshot
```

The screenshot is captured as a BMP and downloaded to the Mythic server via the file download protocol.

## Detailed Summary

Captures the primary display using GDI functions:

1. Gets device context for the desktop via `GetDC(NULL)`
2. Creates a compatible memory DC and bitmap
3. Uses `BitBlt` to copy the screen contents
4. Constructs a BMP file in memory (header + pixel data)
5. Transfers the BMP via Mythic's download protocol

The screenshot is a full desktop capture at the current resolution.

### APIs Used

| API | Purpose | Library |
|-----|---------|---------|
| `GetDC` | Get desktop device context | user32 |
| `CreateCompatibleDC` | Create memory device context | gdi32 |
| `CreateCompatibleBitmap` | Create bitmap at screen dimensions | gdi32 |
| `SelectObject` | Select bitmap into memory DC | gdi32 |
| `BitBlt` | Copy screen contents to bitmap | gdi32 |
| `GetDIBits` | Extract pixel data from bitmap | gdi32 |
| `DeleteObject` | Clean up GDI objects | gdi32 |
| `ReleaseDC` | Release desktop DC | user32 |

## MITRE ATT&CK Mapping

- **T1113** - Screen Capture

## OPSEC Considerations

- Loads `user32.dll` and `gdi32.dll` if not already loaded
- GDI-based screen capture is a well-known technique monitored by some EDR products
- Screenshot files can be large (several MB for high-resolution displays)
