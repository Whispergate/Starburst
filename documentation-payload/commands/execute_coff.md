+++
title = "execute_coff"
chapter = false
weight = 103
+++

## Summary

Execute a COFF (Common Object File Format) object file, commonly known as a BOF (Beacon Object File). Provides Beacon API compatibility for existing BOF tooling.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

- **file** (File, required) - COFF/BOF object file to execute.
- **arguments** (String, optional) - Packed arguments for the BOF. Can be hex-encoded or raw string. Default: empty.
- **entrypoint** (String, optional) - Entry point function name. Default: `go`.

### Usage

```
execute_coff
```

A file dialog will appear to select the BOF file.

## Detailed Summary

Implements a full COFF loader with Beacon API compatibility:

1. **Parse COFF** - Reads section headers, symbol table, and relocation entries from the object file
2. **Allocate memory** - Allocates RW memory for each section, copies section data
3. **Resolve symbols** - Maps Beacon API function names to internal implementations
4. **Apply relocations** - Processes COFF relocations to fix up addresses
5. **Execute** - Changes memory protection to RX and calls the entry point function
6. **Collect output** - Beacon API output calls (`BeaconPrintf`, `BeaconOutput`) are captured and returned

### Supported Beacon APIs

| API | Description |
|-----|-------------|
| `BeaconPrintf` | Formatted string output |
| `BeaconOutput` | Raw data output |
| `BeaconDataParse` | Initialize argument parser |
| `BeaconDataInt` | Read 4-byte integer from args |
| `BeaconDataShort` | Read 2-byte integer from args |
| `BeaconDataLength` | Get remaining args length |
| `BeaconDataExtract` | Read length-prefixed string |
| `BeaconFormatAlloc` | Allocate format buffer |
| `BeaconFormatReset` | Reset format buffer |
| `BeaconFormatFree` | Free format buffer |
| `BeaconFormatAppend` | Append raw data |
| `BeaconFormatPrintf` | Append formatted string |
| `BeaconFormatToString` | Get formatted buffer |
| `BeaconFormatInt` | Append 4-byte integer |

### Instance Access

BOF callbacks access the agent's instance struct via `TEB.ArbitraryUserPointer` (`gs:[0x28]` on x64). Before calling the BOF entry point, the loader stores the instance pointer in this field and restores the original value after execution.

## MITRE ATT&CK Mapping

- **T1106** - Native API

## OPSEC Considerations

- BOFs execute in the agent's thread - a crashing BOF will crash the agent
- No process creation required - stealthier than `shell` for many operations
- Memory allocations for COFF sections may be visible to memory scanners
- BOF memory is freed after execution

## Limitations

- x64 BOFs only (when agent is x64)
- BOF must follow the standard Beacon API conventions
- No support for BOFs that require dynamic function resolution beyond the provided Beacon API set
