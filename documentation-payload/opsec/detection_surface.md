+++
title = "Detection Surface"
chapter = false
weight = 10
+++

## Detection Surface Analysis

### Process-Level Indicators

| Indicator | Detail | Mitigation |
|-----------|--------|------------|
| Unbacked executable memory | Shellcode runs from `VirtualAlloc`'d RX region | Use Crystal Palace loader to stomp a legitimate module |
| Thread start address | Thread origin in non-image memory | Crystal Palace maps shellcode over a real DLL's `.text` |
| No module backing | VAD entry shows `Private` not `Image` | Module stomping via UDRL |
| Periodic network callbacks | Beaconing pattern in WinHTTP traffic | Increase jitter, use HTTPX with malleable profile |

### Network Indicators

| Indicator | Detail | Mitigation |
|-----------|--------|------------|
| Regular callback intervals | Even with jitter, statistical analysis can detect beaconing | Set high jitter (40%+), vary callback intervals |
| Base64 in HTTP | GET query parameters contain base64 data | Use HTTPX transforms (netbios, xor, prepend/append) |
| TLS fingerprint | WinHTTP JA3 hash | Known WinHTTP fingerprint; consider environment match |
| Unusual User-Agent | Default UA may not match target | Configure UA to match target browser/OS |

### ETW and Event Log Coverage

| Source | Event | Triggered By |
|--------|-------|-------------|
| Sysmon Event ID 1 | Process creation | `shell`, `execute_assembly` (spawned process) |
| Sysmon Event ID 8 | CreateRemoteThread | `shinject`/`migrate` (CRT and Section injection techniques) |
| Sysmon Event ID 10 | Process access | `shinject`/`migrate` (OpenProcess - all injection techniques) |
| Security Event 4688 | Process creation | Any command spawning a child process |
| Security Event 7045 | Service installed | `jump_psexec` |
| System Event 7040 | Service config changed | `jump_scshell` |
| WMI Activity Log | WMI operation | `jump_wmiexec` |
| PowerShell Script Block | Script execution | `execute_assembly` (if CLR triggers PS logging) |

### Memory Indicators

| Indicator | Scan Type | Detail |
|-----------|-----------|--------|
| AMSI bypass | Runtime scan | No built-in AMSI bypass - execute_assembly loads CLR which triggers AMSI |
| PE headers in memory | Memory scan | Assembly loaded via CLR may have PE headers in heap |
| Shellcode patterns | Signature scan | PIC bootstrap stub has identifiable patterns (PEB walk, hash loop) |
| Unmasked keys during execution | Memory scan | AES key and UUIDs are plaintext while agent is actively processing tasks |

### Feature-Specific Indicators

| Feature | Indicator | Detail |
|---------|-----------|--------|
| `socks` | Behavioral shift | Agent sleep drops to 0ms during active proxy - continuous HTTP callbacks |
| `socks` | Outbound TCP connections | Agent creates TCP connections to arbitrary hosts on behalf of SOCKS clients |
| `ssh` | Child process | Spawns `ssh.exe` with pipe-redirected stdin/stdout, command line contains target host |
| `rpfwd` | Listening socket | Agent binds a local TCP port, visible via `netstat` or Sysmon Event ID 3 |
| `keylog` | API polling | `GetAsyncKeyState` called in tight loop, blocks beacon for capture duration |
| `browserpivot` | Local HTTP proxy | Creates listening socket for browser session proxying via WinINet |
| `link` (SMB) | Named pipe DACL | Pipe created with Everyone SID full access - any local user can connect |
| `link` (SMB) | Pipe enumeration | Named pipe visible via `\\.\pipe\*` enumeration (Sysmon Event ID 17/18) |
| `execute_assembly` | CLR loading | Loads .NET CLR into process, triggers AMSI scanning of loaded assemblies |
| Draugr | Module load | KernelBase.dll `.text` section scanned for `JMP [RBX]` gadgets at init |
| Draugr | RUNTIME_FUNCTION parsing | Parses unwind info for each spoofed frame's target function at init |
| Draugr (custom) | Profile mismatch | Custom frame sequence may not match expected stacks for the stomped module's thread pattern |
| Injection (APC) | Suspended thread | Early Bird creates suspended thread + `QueueUserAPC` - cross-process APC monitored by some EDRs |
| Injection (Section) | Cross-process mapping | `NtMapViewOfSection` into remote process + `CreateRemoteThread` - no `VirtualAllocEx`/`WriteProcessMemory` but mapping is observable |
| Sleep Mask (Full Image) | VirtualProtect flip | `VirtualProtect` RW↔RX on shellcode region generates ETW events each sleep cycle |
| Sleep Mask (Heap) | HeapWalk enumeration | Process heap enumeration via `HeapWalk` - unusual API pattern for most processes |

### Recommendations

1. **Always use Crystal Palace** for production deployments to eliminate unbacked memory indicators
2. **Configure HTTPX** with transforms matching legitimate target traffic patterns
3. **Set jitter to 40%+** to break statistical beaconing detection
4. **Match User-Agent** to the target environment's browser
5. **Use debug builds only in isolated test environments** - they contain identifying strings
6. **Consider kill dates** for time-limited operations to ensure agent self-termination
7. **Match Draugr profile to injection context** - if using Crystal Palace to stomp a specific DLL, build a custom spoof profile that mimics thread stacks typical for that module (use Process Hacker on a reference system to observe real stacks)
8. **Use the [Arsenal Kit](https://github.com/Whispergate/Starburst.ArsenalKit) to tune injection and masking** - switch injection technique from `crt` to `section` to eliminate `VirtualAllocEx`/`WriteProcessMemory` telemetry, or use `apc` to avoid `CreateRemoteThread` events. Select sleep mask based on target's scanning capability
9. **Write custom Arsenal Kit modules** for high-value targets - the `CUSTOM` slots in each module provide a working baseline to build on
