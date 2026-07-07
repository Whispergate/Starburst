+++
title = "starburst"
chapter = true
weight = 5
pre = "<b>1. </b>"
+++

![Starburst](/agents/starburst/starburst.svg?width=600px)

## Summary

Starburst is a Windows PIC (Position-Independent Code) agent for [Mythic](https://github.com/its-a-feature/Mythic), built on the [Stardust](https://github.com/Cracked5pider/Stardust) shellcode framework. It compiles to raw x64/x86 shellcode that runs entirely from memory with no PE on disk.

### Key Features

- True position-independent shellcode - runs from any RWX/RX allocation
- Crystal Palace compatible (entry at offset 0)
- FNV1a hash-based API resolution with no import table
- AES256-CBC + HMAC-SHA256 encryption via Windows BCrypt APIs
- Compact binary TLV wire protocol with Python translation container
- Modular command system - commands compiled in/out at build time
- Indirect syscall table (HellsGate/HalosGate SSN extraction)
- Sleep-time sensitive data masking (XOR key material during sleep)
- 58 built-in commands covering file ops, process management, code execution, lateral movement, token manipulation, and P2P linking
- SMB named pipe P2P transport with delegate message relay
- TCP P2P transport with delegate message relay (connect/disconnect commands)
- Browser pivoting (WinINet session inheritance)
- Process migration with configurable spawn target
- SOCKS5 proxy integration
- SSH session deployment
- Reverse port forwarding
- Keystroke logging
- DLL blocking policy for child processes
- Desktop/window station enumeration
- File timestamp modification (timestomp)
- Draugr N-frame call stack spoofing with operator-customizable profiles
- [Arsenal Kit](https://github.com/Whispergate/Starburst.ArsenalKit) - modular, operator-swappable injection techniques (CRT/APC/Section/Custom), sleep masks (Default/Full Image/Heap/Custom), and call stack spoof profiles via compile-time selection headers
- Multiple output formats: raw shellcode, EXE, DLL, Windows service

### Authors

- [@Lavender-exe](https://github.com/Lavender-exe)

{{% children %}}
