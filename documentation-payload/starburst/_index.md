+++
title = "Starburst"
chapter = true
weight = 5
+++

## Summary

Starburst is a Windows PIC (Position-Independent Code) agent for [Mythic](https://github.com/its-a-feature/Mythic), built on the [Stardust](https://github.com/Cracked5pider/Stardust) shellcode framework. It compiles to raw x64/x86 shellcode that runs entirely from memory with no PE on disk.

### Key Features

- True position-independent shellcode - runs from any RWX/RX allocation (x64 and x86)
- CrystalKit - Crystal Palace integration with custom UDRL/post-ex loader support, flexible archive handling compatible with third-party kits (Picollo, etc.)
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
- [Arsenal Kit](https://github.com/Whispergate/Starburst.ArsenalKit) - operator customization kit: compile-time injection techniques (CRT/APC/Section/Custom), sleep masks (Default/Full Image/Heap/Custom), call stack spoof profiles (5 pre-built + custom), artifact wrappers (EXE/DLL/SVC with pipe/fiber/APC-self/callback bypass), loader kit (module stomping + DLL sideloading), resource kit (PowerShell/HTA/VBS/Python/C#/MSBuild stagers), and operator utilities
- Forge compatible - execute_coff, execute_assembly, execute_pic, and shinject support file-at-execution-time via Default/New parameter groups
- Multiple output formats: raw shellcode, EXE, DLL, Windows service

### Authors

- [@Lavender-exe](https://github.com/Lavender-exe)

## Table of Contents

{{% children %}}
