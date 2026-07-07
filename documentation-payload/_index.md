+++
title = "Starburst"
chapter = true
weight = 5
+++

# Starburst

## Windows PIC Agent

Starburst is a Windows post-exploitation agent built on the Stardust position-independent code (PIC) framework. It compiles to raw shellcode with no CRT dependencies and is fully Crystal Palace compatible.

Starburst includes an [Arsenal Kit](https://github.com/Whispergate/Starburst.ArsenalKit) with operator-swappable injection techniques, sleep masks, and call stack spoof profiles - selected at build time via Mythic parameters or `config.h` defines.

{{% children %}}
