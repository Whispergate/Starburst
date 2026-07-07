# Crystal Palace Integration

Starburst uses Crystal Palace as its primary custom loader for generating
obfuscated position-independent shellcode wrappers.

## Setup

1. Obtain Crystal Palace from https://tradecraftgarden.org
2. Place the following files in `crystal-linker/`:
   - `crystalpalace.jar`
   - `cpl` (wrapper script)
3. Compile the default loaders:
   ```
   cd default && mkdir -p bin && make x64 && make x86
   cd ../post-ex && mkdir -p bin && make x64 && make x86
   ```

## Requirements

- Java 11+ (OpenJDK)
- MinGW-w64

## Directory Structure

```
crystal-palace/
  default/           Default UDRL loader (wraps raw shellcode)
    src/loader.c     PIC loader with ROR13 DFR
    loader.spec      Crystal Palace linker script
    Makefile          Compiles loader to COFF object

  post-ex/           Post-exploitation loader (wraps shellcode + args)
    src/loader-postex.c
    loader.spec
    Makefile

  crystal-linker/    Crystal Palace JAR + wrapper (operator-supplied)
```

## Custom UDRL

Operators can upload a custom UDRL as a ZIP file when building a payload.
The ZIP must contain:
- `Makefile` (produces COFF object in `bin/`)
- `loader.spec` (Crystal Palace linker script)
- `src/` directory with loader source

Custom UDRLs are compiled and linked at build time.
Custom post-ex UDRLs are stored per-payload for runtime use.
