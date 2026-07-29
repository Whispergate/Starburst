# Starburst.CrystalKit

Crystal Palace integration for the Starburst agent. Produces obfuscated position-independent shellcode
by linking Starburst's raw PIC output through a Crystal Palace loader.

## How It Works

Starburst compiles to raw shellcode (`.bin`). When the output type is set to "Crystal Palace shellcode",
the builder wraps the raw shellcode in a minimal DLL stub (`sc_stub.c`), then passes it to Crystal
Palace's `cpl link` command with the loader's `.spec` file. The result is a fully self-contained PIC
blob with the loader's reflective capabilities baked in.

```
Raw Starburst shellcode (.bin)
    ↓
DLL stub wrapper (sc_stub.c)
    ↓  ld -r -b binary (embed shellcode as .data)
    ↓  gcc -shared (link stub + payload into DLL)
    ↓
Crystal Palace `cpl link`
    ↓  loader.spec defines the final PIC layout
    ↓
Final PIC shellcode with loader
```

Post-exploitation payloads (execute_assembly, execute_pic, shinject) follow the same flow using the
post-ex loader, which additionally accepts an arguments buffer (`%ARGFILE`).

## Setup

1. Obtain Crystal Palace from https://tradecraftgarden.org
2. Place the following files in `crystal-linker/`:
   - `crystalpalace.jar`
   - `cpl` (wrapper script, optional)
3. Build the default loaders:
   ```
   cd default && mkdir -p bin && make x64 && make x86
   cd ../post-ex && mkdir -p bin && make x64 && make x86
   ```

## Requirements

- Java 11+ (OpenJDK)
- MinGW-w64 cross-compiler toolchain:
  - `x86_64-w64-mingw32-gcc` (x64 builds)
  - `i686-w64-mingw32-gcc` (x86 builds)
  - On Windows: MSYS2 with `mingw-w64-x86_64-toolchain` and `mingw-w64-i686-toolchain` packages
- NASM (for Starburst agent assembly stubs)

## Directory Structure

```
crystal-palace/
  crystal-linker/          Crystal Palace JAR + wrapper (operator-supplied)
    crystalpalace.jar
    README

  default/                 Default UDRL loader (wraps raw shellcode)
    src/loader.c           PIC loader with ROR13 dynamic function resolution
    loader.spec            Crystal Palace linker script
    Makefile               Compiles loader to COFF object (bin/loader.{arch}.o)

  post-ex/                 Post-exploitation loader (wraps shellcode + args)
    src/loader-postex.c    PIC loader with argument buffer support
    loader.spec            Crystal Palace linker script (references %ARGFILE)
    Makefile               Compiles post-ex loader to COFF object

  README.md                This file
```

## Custom UDRL

Operators can upload a custom UDRL as a ZIP file when building a payload through the Mythic UI.
Enable the **"Use custom Crystal Palace UDRL"** toggle in the UDRL build parameter group, then
upload a ZIP archive.

### Supported Archive Layouts

The builder auto-discovers `Makefile` and `loader.spec` locations, so multiple archive structures
are supported:

**Flat layout** (loader.spec at archive root):
```
my-loader.zip
  Makefile
  loader.spec
  src/
    loader.c
```

**Nested layout** (subdirectories with their own Makefile and loader.spec):
```
my-kit.zip
  Makefile              ← top-level Makefile that delegates to subdirs
  loader/
    Makefile
    loader.spec
    src/
      loader.c
  postex-loader/
    Makefile
    loader.spec
    src/
      loader-postex.c
```

**Single-loader archive** (only one loader type present):
```
my-loader.zip
  loader/
    Makefile
    loader.spec
    src/
      loader.c
```

### Role Selection

When an archive contains multiple subdirectories with `loader.spec` files, the builder selects
the appropriate one based on the context:

- **Loader role** (payload build): prefers a directory named exactly `loader`, otherwise picks
  the first non-postex directory
- **Post-ex role** (post-exploitation operations): prefers directories containing `postex`,
  `post-ex`, or `post_ex` in the name

### Build Process

1. Archive is extracted to a temporary directory
2. Builder finds the Makefile directory (top-level if present, otherwise first subdir with Makefile)
3. `make {arch}` is run (where arch is `x64` or `x86`)
4. Builder finds the `loader.spec` for the appropriate role
5. Starburst shellcode is wrapped in a DLL stub and linked via `cpl link` with the discovered spec
6. Temporary files are cleaned up

### Writing a Custom UDRL

Your loader must:
- Compile to a COFF object via `make x64` and/or `make x86`
- Include a `loader.spec` Crystal Palace linker script
- Be compatible with `cpl link` (DLL input → PIC output)

The DLL stub (`sc_stub.c`) provides two symbols to your loader:
- `sc_payload` - start of the embedded Starburst shellcode
- `sc_payload_end` - end of the embedded shellcode

## Custom Post-Ex UDRL

Operators can also upload a custom post-ex UDRL. This loader is used for post-exploitation
operations (execute_assembly, execute_pic, shinject) and receives an additional argument buffer.

Enable **"Use custom post-ex UDRL"** in the UDRL build parameter group and upload a ZIP archive.
The same archive layout rules apply - the builder will look for a directory with `postex` in the
name when selecting the spec file.

Custom post-ex UDRLs are stored per-payload and persist for the lifetime of the callback, so
post-ex operations use your custom loader rather than the default.

### Post-Ex Loader Requirements

Your post-ex loader.spec must accept `%ARGFILE` - a Crystal Palace variable pointing to the
arguments binary. The default post-ex loader demonstrates this pattern.

## Architectures

Both x64 and x86 are supported. The builder passes the target architecture to `make` and selects
the appropriate cross-compiler automatically:

| Architecture | Compiler | MSYS2 Package |
|-------------|----------|---------------|
| x64 | `x86_64-w64-mingw32-gcc` | `mingw-w64-x86_64-toolchain` |
| x86 | `i686-w64-mingw32-gcc` | `mingw-w64-i686-toolchain` |

On Windows, the builder adds MSYS2 bin directories to PATH automatically. On Linux, the
cross-compilers must be available on PATH (installed via package manager).

## Troubleshooting

**"Crystal Palace not installed"** - `crystalpalace.jar` not found in `crystal-linker/`. Download
from https://tradecraftgarden.org and place it there.

**"Custom UDRL compile failed"** - `make {arch}` returned an error. Check that your Makefile
supports the `x64` and `x86` targets and that the cross-compiler is installed.

**"No loader.spec found"** - The builder couldn't locate a `loader.spec` in your archive. Verify
your ZIP structure matches one of the supported layouts above.

**"DLL stub wrapping failed"** - The shellcode-to-DLL wrapping step failed. Check that `ld` and
`objcopy` are available (part of the MinGW-w64 toolchain).

**x86 build errors with `__udivdi3`** - 64-bit division in `-nostdlib` x86 builds requires
`libgcc`. Avoid 64-bit arithmetic in x86 loader code, or link against libgcc.
