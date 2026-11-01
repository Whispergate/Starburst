#!/usr/bin/env python3
"""
Generate dir32 fixup table for x86 PIC shellcode.

Links the x86 code at two different section bases, diffs the .text sections
to find all absolute address references, then:
  1. Appends a fixup table [count][offset_1][offset_2]... to the shellcode
  2. Patches the entry stub (bytes 2-5) with the offset to the fixup table
"""
import struct, sys, os, subprocess, tempfile, glob

def extract_text_section(exe_path):
    with open(exe_path, 'rb') as f:
        data = f.read()
    pe_off = struct.unpack_from('<I', data, 0x3C)[0]
    coff = pe_off + 4
    num_sec = struct.unpack_from('<H', data, coff + 2)[0]
    opt_size = struct.unpack_from('<H', data, coff + 16)[0]
    sec_base = coff + 20 + opt_size
    for i in range(num_sec):
        s = sec_base + i * 40
        name = data[s:s+8].rstrip(b'\0')
        if name == b'.text':
            raw_sz = struct.unpack_from('<I', data, s + 16)[0]
            raw_ptr = struct.unpack_from('<I', data, s + 20)[0]
            return data[raw_ptr:raw_ptr + raw_sz]
    raise RuntimeError("no .text section")


def main():
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} <obj_dir> <linker.ld> <output.bin>")
        sys.exit(1)

    obj_dir = sys.argv[1]
    linker_ld = sys.argv[2]
    output = sys.argv[3]

    objs = sorted(glob.glob(os.path.join(obj_dir, "*.x86.obj")))
    if not objs:
        print(f"[-] no .x86.obj in {obj_dir}", file=sys.stderr)
        sys.exit(1)

    gcc_dirs = sorted(glob.glob("/usr/lib/gcc/i686-w64-mingw32/*/include/c++"))
    inc = ""
    if gcc_dirs:
        d = gcc_dirs[-1]
        inc = f"-isystem {d} -isystem {d}/i686-w64-mingw32"

    cc = "clang -target i686-w64-mingw32"
    cflags = ("-Os -nostdlib -fno-asynchronous-unwind-tables -std=c++20 "
              "-fno-ident -fpack-struct=8 -falign-functions=1 -w -mno-sse "
              "-ffunction-sections -falign-jumps=1 -falign-labels=1 -fno-jump-tables "
              "-Wl,--enable-stdcall-fixup -masm=intel -fno-exceptions "
              "-fms-extensions")
    obj_str = " ".join(objs)

    delta = 0x10000

    with tempfile.TemporaryDirectory() as td:
        ld0 = os.path.join(td, "ld0.ld")
        ld1 = os.path.join(td, "ld1.ld")
        with open(linker_ld) as f:
            base_ld = f.read()

        with open(ld0, 'w') as f:
            f.write(base_ld)

        with open(ld1, 'w') as f:
            f.write("SECTIONS\n{\n    . = 0x%x;\n" % delta)
            idx = base_ld.find('.text')
            if idx >= 0:
                brace = base_ld.find('{', idx)
                f.write("    .text : " + base_ld[brace:])
            else:
                f.write(base_ld[base_ld.find('{'):])

        exe0 = os.path.join(td, "b0.exe")
        exe1 = os.path.join(td, "b1.exe")

        for exe, ld in [(exe0, ld0), (exe1, ld1)]:
            cmd = f"{cc} {obj_str} -o {exe} {cflags} -Wl,-T{ld} {inc}"
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if r.returncode != 0:
                ok = "section below image base" in r.stderr
                if not ok:
                    print(f"[-] link failed: {r.stderr[:500]}", file=sys.stderr)
                    sys.exit(1)

        t0 = extract_text_section(exe0)
        t1 = extract_text_section(exe1)
        if len(t0) != len(t1):
            print(f"[-] size mismatch {len(t0)} vs {len(t1)}", file=sys.stderr)
            sys.exit(1)

        text_size = len(t0)

        # find dir32 locations: 4-byte values that differ by exactly delta
        fixups = []
        for i in range(text_size - 3):
            v0 = struct.unpack_from('<I', t0, i)[0]
            v1 = struct.unpack_from('<I', t1, i)[0]
            if (v1 - v0) & 0xFFFFFFFF == delta:
                fixups.append(i)

        # deduplicate overlapping
        clean = []
        i = 0
        while i < len(fixups):
            clean.append(fixups[i])
            j = i + 1
            while j < len(fixups) and fixups[j] < fixups[i] + 4:
                j += 1
            i = j
        fixups = clean

        # exclude the entry stub placeholder at offset 2 (it's initially 0 in both)
        fixups = [f for f in fixups if f != 2]

        # build fixup table: [uint32 count][uint32 offset]...
        ftbl = struct.pack('<I', len(fixups))
        for off in fixups:
            ftbl += struct.pack('<I', off)

        # assemble output: base-0 shellcode + fixup table
        out = bytearray(t0)

        # patch bytes 2-5 with offset to fixup table (= text_size)
        struct.pack_into('<I', out, 2, text_size)

        out += ftbl

        with open(output, 'wb') as f:
            f.write(out)

        print(f"[fixups] {len(fixups)} dir32 fixups, "
              f"shellcode={text_size} + table={len(ftbl)} = {len(out)} bytes")


if __name__ == "__main__":
    main()
