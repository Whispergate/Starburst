#!/usr/bin/env python3
"""
Embed a compiled sleepmask-vs .o file as a C header for Starburst.

Usage:
    python3 embed_sleepmask.py <path/to/sleepmask.x64.o> [output_header]

Generates include/evasion/sleepmask_vs_data.h (or custom output path)
with the COFF bytes as a static const array.
"""
import sys
import os

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <sleepmask.o> [output.h]", file=sys.stderr)
        sys.exit(1)

    input_path = sys.argv[1]
    if len(sys.argv) >= 3:
        output_path = sys.argv[2]
    else:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        output_path = os.path.join(script_dir, "..", "include", "evasion", "sleepmask_vs_data.h")

    with open(input_path, "rb") as f:
        data = f.read()

    hex_vals = ", ".join(f"0x{b:02x}" for b in data)

    with open(output_path, "w") as f:
        f.write("#ifndef STARBURST_SLEEPMASK_VS_DATA_H\n")
        f.write("#define STARBURST_SLEEPMASK_VS_DATA_H\n")
        f.write("#define SLEEPMASK_VS_COFF_DATA_DEFINED\n")
        f.write(f"static const uint8_t SLEEPMASK_VS_COFF[] = {{ {hex_vals} }};\n")
        f.write(f"static const uint32_t SLEEPMASK_VS_COFF_SIZE = {len(data)};\n")
        f.write("#endif\n")

    print(f"Embedded {len(data)} bytes from {input_path} -> {output_path}")

if __name__ == "__main__":
    main()
