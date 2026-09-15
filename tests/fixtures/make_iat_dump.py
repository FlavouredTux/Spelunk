#!/usr/bin/env python3
"""Emit a raw-region capture whose .rdata holds an unnamed IAT.

Companion to make_pe_refdll.py. Models a Scylla-style scrape of a process
that imported refdll.dll: the loader resolved each IAT slot to
`loaded_base + export_rva`, but the import directory is gone, so the slots
are just bare pointers. `spelunk --recover-imports` must base-solve them back
to dll!func names.

Writes two files next to the given manifest path:
    <manifest>              the --regions manifest
    <stem>.iat.bin         the captured .rdata bytes

Layout (one r-- region at 0x140002000, the dump's own .rdata):
    +0x00  qword 0x7ff8aabb1000   -> refdll.dll!OpenThing
    +0x08  qword 0x7ff8aabb1040   -> refdll.dll!ReadThing
    +0x10  qword 0x7ff8aabb1080   -> refdll.dll!WriteThing
    +0x18  qword 0x7ff8aabb10c0   -> refdll.dll!CloseThing
    +0x20  qword 0x7ff8aabb1100   -> refdll.dll!FlushThing
    +0x28  qword 0x7ff8aabb2000   -> in-band but not an export (noise; the
                                     cluster still solves by majority, this
                                     slot is left unnamed)
    +0x30  qword 0x0000000000000000  non-pointer (ignored)

The module loads at 0x7ff8aabb0000, deliberately different from the
reference DLL's preferred base (0x180000000), so naming requires solving
the base rather than matching it.

Usage:
    make_iat_dump.py <manifest-output-path>
"""

import os
import struct
import sys


REGION_VA   = 0x140002000
REGION_SIZE = 0x1000
LOADED_BASE = 0x7ff8aabb0000

SLOTS = [
    LOADED_BASE + 0x1000,
    LOADED_BASE + 0x1040,
    LOADED_BASE + 0x1080,
    LOADED_BASE + 0x10c0,
    LOADED_BASE + 0x1100,
    LOADED_BASE + 0x2000,   # in-band noise, not a real export RVA
    0x0000000000000000,     # non-pointer
]


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    manifest_path = sys.argv[1]

    blob = bytearray(REGION_SIZE)
    for i, v in enumerate(SLOTS):
        struct.pack_into("<Q", blob, i * 8, v)

    bin_name = os.path.basename(manifest_path) + ".iat.bin"
    bin_path = os.path.join(os.path.dirname(manifest_path), bin_name)
    with open(bin_path, "wb") as f:
        f.write(blob)

    manifest = (
        "# IAT capture for --recover-imports (see make_iat_dump.py)\n"
        f"0x{REGION_VA:x}  0x{REGION_SIZE:x}  r--  {bin_name}\n"
    )
    with open(manifest_path, "w") as f:
        f.write(manifest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
