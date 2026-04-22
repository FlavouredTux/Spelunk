#!/usr/bin/env python3
"""Emit a tiny malformed-for-Ember PE32 image.

The file is structurally PE, but uses the PE32 optional-header magic so
the loader must reject it with the explicit PE32+ only error.
"""

import struct
import sys


def main() -> int:
    if len(sys.argv) != 2:
        return 2
    out_path = sys.argv[1]

    dos = bytearray(b"\x00" * 0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)

    coff = struct.pack("<HHIIIHH",
                       0x14C,  # i386
                       1,
                       0, 0, 0,
                       0xE0,
                       0x0002)

    opt = bytearray(b"\x00" * 0xE0)
    struct.pack_into("<H", opt, 0x00, 0x10B)  # PE32
    struct.pack_into("<I", opt, 0x10, 0x1000)  # entry RVA
    struct.pack_into("<I", opt, 0x1C, 0x400000)  # image base for PE32
    struct.pack_into("<I", opt, 0x38, 0x2000)  # size of image
    struct.pack_into("<I", opt, 0x3C, 0x200)   # size of headers
    struct.pack_into("<I", opt, 0x5C, 16)      # NumberOfRvaAndSizes

    sec = (b".text\0\0\0"
           + struct.pack("<IIII", 1, 0x1000, 0x200, 0x200)
           + struct.pack("<IIHHI", 0, 0, 0, 0, 0x60000020))

    out = bytearray(0x400)
    out[0:0x40] = dos
    out[0x40:0x44] = b"PE\x00\x00"
    out[0x44:0x58] = coff
    out[0x58:0x58 + len(opt)] = opt
    out[0x138:0x138 + len(sec)] = sec
    out[0x200] = 0xC3  # ret

    with open(out_path, "wb") as f:
        f.write(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
