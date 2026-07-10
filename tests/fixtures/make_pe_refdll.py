#!/usr/bin/env python3
"""Emit a tiny x86_64 PE32+ DLL whose only point is its export table.

Used as a *reference DLL* for `ember --recover-imports`: the recovery
base-solves harvested IAT pointers against a reference DLL's export
RVA→name map. This fixture has five named exports at fixed RVAs and a
preferred image base (0x180000000) deliberately different from the base
the companion dump (make_iat_dump.py) loads it at - so the test actually
exercises base-solving rather than a trivial identity match.

Exports (RVA : name):
    0x1000 : OpenThing
    0x1040 : ReadThing
    0x1080 : WriteThing
    0x10c0 : CloseThing
    0x1100 : FlushThing

Usage:
    make_pe_refdll.py <output-path>
"""

import struct
import sys


IMAGE_BASE     = 0x180000000
SECTION_ALIGN  = 0x1000
FILE_ALIGN     = 0x200
MACHINE_AMD64  = 0x8664

IMAGE_FILE_EXECUTABLE_IMAGE    = 0x0002
IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020
IMAGE_FILE_DLL                 = 0x2000

SCN_CNT_CODE        = 0x00000020
SCN_CNT_INITIALIZED = 0x00000040
SCN_MEM_EXECUTE     = 0x20000000
SCN_MEM_READ        = 0x40000000

EXPORTS = [
    (0x1000, b"OpenThing"),
    (0x1040, b"ReadThing"),
    (0x1080, b"WriteThing"),
    (0x10c0, b"CloseThing"),
    (0x1100, b"FlushThing"),
]


def align(v, a):
    return (v + a - 1) & ~(a - 1)


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    out_path = sys.argv[1]

    rva_text   = 0x1000
    rva_rdata  = 0x2000
    foff_text  = FILE_ALIGN
    foff_rdata = foff_text + FILE_ALIGN

    # ---- .text: a NOP sled covering every export RVA --------------------
    text = bytearray(b"\x90" * 0x200)
    text_virt_size = len(text)

    # ---- .rdata: the export directory -----------------------------------
    rdata = bytearray()

    def here():
        return rva_rdata + len(rdata)

    export_dir_off = len(rdata)
    rdata += b"\x00" * 40

    dllname_rva = here()
    rdata += b"refdll.dll\x00"
    while len(rdata) % 4 != 0:
        rdata.append(0)

    # EAT: one func RVA per export, in declared order.
    eat_rva = here()
    for rva, _ in EXPORTS:
        rdata += struct.pack("<I", rva)

    # ENT: name RVAs (filled after the strings are laid out).
    ent_rva = here()
    rdata += b"\x00" * (4 * len(EXPORTS))

    # EOT: ordinal (EAT index) per name, ascending.
    eot_rva = here()
    for i in range(len(EXPORTS)):
        rdata += struct.pack("<H", i)
    while len(rdata) % 2 != 0:
        rdata.append(0)

    # Name strings.
    name_rvas = []
    for _, name in EXPORTS:
        name_rvas.append(here())
        rdata += name + b"\x00"
    while len(rdata) % 4 != 0:
        rdata.append(0)

    # Back-patch ENT with each name RVA.
    for i, nrva in enumerate(name_rvas):
        struct.pack_into("<I", rdata, (ent_rva - rva_rdata) + i * 4, nrva)

    # Back-patch the export directory header.
    struct.pack_into("<IIHHIIIIIII", rdata, export_dir_off,
                     0, 0, 0, 0,
                     dllname_rva,
                     1,                  # ordinal base
                     len(EXPORTS),       # NumberOfFunctions
                     len(EXPORTS),       # NumberOfNames
                     eat_rva, ent_rva, eot_rva)

    rdata_virt_size = len(rdata)

    # ---- offsets + sizes ------------------------------------------------
    text_raw_size  = align(len(text),  FILE_ALIGN)
    rdata_raw_size = align(len(rdata), FILE_ALIGN)
    file_end       = foff_rdata + rdata_raw_size

    size_of_image   = align(rva_rdata + rdata_virt_size, SECTION_ALIGN)
    size_of_headers = FILE_ALIGN

    # ---- headers --------------------------------------------------------
    dos = bytearray(b"\x00" * 0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)

    nt_sig = b"PE\x00\x00"
    coff = struct.pack("<HHIIIHH",
                       MACHINE_AMD64, 2, 0, 0, 0, 240,
                       IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE
                       | IMAGE_FILE_DLL)

    opt = bytearray()
    opt += struct.pack("<H", 0x20b)
    opt += struct.pack("<BB", 14, 0)
    opt += struct.pack("<III", text_raw_size, rdata_raw_size, 0)
    opt += struct.pack("<I", 0)                  # AddressOfEntryPoint (none)
    opt += struct.pack("<I", rva_text)
    opt += struct.pack("<Q", IMAGE_BASE)
    opt += struct.pack("<II", SECTION_ALIGN, FILE_ALIGN)
    opt += struct.pack("<HHHHHH", 6, 0, 0, 0, 6, 0)
    opt += struct.pack("<I", 0)
    opt += struct.pack("<III", size_of_image, size_of_headers, 0)
    opt += struct.pack("<HH", 3, 0x8160)
    opt += struct.pack("<QQQQ", 0x100000, 0x1000, 0x100000, 0x1000)
    opt += struct.pack("<II", 0, 16)
    data_dirs = [(0, 0)] * 16
    data_dirs[0] = (rva_rdata + export_dir_off, 40)   # Export directory
    for va, sz in data_dirs:
        opt += struct.pack("<II", va, sz)
    assert len(opt) == 240, len(opt)

    def section_hdr(name, vsize, vrva, rsize, roff, chars):
        return (name.ljust(8, b"\0")
              + struct.pack("<IIII", vsize, vrva, rsize, roff)
              + struct.pack("<IIHHI", 0, 0, 0, 0, chars))

    sec_tab = bytearray()
    sec_tab += section_hdr(b".text",  text_virt_size,  rva_text,  text_raw_size,  foff_text,
                           SCN_CNT_CODE | SCN_MEM_EXECUTE | SCN_MEM_READ)
    sec_tab += section_hdr(b".rdata", rdata_virt_size, rva_rdata, rdata_raw_size, foff_rdata,
                           SCN_CNT_INITIALIZED | SCN_MEM_READ)

    out = bytearray(file_end)
    out[0:0x40]          = dos
    out[0x40:0x44]       = nt_sig
    out[0x44:0x58]       = coff
    out[0x58:0x58 + 240] = opt
    out[0x58 + 240:0x58 + 240 + len(sec_tab)] = sec_tab
    out[foff_text :foff_text  + len(text)]  = text
    out[foff_rdata:foff_rdata + len(rdata)] = rdata

    with open(out_path, "wb") as f:
        f.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
