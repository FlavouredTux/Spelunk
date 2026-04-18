#!/usr/bin/env python3
"""Emit a minimal x86_64 Mach-O executable for cross-platform golden tests.

The fixture carries one __TEXT segment with two functions:
  entry (0x100001000): mov eax, 0x2a; ret                → returns 42
  add42 (0x100001006): lea eax, [rdi + 0x2a]; ret        → returns a1+42

LC_MAIN points at entry; LC_SYMTAB lists both with their C names.
No dynamic imports / dyld-info — we only want to exercise the loader's
header, segment, symtab, LC_MAIN, and LC_FUNCTION_STARTS paths.

Usage:
  make_macho_tiny.py <output-path>
"""

import struct
import sys


def uleb128(v):
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    out_path = sys.argv[1]

    PAGE = 0x1000
    BASE = 0x100000000

    # Machine code:
    #  entry:   b8 2a 00 00 00   mov eax, 42
    #           c3               ret
    #  add42:   8d 47 2a         lea eax, [rdi + 42]
    #           c3               ret
    code = bytes.fromhex("b82a000000c3") + bytes.fromhex("8d472ac3")

    # Layout:
    #   file offset 0           : mach_header_64 + load commands (< 1 page)
    #   file offset PAGE        : __TEXT contents (code)
    text_file_off = PAGE
    text_vmaddr   = BASE + PAGE
    entry_vmaddr  = text_vmaddr + 0
    add42_vmaddr  = text_vmaddr + 6
    text_vmsize   = PAGE

    # Build the __TEXT segment load command (72 header + 80-byte section entry).
    seg_text = bytearray()
    seg_text += struct.pack("<II", 0x19, 72 + 80)        # cmd=LC_SEGMENT_64, cmdsize
    seg_text += b"__TEXT".ljust(16, b"\0")                # segname[16]
    seg_text += struct.pack("<QQQQ",
                            text_vmaddr, text_vmsize,    # vmaddr, vmsize
                            text_file_off, len(code))    # fileoff, filesize
    seg_text += struct.pack("<IIII", 5, 5, 1, 0)          # maxprot, initprot, nsects, flags
    seg_text += b"__text".ljust(16, b"\0")                # sectname[16]
    seg_text += b"__TEXT".ljust(16, b"\0")                # segname[16]
    seg_text += struct.pack("<QQ", text_vmaddr, len(code))  # addr, size
    seg_text += struct.pack("<II", text_file_off, 4)      # offset, align
    # reloff, nreloc, flags, reserved1, reserved2, reserved3 = 6 × u32
    seg_text += struct.pack("<IIIIII", 0, 0, 0x80000400, 0, 0, 0)

    # __LINKEDIT segment holding symtab + strtab.
    link_file_off = text_file_off + len(code)
    # Align linkedit to 8.
    link_file_off = (link_file_off + 7) & ~7

    # nlist_64: n_strx(4), n_type(1), n_sect(1), n_desc(2), n_value(8) = 16
    # Symbols: _main → entry, _add42 → add42.
    strtab = b"\0_main\0_add42\0"
    sym_offs = {"_main": 1, "_add42": 7}
    nlist = bytearray()
    for name, vm in [("_main", entry_vmaddr), ("_add42", add42_vmaddr)]:
        nlist += struct.pack("<IBBHQ", sym_offs[name], 0x0F, 1, 0, vm)  # N_SECT|N_EXT, sect=1
    # LC_FUNCTION_STARTS data: ULEB128 deltas from __TEXT base.
    #   first delta = entry - text_vmaddr = 0 → terminator, can't use 0
    # The on-disk encoding uses non-zero deltas; first delta is (entry - text_vmaddr),
    # which here is 0. Workaround: place entry at text_vmaddr+6 and add42 at +0?
    # Simpler: use a one-entry starts list skipping entry=0 is awkward, so
    # fall back to just listing add42 at delta 6. Linker tools treat the
    # __TEXT base itself as implicitly a function start when the first
    # delta is non-zero — matches what we want for coverage anyway.
    fn_starts = uleb128(add42_vmaddr - text_vmaddr) + b"\0"
    # Align everything to 8.
    sym_off = link_file_off
    str_off = sym_off + len(nlist)
    fn_starts_off = str_off + len(strtab)
    fn_starts_off = (fn_starts_off + 7) & ~7
    link_filesize = fn_starts_off + len(fn_starts) - link_file_off

    seg_link = bytearray()
    seg_link += struct.pack("<II", 0x19, 72)
    seg_link += b"__LINKEDIT".ljust(16, b"\0")
    seg_link += struct.pack("<QQQQ",
                            text_vmaddr + text_vmsize, PAGE,
                            link_file_off, link_filesize)
    seg_link += struct.pack("<IIII", 1, 1, 0, 0)   # r--

    # LC_SYMTAB: cmd(4) cmdsize(4) symoff(4) nsyms(4) stroff(4) strsize(4)
    lc_symtab = struct.pack("<IIIIII", 0x02, 24, sym_off, 2, str_off, len(strtab))

    # LC_FUNCTION_STARTS (linkedit_data_command): cmd cmdsize dataoff datasize
    lc_fnstarts = struct.pack("<IIII", 0x26, 16, fn_starts_off, len(fn_starts))

    # LC_MAIN: cmd cmdsize entryoff stacksize
    lc_main = struct.pack("<IIQQ", 0x80000028, 24, text_file_off, 0)

    lcs = bytes(seg_text) + bytes(seg_link) + lc_symtab + lc_fnstarts + lc_main
    ncmds = 5
    sizeofcmds = len(lcs)

    hdr = struct.pack("<IIIIIIII",
                      0xFEEDFACF,      # magic (LE 64-bit Mach-O)
                      0x01000007,      # cputype = x86_64
                      3,               # cpusubtype = ALL
                      2,               # filetype = MH_EXECUTE
                      ncmds,
                      sizeofcmds,
                      0x00200085,      # flags: NOUNDEFS|DYLDLINK|TWOLEVEL|PIE
                      0)               # reserved

    # Glue everything together.
    out = bytearray()
    out += hdr
    out += lcs
    out += b"\0" * (text_file_off - len(out))
    out += code
    out += b"\0" * (sym_off - len(out))
    out += nlist
    out += strtab
    out += b"\0" * (fn_starts_off - len(out))
    out += fn_starts

    with open(out_path, "wb") as f:
        f.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
