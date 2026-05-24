#!/usr/bin/env python3
"""Emit a tiny Mach-O whose hidden function is named only by compact unwind."""

import struct
import sys


def align(v, a):
    return (v + a - 1) & ~(a - 1)


def align8(v):
    return align(v, 8)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: make_macho_compact_unwind.py <output-path>", file=sys.stderr)
        return 2

    out_path = sys.argv[1]
    PAGE = 0x1000
    BASE = 0x100000000
    text_file_off = PAGE
    link_file_off = PAGE * 2
    text_vmaddr = BASE + PAGE
    main_va = text_vmaddr
    hidden_va = text_vmaddr + 6

    code = bytes.fromhex("b801000000c3") + bytes.fromhex("b82a000000c3")

    # Minimal Apple compact-unwind v1:
    # header + two first-level entries (one real group, one sentinel) +
    # one regular second-level page with two function starts.
    index_off = 28
    index_count = 2
    page_off = index_off + index_count * 12
    unwind = bytearray()
    unwind += struct.pack("<IIIIIII", 1, 0, 0, 0, 0, index_off, index_count)
    unwind += struct.pack("<III", 0, page_off, 0)
    unwind += struct.pack("<III", len(code), 0, 0)
    unwind += struct.pack("<IHH", 2, 8, 2)
    unwind += struct.pack("<II", main_va - text_vmaddr, 0)
    unwind += struct.pack("<II", hidden_va - text_vmaddr, 0)

    unwind_off = align8(len(code))
    text_filesize = unwind_off + len(unwind)

    seg_text = bytearray()
    seg_text += struct.pack("<II", 0x19, 72 + 2 * 80)
    seg_text += b"__TEXT".ljust(16, b"\0")
    seg_text += struct.pack("<QQQQ", text_vmaddr, PAGE, text_file_off, text_filesize)
    seg_text += struct.pack("<IIII", 5, 5, 2, 0)
    seg_text += b"__text".ljust(16, b"\0")
    seg_text += b"__TEXT".ljust(16, b"\0")
    seg_text += struct.pack("<QQ", text_vmaddr, len(code))
    seg_text += struct.pack("<II", text_file_off, 4)
    seg_text += struct.pack("<IIIIII", 0, 0, 0x80000400, 0, 0, 0)
    seg_text += b"__unwind_info".ljust(16, b"\0")
    seg_text += b"__TEXT".ljust(16, b"\0")
    seg_text += struct.pack("<QQ", text_vmaddr + unwind_off, len(unwind))
    seg_text += struct.pack("<II", text_file_off + unwind_off, 3)
    seg_text += struct.pack("<IIIIII", 0, 0, 0, 0, 0, 0)

    strings = bytearray(b"\0")
    main_name_off = len(strings)
    strings += b"_main\0"
    strtab = bytes(strings)
    nlist = struct.pack("<IBBHQ", main_name_off, 0x0F, 1, 0, main_va)
    sym_off = link_file_off
    str_off = sym_off + len(nlist)
    link_filesize = len(nlist) + len(strtab)

    seg_link = bytearray()
    seg_link += struct.pack("<II", 0x19, 72)
    seg_link += b"__LINKEDIT".ljust(16, b"\0")
    seg_link += struct.pack("<QQQQ", text_vmaddr + PAGE, PAGE, link_file_off, link_filesize)
    seg_link += struct.pack("<IIII", 1, 1, 0, 0)

    lc_symtab = struct.pack("<IIIIII", 0x02, 24, sym_off, 1, str_off, len(strtab))
    lc_entry = struct.pack("<IIQQ", 0x80000028, 24, text_file_off, 0)
    lcs = bytes(seg_text) + bytes(seg_link) + lc_symtab + lc_entry
    hdr = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x01000007, 3, 2, 4, len(lcs), 0x00200085, 0)

    out = bytearray()
    out += hdr
    out += lcs
    out += b"\0" * (text_file_off - len(out))
    out += code
    out += b"\0" * (text_file_off + unwind_off - len(out))
    out += unwind
    out += b"\0" * (sym_off - len(out))
    out += nlist
    out += strtab
    with open(out_path, "wb") as f:
        f.write(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
