#!/usr/bin/env python3
"""Emit a tiny Mach-O primary or matching dSYM-like symbol companion."""

import struct
import sys


def align(v, a):
    return (v + a - 1) & ~(a - 1)


def align8(v):
    return align(v, 8)


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
    mode = "primary"
    args = sys.argv[1:]
    if args and args[0] == "--dsym":
        mode = "dsym"
        args = args[1:]
    if len(args) != 1:
        print("usage: make_macho_dsym_pair.py [--dsym] <output-path>", file=sys.stderr)
        return 2

    out_path = args[0]
    PAGE = 0x1000
    BASE = 0x100000000
    text_file_off = PAGE
    link_file_off = PAGE * 2
    text_vmaddr = BASE + PAGE
    main_va = text_vmaddr
    hidden_va = text_vmaddr + 6

    code = bytes.fromhex("b801000000c3") + bytes.fromhex("b863000000c3")

    seg_text = bytearray()
    seg_text += struct.pack("<II", 0x19, 72 + 80)
    seg_text += b"__TEXT".ljust(16, b"\0")
    seg_text += struct.pack("<QQQQ", text_vmaddr, PAGE, text_file_off, len(code))
    seg_text += struct.pack("<IIII", 5, 5, 1, 0)
    seg_text += b"__text".ljust(16, b"\0")
    seg_text += b"__TEXT".ljust(16, b"\0")
    seg_text += struct.pack("<QQ", text_vmaddr, len(code))
    seg_text += struct.pack("<II", text_file_off, 4)
    seg_text += struct.pack("<IIIIII", 0, 0, 0x80000400, 0, 0, 0)

    strings = bytearray(b"\0")
    sym_offs = {}

    def add_string(s):
        sym_offs[s] = len(strings)
        strings.extend(s.encode("ascii") + b"\0")

    add_string("_main")
    if mode == "dsym":
        add_string("_dsym_named_hidden")
    strtab = bytes(strings)

    syms = [("_main", main_va, 1)]
    if mode == "dsym":
        syms.append(("_dsym_named_hidden", hidden_va, 1))
    nlist = bytearray()
    for name, vm, sect in syms:
        nlist += struct.pack("<IBBHQ", sym_offs[name], 0x0F, sect, 0, vm)

    fn_starts = uleb128(hidden_va - text_vmaddr) + b"\0"
    sym_off = link_file_off
    str_off = sym_off + len(nlist)
    fn_starts_off = align8(str_off + len(strtab))
    link_filesize = fn_starts_off + len(fn_starts) - link_file_off

    seg_link = bytearray()
    seg_link += struct.pack("<II", 0x19, 72)
    seg_link += b"__LINKEDIT".ljust(16, b"\0")
    seg_link += struct.pack("<QQQQ", text_vmaddr + PAGE, PAGE, link_file_off, link_filesize)
    seg_link += struct.pack("<IIII", 1, 1, 0, 0)

    lc_symtab = struct.pack("<IIIIII", 0x02, 24, sym_off, len(syms), str_off, len(strtab))
    lc_fnstarts = struct.pack("<IIII", 0x26, 16, fn_starts_off, len(fn_starts))
    lc_entry = b"" if mode == "dsym" else struct.pack("<IIQQ", 0x80000028, 24, text_file_off, 0)
    lcs = bytes(seg_text) + bytes(seg_link) + lc_symtab + lc_fnstarts + lc_entry
    ncmds = 4 if mode == "dsym" else 5
    filetype = 0x0A if mode == "dsym" else 0x02
    hdr = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x01000007, 3, filetype, ncmds, len(lcs), 0x00200085, 0)

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
    raise SystemExit(main())
