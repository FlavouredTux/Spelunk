#!/usr/bin/env python3
"""Emit a tiny x86_64 Mach-O with an Objective-C block literal."""

import struct
import sys


def align(v, a):
    return (v + a - 1) & ~(a - 1)


def align8(v):
    return align(v, 8)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: make_macho_blocks.py <output-path>", file=sys.stderr)
        return 2

    out_path = sys.argv[1]
    PAGE = 0x1000
    BASE = 0x100000000
    text_file_off = PAGE
    const_file_off = PAGE * 2
    cstring_file_off = PAGE * 3
    link_file_off = PAGE * 4
    text_vmaddr = BASE + PAGE
    const_vmaddr = BASE + PAGE * 2
    cstring_vmaddr = BASE + PAGE * 3
    main_va = text_vmaddr
    invoke_va = text_vmaddr + 6
    literal_va = const_vmaddr
    block_size = 48
    descriptor_va = const_vmaddr + block_size
    sig_va = cstring_vmaddr

    source_name = b"-[SampleWorker finish:]_block_invoke\0"
    signature = b"Q8@?0\0"
    source_name_va = cstring_vmaddr + len(signature)
    lea_next = invoke_va + 7
    disp = source_name_va - lea_next
    invoke_code = (
        b"\x48\x8d\x0d" + struct.pack("<i", disp) +
        bytes.fromhex("488b4728c3")
    )
    code = (
        bytes.fromhex("b801000000c3") +  # main: return 1
        invoke_code                       # block invoke references its metadata name
    )
    block_has_signature = 1 << 30
    const = (
        struct.pack("<Q", 0) +
        struct.pack("<I", block_has_signature) +
        struct.pack("<I", 0) +
        struct.pack("<Q", invoke_va) +
        struct.pack("<Q", descriptor_va) +
        struct.pack("<Q", 0x1111111111111111) +
        struct.pack("<Q", source_name_va) +
        struct.pack("<Q", 0) +
        struct.pack("<Q", block_size) +
        struct.pack("<Q", sig_va)
    )

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

    seg_const = bytearray()
    seg_const += struct.pack("<II", 0x19, 72 + 80)
    seg_const += b"__DATA_CONST".ljust(16, b"\0")
    seg_const += struct.pack("<QQQQ", const_vmaddr, PAGE, const_file_off, len(const))
    seg_const += struct.pack("<IIII", 3, 3, 1, 0)
    seg_const += b"__const".ljust(16, b"\0")
    seg_const += b"__DATA_CONST".ljust(16, b"\0")
    seg_const += struct.pack("<QQ", const_vmaddr, len(const))
    seg_const += struct.pack("<II", const_file_off, 3)
    seg_const += struct.pack("<IIIIII", 0, 0, 0, 0, 0, 0)

    seg_cstring = bytearray()
    seg_cstring += struct.pack("<II", 0x19, 72 + 80)
    seg_cstring += b"__TEXT".ljust(16, b"\0")
    cstrings = signature + source_name
    seg_cstring += struct.pack("<QQQQ", cstring_vmaddr, PAGE, cstring_file_off, len(cstrings))
    seg_cstring += struct.pack("<IIII", 5, 5, 1, 0)
    seg_cstring += b"__cstring".ljust(16, b"\0")
    seg_cstring += b"__TEXT".ljust(16, b"\0")
    seg_cstring += struct.pack("<QQ", cstring_vmaddr, len(cstrings))
    seg_cstring += struct.pack("<II", cstring_file_off, 3)
    seg_cstring += struct.pack("<IIIIII", 0, 0, 0x2, 0, 0, 0)

    strings = bytearray(b"\0")
    main_name_off = len(strings)
    strings += b"_main\0"
    strtab = bytes(strings)
    nlist = struct.pack("<IBBHQ", main_name_off, 0x0F, 1, 0, main_va)

    sym_off = link_file_off
    str_off = sym_off + len(nlist)
    link_filesize = str_off + len(strtab) - link_file_off

    seg_link = bytearray()
    seg_link += struct.pack("<II", 0x19, 72)
    seg_link += b"__LINKEDIT".ljust(16, b"\0")
    seg_link += struct.pack("<QQQQ", cstring_vmaddr + PAGE, PAGE, link_file_off, link_filesize)
    seg_link += struct.pack("<IIII", 1, 1, 0, 0)

    lc_symtab = struct.pack("<IIIIII", 0x02, 24, sym_off, 1, str_off, len(strtab))
    lc_entry = struct.pack("<IIQQ", 0x80000028, 24, text_file_off, 0)
    lcs = bytes(seg_text) + bytes(seg_const) + bytes(seg_cstring) + bytes(seg_link) + lc_symtab + lc_entry
    hdr = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x01000007, 3, 2, 6, len(lcs), 0x00200085, 0)

    out = bytearray()
    out += hdr
    out += lcs
    out += b"\0" * (text_file_off - len(out))
    out += code
    out += b"\0" * (const_file_off - len(out))
    out += const
    out += b"\0" * (cstring_file_off - len(out))
    out += cstrings
    out += b"\0" * (sym_off - len(out))
    out += nlist
    out += strtab

    with open(out_path, "wb") as f:
        f.write(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
