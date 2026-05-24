#!/usr/bin/env python3
"""Emit a tiny x86_64 Mach-O with a __swift5_types descriptor."""

import struct
import sys


def align(v, a):
    return (v + a - 1) & ~(a - 1)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: make_macho_swift_types.py <output-path>", file=sys.stderr)
        return 2
    out_path = sys.argv[1]

    PAGE = 0x1000
    BASE = 0x100000000
    text_file_off = PAGE
    text_vmaddr = BASE + PAGE

    main_va = text_vmaddr
    field_name_fn_va = text_vmaddr + 11
    accessor_fn_va = text_vmaddr + 22

    # Layout:
    #   main:       movabs rax, swift_type_Widget; ret
    #   field_name: movabs rax, swift_field_Widget_title; ret
    #   accessor:   return 0x2a, named only through Swift metadata
    code_size = 28
    swift_types_off = align(code_size, 4)
    desc_off = align(swift_types_off + 4, 4)
    fieldmd_off = align(desc_off + 24, 4)
    name_off = fieldmd_off + 28
    field_type_off = name_off + len("Widget") + 1
    field_name_off = field_type_off + len("Swift.Int") + 1

    desc_va = text_vmaddr + desc_off
    swift_types_va = text_vmaddr + swift_types_off
    fieldmd_va = text_vmaddr + fieldmd_off
    name_va = text_vmaddr + name_off
    field_type_va = text_vmaddr + field_type_off
    field_name_va = text_vmaddr + field_name_off

    code = (
        b"\x48\xb8" + struct.pack("<Q", desc_va) + b"\xc3" +
        b"\x48\xb8" + struct.pack("<Q", field_name_va) + b"\xc3" +
        b"\xb8\x2a\x00\x00\x00\xc3"
    )

    text = bytearray()
    text += code
    text += b"\0" * (swift_types_off - len(text))
    text += struct.pack("<i", desc_va - swift_types_va)
    text += b"\0" * (desc_off - len(text))
    # TargetStructDescriptor prefix:
    # flags(kind=struct=17), parent rel, name rel, access fn, fields, ...
    text += struct.pack("<Iiiiii",
                        17,
                        0,
                        name_va - (desc_va + 8),
                        accessor_fn_va - (desc_va + 12),
                        fieldmd_va - (desc_va + 16),
                        0)
    text += b"\0" * (fieldmd_off - len(text))
    # Swift FieldDescriptor + one FieldRecord for `title`.
    text += struct.pack("<iiHHI",
                        name_va - (fieldmd_va + 0),
                        0,
                        0,
                        12,
                        1)
    record_va = fieldmd_va + 16
    text += struct.pack("<Iii",
                        0,
                        field_type_va - (record_va + 4),
                        field_name_va - (record_va + 8))
    text += b"Widget\0"
    text += b"Swift.Int\0"
    text += b"title\0"

    seg_text = bytearray()
    seg_text += struct.pack("<II", 0x19, 72 + 4 * 80)
    seg_text += b"__TEXT".ljust(16, b"\0")
    seg_text += struct.pack("<QQQQ", text_vmaddr, PAGE, text_file_off, len(text))
    seg_text += struct.pack("<IIII", 5, 5, 4, 0)
    for name, off, size, flags in [
        ("__text", 0, len(code), 0x80000400),
        ("__swift5_types", swift_types_off, 4, 0),
        ("__swift5_fieldmd", fieldmd_off, 28, 0),
        ("__const", desc_off, len(text) - desc_off, 0),
    ]:
        seg_text += name.encode("ascii").ljust(16, b"\0")
        seg_text += b"__TEXT".ljust(16, b"\0")
        seg_text += struct.pack("<QQ", text_vmaddr + off, size)
        seg_text += struct.pack("<II", text_file_off + off, 2)
        seg_text += struct.pack("<IIIIII", 0, 0, flags, 0, 0, 0)

    strtab = b"\0_main\0_field_name\0"
    nlist = (
        struct.pack("<IBBHQ", 1, 0x0F, 1, 0, main_va) +
        struct.pack("<IBBHQ", 7, 0x0F, 1, 0, field_name_fn_va)
    )
    link_file_off = align(text_file_off + len(text), 8)
    sym_off = link_file_off
    str_off = sym_off + len(nlist)
    link_filesize = str_off + len(strtab) - link_file_off
    seg_link = bytearray()
    seg_link += struct.pack("<II", 0x19, 72)
    seg_link += b"__LINKEDIT".ljust(16, b"\0")
    seg_link += struct.pack("<QQQQ", text_vmaddr + PAGE, PAGE, link_file_off, link_filesize)
    seg_link += struct.pack("<IIII", 1, 1, 0, 0)

    lc_symtab = struct.pack("<IIIIII", 0x02, 24, sym_off, 2, str_off, len(strtab))
    lc_main = struct.pack("<IIQQ", 0x80000028, 24, text_file_off, 0)

    lcs = bytes(seg_text) + bytes(seg_link) + lc_symtab + lc_main
    hdr = struct.pack("<IIIIIIII",
                      0xFEEDFACF, 0x01000007, 3, 2,
                      4, len(lcs), 0x00200085, 0)

    out = bytearray()
    out += hdr
    out += lcs
    out += b"\0" * (text_file_off - len(out))
    out += text
    out += b"\0" * (sym_off - len(out))
    out += nlist
    out += strtab

    with open(out_path, "wb") as f:
        f.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
