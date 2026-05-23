#!/usr/bin/env python3
"""Emit a tiny x86_64 Mach-O with ObjC relative lists and metadata."""

import struct
import sys


def align(v, a):
    return (v + a - 1) & ~(a - 1)


def pad_to(buf, a):
    buf += b"\0" * (align(len(buf), a) - len(buf))


def add_cstr(buf, s):
    off = len(buf)
    buf.extend(s.encode("ascii") + b"\0")
    return off


def pack_rel_method(buf, off, entry_va, sel_va, types_va, imp_va):
    struct.pack_into("<iii", buf, off,
                     sel_va - (entry_va + 0),
                     types_va - (entry_va + 4),
                     imp_va - (entry_va + 8))


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: make_macho_objc_relative.py <output-path>", file=sys.stderr)
        return 2
    out_path = sys.argv[1]

    PAGE = 0x1000
    BASE = 0x100000000
    text_file_off = PAGE
    data_file_off = PAGE * 2
    text_vmaddr = BASE + PAGE
    data_vmaddr = BASE + PAGE * 2

    data = bytearray()
    classlist_off = len(data)
    data += b"\0" * 8

    pad_to(data, 8)
    nlclasslist_off = len(data)
    data += b"\0" * 8

    pad_to(data, 8)
    catlist_off = len(data)
    data += b"\0" * 8

    pad_to(data, 8)
    nlcatlist_off = len(data)
    data += b"\0" * 8

    pad_to(data, 8)
    class_off = len(data)
    data += b"\0" * 40

    pad_to(data, 8)
    ro_off = len(data)
    data += b"\0" * 72

    pad_to(data, 4)
    method_list_off = len(data)
    data += b"\0" * (8 + 2 * 12)

    pad_to(data, 8)
    cat_off = len(data)
    data += b"\0" * 56

    pad_to(data, 4)
    cat_method_list_off = len(data)
    data += b"\0" * (8 + 12)

    pad_to(data, 8)
    ivar_list_off = len(data)
    data += b"\0" * (8 + 32)

    pad_to(data, 8)
    prop_list_off = len(data)
    data += b"\0" * (8 + 16)

    pad_to(data, 8)
    cat_prop_list_off = len(data)
    data += b"\0" * (8 + 16)

    pad_to(data, 8)
    ivar_offset_off = len(data)
    data += b"\0" * 8

    name_off = add_cstr(data, "Tiny")
    cat_name_off = add_cstr(data, "Extra")
    ping_sel_off = add_cstr(data, "ping")
    count_sel_off = add_cstr(data, "count")
    pong_sel_off = add_cstr(data, "pong")
    void_types_off = add_cstr(data, "v16@0:8")
    int_types_off = add_cstr(data, "i16@0:8")
    ivar_name_off = add_cstr(data, "_count")
    ivar_type_off = add_cstr(data, "i")
    prop_name_off = add_cstr(data, "count")
    prop_attrs_off = add_cstr(data, "Ti,N,V_count")
    cat_prop_name_off = add_cstr(data, "extra")
    cat_prop_attrs_off = add_cstr(data, "T@,N")

    class_va = data_vmaddr + class_off
    ro_va = data_vmaddr + ro_off
    method_list_va = data_vmaddr + method_list_off
    cat_va = data_vmaddr + cat_off
    cat_method_list_va = data_vmaddr + cat_method_list_off
    ivar_list_va = data_vmaddr + ivar_list_off
    prop_list_va = data_vmaddr + prop_list_off
    cat_prop_list_va = data_vmaddr + cat_prop_list_off
    ivar_offset_va = data_vmaddr + ivar_offset_off

    ping_va = text_vmaddr
    count_va = text_vmaddr + 6
    pong_va = text_vmaddr + 17

    # ping: mov eax, 7; ret
    ping_code = bytes.fromhex("b807000000c3")
    # count: mov rax, qword ptr [rip + _count_offset]; mov eax, [rdi + rax]; ret
    count_disp = ivar_offset_va - (count_va + 7)
    count_code = bytes.fromhex("488b05") + struct.pack("<i", count_disp) + bytes.fromhex("8b0407c3")
    # category method: mov eax, 9; ret
    pong_code = bytes.fromhex("b809000000c3")
    code = ping_code + count_code + pong_code

    def va(off):
        return data_vmaddr + off

    struct.pack_into("<Q", data, classlist_off, class_va)
    struct.pack_into("<Q", data, nlclasslist_off, class_va)
    struct.pack_into("<Q", data, catlist_off, cat_va)
    struct.pack_into("<Q", data, nlcatlist_off, cat_va)
    struct.pack_into("<QQQQQ", data, class_off, 0, 0, 0, 0, ro_va)
    struct.pack_into("<IIIIQQQQQQQ", data, ro_off,
                     0, 0, 16, 0,
                     0, va(name_off), method_list_va, 0,
                     ivar_list_va, 0, prop_list_va)

    struct.pack_into("<II", data, method_list_off, 0x8000000C, 2)
    entry_va = method_list_va + 8
    pack_rel_method(data, method_list_off + 8,
                    entry_va, va(ping_sel_off), va(void_types_off), ping_va)
    entry_va += 12
    pack_rel_method(data, method_list_off + 20,
                    entry_va, va(count_sel_off), va(int_types_off), count_va)

    struct.pack_into("<QQQQQQQ", data, cat_off,
                     va(cat_name_off), class_va, cat_method_list_va, 0, 0,
                     cat_prop_list_va, 0)
    struct.pack_into("<II", data, cat_method_list_off, 0x8000000C, 1)
    entry_va = cat_method_list_va + 8
    pack_rel_method(data, cat_method_list_off + 8,
                    entry_va, va(pong_sel_off), va(int_types_off), pong_va)

    struct.pack_into("<II", data, ivar_list_off, 32, 1)
    struct.pack_into("<QQQII", data, ivar_list_off + 8,
                     ivar_offset_va, va(ivar_name_off), va(ivar_type_off), 2, 4)
    struct.pack_into("<II", data, prop_list_off, 16, 1)
    struct.pack_into("<QQ", data, prop_list_off + 8, va(prop_name_off), va(prop_attrs_off))
    struct.pack_into("<II", data, cat_prop_list_off, 16, 1)
    struct.pack_into("<QQ", data, cat_prop_list_off + 8,
                     va(cat_prop_name_off), va(cat_prop_attrs_off))
    struct.pack_into("<Q", data, ivar_offset_off, 16)

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

    sections = [
        ("__objc_classlist", classlist_off, 8, 3),
        ("__objc_nlclslist", nlclasslist_off, 8, 3),
        ("__objc_catlist", catlist_off, 8, 3),
        ("__objc_nlcatlist", nlcatlist_off, 8, 3),
        ("__objc_data", class_off, 40, 3),
        ("__objc_const", ro_off, ivar_offset_off - ro_off, 3),
        ("__objc_ivar", ivar_offset_off, 8, 3),
    ]
    seg_data = bytearray()
    seg_data += struct.pack("<II", 0x19, 72 + len(sections) * 80)
    seg_data += b"__DATA".ljust(16, b"\0")
    seg_data += struct.pack("<QQQQ", data_vmaddr, PAGE, data_file_off, len(data))
    seg_data += struct.pack("<IIII", 3, 3, len(sections), 0)
    for name, off, size, align_pow in sections:
        seg_data += name.encode("ascii").ljust(16, b"\0")
        seg_data += b"__DATA".ljust(16, b"\0")
        seg_data += struct.pack("<QQ", data_vmaddr + off, size)
        seg_data += struct.pack("<II", data_file_off + off, align_pow)
        seg_data += struct.pack("<IIIIII", 0, 0, 0, 0, 0, 0)

    lc_main = struct.pack("<IIQQ", 0x80000028, 24, text_file_off, 0)
    lcs = bytes(seg_text) + bytes(seg_data) + lc_main
    hdr = struct.pack("<IIIIIIII",
                      0xFEEDFACF, 0x01000007, 3, 2,
                      3, len(lcs), 0x00200085, 0)

    out = bytearray()
    out += hdr
    out += lcs
    out += b"\0" * (text_file_off - len(out))
    out += code
    out += b"\0" * (data_file_off - len(out))
    out += data

    with open(out_path, "wb") as f:
        f.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
