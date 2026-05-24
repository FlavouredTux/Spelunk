#!/usr/bin/env python3
"""Emit a tiny x86_64 Mach-O that calls objc_msgSend floating-return variants."""

import struct
import sys


PAGE = 0x1000
BASE = 0x100000000


def align8(v):
    return (v + 7) & ~7


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


def cstr_table(names):
    data = bytearray(b"\0")
    offs = {}
    for name in names:
        offs[name] = len(data)
        data.extend(name.encode("ascii") + b"\0")
    return bytes(data), offs


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: make_macho_objc_fpret.py <output-path>", file=sys.stderr)
        return 2
    out_path = sys.argv[1]

    text_file_off = PAGE
    data_file_off = PAGE * 2
    text_vmaddr = BASE + PAGE
    data_vmaddr = BASE + PAGE * 2
    main_vmaddr = text_vmaddr

    fpret_slot_vmaddr = data_vmaddr
    fp2ret_slot_vmaddr = data_vmaddr + 8
    selref_vmaddr = data_vmaddr + 16
    methname_vmaddr = data_vmaddr + 24

    code = bytearray()

    def emit(b):
        code.extend(b)

    emit(b"\x55")                             # push rbp
    emit(b"\x48\x89\xe5")                     # mov rbp, rsp
    emit(b"\x48\x83\xec\x10")                 # sub rsp, 0x10
    emit(b"\xbf\x34\x12\x00\x00")             # mov edi, 0x1234
    ip = main_vmaddr + len(code)
    emit(b"\x48\x8b\x35" + struct.pack("<i", selref_vmaddr - (ip + 7)))
    fpret_call_off = len(code)
    emit(b"\xe8\x00\x00\x00\x00")             # patched below
    emit(b"\xbf\x78\x56\x00\x00")             # mov edi, 0x5678
    ip = main_vmaddr + len(code)
    emit(b"\x48\x8b\x35" + struct.pack("<i", selref_vmaddr - (ip + 7)))
    fp2ret_call_off = len(code)
    emit(b"\xe8\x00\x00\x00\x00")             # patched below
    emit(b"\x31\xc0")                         # xor eax, eax
    emit(b"\xc9\xc3")                         # leave; ret

    fpret_stub_vmaddr = main_vmaddr + len(code)
    code[fpret_call_off + 1:fpret_call_off + 5] = struct.pack(
        "<i", fpret_stub_vmaddr - (main_vmaddr + fpret_call_off + 5))
    emit(b"\xff\x25" + struct.pack(
        "<i", fpret_slot_vmaddr - (fpret_stub_vmaddr + 6)))
    fp2ret_stub_vmaddr = main_vmaddr + len(code)
    code[fp2ret_call_off + 1:fp2ret_call_off + 5] = struct.pack(
        "<i", fp2ret_stub_vmaddr - (main_vmaddr + fp2ret_call_off + 5))
    emit(b"\xff\x25" + struct.pack(
        "<i", fp2ret_slot_vmaddr - (fp2ret_stub_vmaddr + 6)))

    main_code_size = fpret_stub_vmaddr - main_vmaddr
    data = struct.pack(
        "<QQQ",
        fpret_stub_vmaddr + 6,
        fp2ret_stub_vmaddr + 6,
        methname_vmaddr,
    ) + b"doubleValue\0"

    seg_text = bytearray()
    seg_text += struct.pack("<II", 0x19, 72 + 2 * 80)
    seg_text += b"__TEXT".ljust(16, b"\0")
    seg_text += struct.pack("<QQQQ", text_vmaddr, PAGE, text_file_off, len(code))
    seg_text += struct.pack("<IIII", 5, 5, 2, 0)
    seg_text += b"__text".ljust(16, b"\0")
    seg_text += b"__TEXT".ljust(16, b"\0")
    seg_text += struct.pack("<QQ", main_vmaddr, main_code_size)
    seg_text += struct.pack("<II", text_file_off, 2)
    seg_text += struct.pack("<IIIIII", 0, 0, 0x80000400, 0, 0, 0)
    seg_text += b"__stubs".ljust(16, b"\0")
    seg_text += b"__TEXT".ljust(16, b"\0")
    seg_text += struct.pack("<QQ", fpret_stub_vmaddr, len(code) - main_code_size)
    seg_text += struct.pack("<II", text_file_off + main_code_size, 2)
    seg_text += struct.pack("<IIIIII", 0, 0, 0x80000408, 0, 6, 0)

    seg_data = bytearray()
    seg_data += struct.pack("<II", 0x19, 72 + 3 * 80)
    seg_data += b"__DATA".ljust(16, b"\0")
    seg_data += struct.pack("<QQQQ", data_vmaddr, PAGE, data_file_off, len(data))
    seg_data += struct.pack("<IIII", 3, 3, 3, 0)
    seg_data += b"__la_symbol_ptr".ljust(16, b"\0")
    seg_data += b"__DATA".ljust(16, b"\0")
    seg_data += struct.pack("<QQ", fpret_slot_vmaddr, 16)
    seg_data += struct.pack("<II", data_file_off, 3)
    seg_data += struct.pack("<IIIIII", 0, 0, 0x7, 0, 0, 0)
    seg_data += b"__objc_selrefs".ljust(16, b"\0")
    seg_data += b"__DATA".ljust(16, b"\0")
    seg_data += struct.pack("<QQ", selref_vmaddr, 8)
    seg_data += struct.pack("<II", data_file_off + 16, 3)
    seg_data += struct.pack("<IIIIII", 0, 0, 0, 0, 0, 0)
    seg_data += b"__objc_methname".ljust(16, b"\0")
    seg_data += b"__DATA".ljust(16, b"\0")
    seg_data += struct.pack("<QQ", methname_vmaddr, len(data) - 24)
    seg_data += struct.pack("<II", data_file_off + 24, 0)
    seg_data += struct.pack("<IIIIII", 0, 0, 0, 0, 0, 0)

    strtab, str_offs = cstr_table(["_main"])
    nlist = struct.pack("<IBBHQ", str_offs["_main"], 0x0F, 1, 0, main_vmaddr)

    lazy_bind = bytearray()
    def emit_lazy_bind(slot_vmaddr, symbol):
        lazy_bind.extend(bytes([0x70 | 1]) + uleb128(slot_vmaddr - data_vmaddr))
        lazy_bind.extend(bytes([0x10 | 1]))
        lazy_bind.extend(bytes([0x40]) + symbol.encode("ascii") + b"\0")
        lazy_bind.extend(bytes([0x50 | 1]))
        lazy_bind.extend(bytes([0x90]))

    emit_lazy_bind(fpret_slot_vmaddr, "_objc_msgSend_fpret")
    emit_lazy_bind(fp2ret_slot_vmaddr, "_objc_msgSend_fp2ret")
    lazy_bind += bytes([0x00])

    link_file_off = align8(data_file_off + len(data))
    sym_off = link_file_off
    str_off = sym_off + len(nlist)
    lazy_bind_off = align8(str_off + len(strtab))
    link_filesize = lazy_bind_off + len(lazy_bind) - link_file_off

    seg_link = bytearray()
    seg_link += struct.pack("<II", 0x19, 72)
    seg_link += b"__LINKEDIT".ljust(16, b"\0")
    seg_link += struct.pack("<QQQQ", data_vmaddr + PAGE, PAGE,
                            link_file_off, link_filesize)
    seg_link += struct.pack("<IIII", 1, 1, 0, 0)

    lc_symtab = struct.pack("<IIIIII", 0x02, 24, sym_off, 1,
                            str_off, len(strtab))
    lc_dyld_info = struct.pack(
        "<IIIIIIIIIIII",
        0x80000022, 48,
        0, 0,
        0, 0,
        lazy_bind_off, len(lazy_bind),
        0, 0,
        0, 0,
    )
    lc_main = struct.pack("<IIQQ", 0x80000028, 24, text_file_off, 0)

    lcs = bytes(seg_text) + bytes(seg_data) + bytes(seg_link) + lc_symtab + lc_dyld_info + lc_main
    hdr = struct.pack(
        "<IIIIIIII",
        0xFEEDFACF, 0x01000007, 3, 2,
        6, len(lcs), 0x00200085, 0,
    )

    out = bytearray()
    out += hdr
    out += lcs
    out += b"\0" * (text_file_off - len(out))
    out += code
    out += b"\0" * (data_file_off - len(out))
    out += data
    out += b"\0" * (sym_off - len(out))
    out += nlist
    out += strtab
    out += b"\0" * (lazy_bind_off - len(out))
    out += lazy_bind

    with open(out_path, "wb") as f:
        f.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
