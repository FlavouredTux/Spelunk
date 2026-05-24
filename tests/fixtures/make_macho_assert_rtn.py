#!/usr/bin/env python3
"""Emit a tiny x86_64 Mach-O whose hidden function is named by __assert_rtn."""

import struct
import sys


PAGE = 0x1000
BASE = 0x100000000


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


def cstr_table(names):
    data = bytearray(b"\0")
    offs = {}
    for name in names:
        offs[name] = len(data)
        data.extend(name.encode("ascii") + b"\0")
    return bytes(data), offs


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: make_macho_assert_rtn.py <output-path>", file=sys.stderr)
        return 2

    out_path = sys.argv[1]
    text_file_off = PAGE
    data_file_off = PAGE * 2
    text_vmaddr = BASE + PAGE
    data_vmaddr = BASE + PAGE * 2
    main_va = text_vmaddr
    main_code = bytes.fromhex("b800000000c3")
    hidden_va = main_va + len(main_code)

    hidden_len = 4 + 7 + 7 + 5 + 7 + 5 + 2
    stub_va = hidden_va + hidden_len
    stub_len = 6
    string_off = align(len(main_code) + hidden_len + stub_len, 8)
    string_va = text_vmaddr + string_off
    func = b"MacPlayer::recoverFromAssert\0"
    file = b"MacPlayer.mm\0"
    expr = b"player != nil\0"
    strings_blob = func + file + expr
    func_va = string_va
    file_va = func_va + len(func)
    expr_va = file_va + len(file)

    code = bytearray()
    code += main_code

    def emit(b):
        code.extend(b)

    def lea_rip(opcode, dst_va):
        ip = text_vmaddr + len(code)
        emit(opcode + struct.pack("<i", dst_va - (ip + 7)))

    emit(b"\x48\x83\xec\x08")                  # sub rsp, 8
    lea_rip(b"\x48\x8d\x3d", func_va)          # lea rdi, function
    lea_rip(b"\x48\x8d\x35", file_va)          # lea rsi, file
    emit(b"\xba\x0c\x00\x00\x00")              # mov edx, 12
    lea_rip(b"\x48\x8d\x0d", expr_va)          # lea rcx, expression
    ip = text_vmaddr + len(code)
    emit(b"\xe8" + struct.pack("<i", stub_va - (ip + 5)))
    emit(b"\x0f\x0b")                          # ud2
    stub_code = b"\xff\x25" + struct.pack("<i", data_vmaddr - (stub_va + 6))
    code += stub_code

    seg_text = bytearray()
    seg_text += struct.pack("<II", 0x19, 72 + 3 * 80)
    seg_text += b"__TEXT".ljust(16, b"\0")
    seg_text += struct.pack("<QQQQ", text_vmaddr, PAGE, text_file_off,
                            string_off + len(strings_blob))
    seg_text += struct.pack("<IIII", 5, 5, 3, 0)
    seg_text += b"__text".ljust(16, b"\0")
    seg_text += b"__TEXT".ljust(16, b"\0")
    seg_text += struct.pack("<QQ", main_va, len(main_code) + hidden_len)
    seg_text += struct.pack("<II", text_file_off, 4)
    seg_text += struct.pack("<IIIIII", 0, 0, 0x80000400, 0, 0, 0)
    seg_text += b"__stubs".ljust(16, b"\0")
    seg_text += b"__TEXT".ljust(16, b"\0")
    seg_text += struct.pack("<QQ", stub_va, stub_len)
    seg_text += struct.pack("<II", text_file_off + len(main_code) + hidden_len, 2)
    seg_text += struct.pack("<IIIIII", 0, 0, 0x80000408, 0, 6, 0)
    seg_text += b"__cstring".ljust(16, b"\0")
    seg_text += b"__TEXT".ljust(16, b"\0")
    seg_text += struct.pack("<QQ", string_va, len(strings_blob))
    seg_text += struct.pack("<II", text_file_off + string_off, 3)
    seg_text += struct.pack("<IIIIII", 0, 0, 0x2, 0, 0, 0)

    data = struct.pack("<Q", stub_va + stub_len)
    seg_data = bytearray()
    seg_data += struct.pack("<II", 0x19, 72 + 80)
    seg_data += b"__DATA".ljust(16, b"\0")
    seg_data += struct.pack("<QQQQ", data_vmaddr, PAGE, data_file_off, len(data))
    seg_data += struct.pack("<IIII", 3, 3, 1, 0)
    seg_data += b"__la_symbol_ptr".ljust(16, b"\0")
    seg_data += b"__DATA".ljust(16, b"\0")
    seg_data += struct.pack("<QQ", data_vmaddr, len(data))
    seg_data += struct.pack("<II", data_file_off, 3)
    seg_data += struct.pack("<IIIIII", 0, 0, 0x7, 0, 0, 0)

    strtab, str_offs = cstr_table(["_main"])
    nlist = struct.pack("<IBBHQ", str_offs["_main"], 0x0F, 1, 0, main_va)

    lazy_bind = bytearray()
    lazy_bind += bytes([0x70 | 1]) + uleb128(0)
    lazy_bind += bytes([0x10 | 1])
    lazy_bind += bytes([0x40]) + b"___assert_rtn\0"
    lazy_bind += bytes([0x50 | 1])
    lazy_bind += bytes([0x90, 0x00])

    fn_starts = uleb128(hidden_va - text_vmaddr) + b"\0"
    link_file_off = align8(data_file_off + len(data))
    sym_off = link_file_off
    str_off = sym_off + len(nlist)
    fn_starts_off = align8(str_off + len(strtab))
    lazy_bind_off = align8(fn_starts_off + len(fn_starts))
    link_filesize = lazy_bind_off + len(lazy_bind) - link_file_off

    seg_link = bytearray()
    seg_link += struct.pack("<II", 0x19, 72)
    seg_link += b"__LINKEDIT".ljust(16, b"\0")
    seg_link += struct.pack("<QQQQ", data_vmaddr + PAGE, PAGE, link_file_off, link_filesize)
    seg_link += struct.pack("<IIII", 1, 1, 0, 0)

    lc_symtab = struct.pack("<IIIIII", 0x02, 24, sym_off, 1, str_off, len(strtab))
    lc_dyld_info = struct.pack(
        "<IIIIIIIIIIII",
        0x80000022, 48,
        0, 0,
        0, 0,
        0, 0,
        lazy_bind_off, len(lazy_bind),
        0, 0,
    )
    lc_fnstarts = struct.pack("<IIII", 0x26, 16, fn_starts_off, len(fn_starts))
    lc_main = struct.pack("<IIQQ", 0x80000028, 24, text_file_off, 0)
    lcs = bytes(seg_text) + bytes(seg_data) + bytes(seg_link) + lc_symtab + lc_dyld_info + lc_fnstarts + lc_main
    hdr = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x01000007, 3, 2, 7, len(lcs), 0x00200085, 0)

    out = bytearray()
    out += hdr
    out += lcs
    out += b"\0" * (text_file_off - len(out))
    out += code
    out += b"\0" * (text_file_off + string_off - len(out))
    out += strings_blob
    out += b"\0" * (data_file_off - len(out))
    out += data
    out += b"\0" * (sym_off - len(out))
    out += nlist
    out += strtab
    out += b"\0" * (fn_starts_off - len(out))
    out += fn_starts
    out += b"\0" * (lazy_bind_off - len(out))
    out += lazy_bind

    with open(out_path, "wb") as f:
        f.write(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
