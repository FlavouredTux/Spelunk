#!/usr/bin/env python3
"""Emit a tiny x86_64 Mach-O that imports puts through a lazy-bind stub.

The fixture has:
  main:    call __stubs._puts; xor eax, eax; ret
  __stubs: jmp qword ptr [rip + __la_symbol_ptr._puts]

By default there is intentionally no undefined nlist row for _puts. The
import name lives only in LC_DYLD_INFO_ONLY.lazy_bind, so the loader must
synthesize the import and connect the x86_64 stub to it for decompiled calls
to be named.

With --dysymtab, the name comes from LC_DYSYMTAB's indirect symbol table
instead, covering the older lazy-pointer section-reserved1 path. With
--dysymtab-direct, main calls through a non-lazy pointer section directly.
With --weak-bind, the non-lazy pointer name comes from LC_DYLD_INFO_ONLY's
weak_bind stream. With --stack-guard, main carries a Mach-O
__stack_chk_guard epilogue.
"""

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
    args = sys.argv[1:]
    mode = "lazy"
    if args and args[0] == "--dysymtab":
        mode = "dysymtab"
        args = args[1:]
    elif args and args[0] == "--dysymtab-direct":
        mode = "dysymtab-direct"
        args = args[1:]
    elif args and args[0] == "--weak-bind":
        mode = "weak-bind"
        args = args[1:]
    elif args and args[0] == "--stack-guard":
        mode = "stack-guard"
        args = args[1:]
    if len(args) != 1:
        print("usage: make_macho_x64_import.py "
              "[--dysymtab|--dysymtab-direct|--weak-bind|--stack-guard] "
              "<output-path>",
              file=sys.stderr)
        return 2
    out_path = args[0]

    text_file_off = PAGE
    data_file_off = PAGE * 2
    text_vmaddr = BASE + PAGE
    data_vmaddr = BASE + PAGE * 2
    main_vmaddr = text_vmaddr
    stub_vmaddr = text_vmaddr + 8
    slot_vmaddr = data_vmaddr

    if mode == "stack-guard":
        fail_slot_vmaddr = data_vmaddr + 8
        code = bytearray()

        def emit(b):
            code.extend(b)

        emit(b"\x55")                         # push rbp
        emit(b"\x48\x89\xe5")                 # mov rbp, rsp
        emit(b"\x48\x83\xec\x10")             # sub rsp, 0x10
        ip = main_vmaddr + len(code)
        emit(b"\x48\x8b\x05" + struct.pack("<i", slot_vmaddr - (ip + 7)))
        emit(b"\x48\x8b\x00")                 # mov rax, [rax]
        emit(b"\x48\x89\x45\xf8")             # mov [rbp - 8], rax
        ip = main_vmaddr + len(code)
        emit(b"\x48\x8b\x05" + struct.pack("<i", slot_vmaddr - (ip + 7)))
        emit(b"\x48\x8b\x00")                 # mov rax, [rax]
        emit(b"\x48\x3b\x45\xf8")             # cmp rax, [rbp - 8]
        jne_off = len(code)
        emit(b"\x0f\x85\x00\x00\x00\x00")     # jne fail, patched below
        emit(b"\x48\x83\xc4\x10")             # add rsp, 0x10
        emit(b"\x5d\xc3")                     # pop rbp; ret
        fail_vmaddr = main_vmaddr + len(code)
        code[jne_off + 2:jne_off + 6] = struct.pack(
            "<i", fail_vmaddr - (main_vmaddr + jne_off + 6))
        stub_vmaddr = fail_vmaddr + 7
        emit(b"\xe8" + struct.pack("<i", stub_vmaddr - (fail_vmaddr + 5)))
        emit(b"\x0f\x0b")                     # ud2
        main_code = bytes(code)
        stub_code = b"\xff\x25" + struct.pack("<i", fail_slot_vmaddr - (stub_vmaddr + 6))
        data = struct.pack("<QQ", 0, 0)
    elif mode in ("dysymtab-direct", "weak-bind"):
        main_code = (
            b"\xff\x15" + struct.pack("<i", slot_vmaddr - (main_vmaddr + 6)) +
            b"\x31\xc0" +
            b"\xc3"
        )
        stub_code = b""
        data = struct.pack("<Q", 0)
    else:
        main_code = (
            b"\xe8" + struct.pack("<i", stub_vmaddr - (main_vmaddr + 5)) +
            b"\x31\xc0" +
            b"\xc3"
        )
        stub_code = b"\xff\x25" + struct.pack("<i", slot_vmaddr - (stub_vmaddr + 6))
        data = struct.pack("<Q", stub_vmaddr + len(stub_code))
    code = main_code + stub_code

    seg_text = bytearray()
    text_nsects = 1 if mode in ("dysymtab-direct", "weak-bind") else 2
    seg_text += struct.pack("<II", 0x19, 72 + text_nsects * 80)
    seg_text += b"__TEXT".ljust(16, b"\0")
    seg_text += struct.pack("<QQQQ", text_vmaddr, PAGE, text_file_off, len(code))
    seg_text += struct.pack("<IIII", 5, 5, text_nsects, 0)
    seg_text += b"__text".ljust(16, b"\0")
    seg_text += b"__TEXT".ljust(16, b"\0")
    seg_text += struct.pack("<QQ", main_vmaddr, len(main_code))
    seg_text += struct.pack("<II", text_file_off, 2)
    seg_text += struct.pack("<IIIIII", 0, 0, 0x80000400, 0, 0, 0)
    if mode not in ("dysymtab-direct", "weak-bind"):
        seg_text += b"__stubs".ljust(16, b"\0")
        seg_text += b"__TEXT".ljust(16, b"\0")
        seg_text += struct.pack("<QQ", stub_vmaddr, len(stub_code))
        seg_text += struct.pack("<II", text_file_off + len(main_code), 2)
        seg_text += struct.pack("<IIIIII", 0, 0, 0x80000408, 0, 6, 0)

    seg_data = bytearray()
    seg_data += struct.pack("<II", 0x19, 72 + 80)
    seg_data += b"__DATA".ljust(16, b"\0")
    seg_data += struct.pack("<QQQQ", data_vmaddr, PAGE, data_file_off, len(data))
    seg_data += struct.pack("<IIII", 3, 3, 1, 0)
    pointer_section = "__got" if mode in ("dysymtab-direct", "weak-bind", "stack-guard") else "__la_symbol_ptr"
    pointer_type = 0x6 if mode in ("dysymtab-direct", "weak-bind", "stack-guard") else 0x7
    seg_data += pointer_section.encode("ascii").ljust(16, b"\0")
    seg_data += b"__DATA".ljust(16, b"\0")
    seg_data += struct.pack("<QQ", slot_vmaddr, len(data))
    seg_data += struct.pack("<II", data_file_off, 3)
    seg_data += struct.pack("<IIIIII", 0, 0, pointer_type, 0, 0, 0)

    use_dysymtab = mode in ("dysymtab", "dysymtab-direct", "stack-guard")
    if mode == "stack-guard":
        names = ["_main", "___stack_chk_guard", "___stack_chk_fail"]
    else:
        names = ["_main", "_puts"] if use_dysymtab else ["_main"]
    strtab, str_offs = cstr_table(names)
    nlist = struct.pack("<IBBHQ", str_offs["_main"], 0x0F, 1, 0, main_vmaddr)
    if mode == "stack-guard":
        nlist += struct.pack("<IBBHQ", str_offs["___stack_chk_guard"], 0x01, 0, 0, 0)
        nlist += struct.pack("<IBBHQ", str_offs["___stack_chk_fail"], 0x01, 0, 0, 0)
    elif use_dysymtab:
        nlist += struct.pack("<IBBHQ", str_offs["_puts"], 0x01, 0, 0, 0)

    lazy_bind = bytearray()
    weak_bind = bytearray()
    def emit_bind_record(buf, slot, name):
        buf += bytes([0x70 | 1]) + uleb128(slot - data_vmaddr)
        buf += bytes([0x10 | 1])
        buf += bytes([0x40]) + name.encode("ascii") + b"\0"
        buf += bytes([0x50 | 1])
        buf += bytes([0x90])

    if mode == "lazy":
        emit_bind_record(lazy_bind, slot_vmaddr, "_puts")
        lazy_bind += bytes([0x00])
    elif mode == "weak-bind":
        emit_bind_record(weak_bind, slot_vmaddr, "_puts")
        weak_bind += bytes([0x00])
    indirect = struct.pack("<II", 1, 2) if mode == "stack-guard" else (
        struct.pack("<I", 1) if use_dysymtab else b"")

    link_file_off = align8(data_file_off + len(data))
    sym_off = link_file_off
    str_off = sym_off + len(nlist)
    indirect_off = align8(str_off + len(strtab))
    weak_bind_off = align8(indirect_off + len(indirect))
    lazy_bind_off = align8(weak_bind_off + len(weak_bind))
    link_filesize = lazy_bind_off + len(lazy_bind) - link_file_off

    seg_link = bytearray()
    seg_link += struct.pack("<II", 0x19, 72)
    seg_link += b"__LINKEDIT".ljust(16, b"\0")
    seg_link += struct.pack("<QQQQ", data_vmaddr + PAGE, PAGE, link_file_off, link_filesize)
    seg_link += struct.pack("<IIII", 1, 1, 0, 0)

    nsyms = 3 if mode == "stack-guard" else (2 if use_dysymtab else 1)
    nindirect = 2 if mode == "stack-guard" else (1 if use_dysymtab else 0)
    lc_symtab = struct.pack("<IIIIII", 0x02, 24, sym_off, nsyms,
                            str_off, len(strtab))
    lc_dysymtab = b""
    if use_dysymtab:
        lc_dysymtab = struct.pack(
            "<IIIIIIIIIIIIIIIIIIII",
            0x0B, 80,
            0, 0,
            0, 1,
            1, 1,
            0, 0,
            0, 0,
            0, 0,
            indirect_off, nindirect,
            0, 0,
            0, 0,
        )
    lc_dyld_info = struct.pack(
        "<IIIIIIIIIIII",
        0x80000022, 48,
        0, 0,
        0, 0,
        weak_bind_off, len(weak_bind),
        lazy_bind_off, len(lazy_bind),
        0, 0,
    )
    lc_main = struct.pack("<IIQQ", 0x80000028, 24, text_file_off, 0)

    lcs = (
        bytes(seg_text) + bytes(seg_data) + bytes(seg_link) + lc_symtab +
        lc_dysymtab + lc_dyld_info + lc_main
    )
    hdr = struct.pack(
        "<IIIIIIII",
        0xFEEDFACF, 0x01000007, 3, 2,
        7 if use_dysymtab else 6, len(lcs), 0x00200085, 0,
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
    out += b"\0" * (indirect_off - len(out))
    out += indirect
    out += b"\0" * (weak_bind_off - len(out))
    out += weak_bind
    out += b"\0" * (lazy_bind_off - len(out))
    out += lazy_bind

    with open(out_path, "wb") as f:
        f.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
