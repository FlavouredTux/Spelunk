#!/usr/bin/env python3
"""Emit a tiny x86_64 Mach-O with an Itanium C++ vtable symbol."""

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
    args = sys.argv[1:]
    mode = "basic"
    if args and args[0] == "--metadata":
        mode = "metadata"
        args = args[1:]
    if args and args[0] == "--metadata-local":
        mode = "metadata-local"
        args = args[1:]
    if args and args[0] == "--metadata-nested-local":
        mode = "metadata-nested-local"
        args = args[1:]
    if args and args[0] == "--metadata-nested-free":
        mode = "metadata-nested-free"
        args = args[1:]
    if args and args[0] == "--metadata-dtor":
        mode = "metadata-dtor"
        args = args[1:]
    if args and args[0] == "--metadata-ctor":
        mode = "metadata-ctor"
        args = args[1:]
    if args and args[0] == "--metadata-operator":
        mode = "metadata-operator"
        args = args[1:]
    if args and args[0] == "--metadata-long":
        mode = "metadata-long"
        args = args[1:]
    if args and args[0] == "--shared-ptr":
        mode = "shared-ptr"
        args = args[1:]
    if len(args) != 1:
        print(
            "usage: make_macho_cpp_rtti.py [--metadata|--metadata-local|--metadata-nested-local|--metadata-nested-free|--metadata-dtor|--metadata-ctor|--metadata-operator|--metadata-long|--shared-ptr] <output-path>",
            file=sys.stderr,
        )
        return 2

    out_path = args[0]
    PAGE = 0x1000
    BASE = 0x100000000
    text_file_off = PAGE
    const_file_off = PAGE * 2
    text_vmaddr = BASE + PAGE
    const_vmaddr = BASE + PAGE * 2
    main_va = text_vmaddr
    method_count = 9 if mode in ("metadata", "metadata-local", "metadata-nested-local", "metadata-nested-free", "metadata-dtor", "metadata-ctor", "metadata-operator", "metadata-long") else 5 if mode == "shared-ptr" else 2
    method_vas = [text_vmaddr + 6 + i * 6 for i in range(method_count)]

    code = bytearray()
    code += bytes.fromhex("b801000000c3")  # main: return 1
    if mode in ("metadata", "metadata-local", "metadata-nested-local", "metadata-nested-free", "metadata-dtor", "metadata-ctor", "metadata-operator", "metadata-long"):
        returns = [10 + i for i in range(method_count)]
    elif mode == "shared-ptr":
        returns = [20 + i for i in range(method_count)]
    else:
        returns = [7, 9]
    for i in range(method_count):
        code += bytes.fromhex("b8") + struct.pack("<I", returns[i]) + bytes.fromhex("c3")
    code = bytes(code)
    const = bytearray()
    const += struct.pack("<q", 0)           # offset_to_top
    const += struct.pack("<Q", 0)           # missing typeinfo: symbol fallback must name this
    for va in method_vas:
        const += struct.pack("<Q", va)
    const += struct.pack("<Q", 0)
    const = bytes(const)

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

    link_file_off = align8(const_file_off + len(const))
    strings = bytearray(b"\0")
    sym_offs = {}

    def add_string(s):
        sym_offs[s] = len(strings)
        strings.extend(s.encode("ascii") + b"\0")

    add_string("_main")
    vtable_symbol = "__ZTVN4Core6PlayerE"
    if mode == "metadata":
        vtable_symbol = "__ZTVNSt3__110__function6__funcIZN7Example6Worker3runEvE3$_0NS_9allocatorIS4_EEFvvEEE"
    elif mode == "metadata-local":
        vtable_symbol = "__ZTVNSt3__110__function6__funcIZL32recoverFileLocalCompilerArtifactvE3$_0NS_9allocatorIS1_EEFvvEEE"
    elif mode == "metadata-nested-local":
        vtable_symbol = "__ZTVNSt3__110__function6__funcIZZN7Example6Worker3runEvENK3$_0clEvEUlvE_NS_9allocatorIS4_EEFvvEEE"
    elif mode == "metadata-nested-free":
        vtable_symbol = "__ZTVNSt3__110__function6__funcIZZ33recoverNestedFreeFunctionArtifactvENK3$_0clEvEUlvE_NS_9allocatorIS1_EEFvvEEE"
    elif mode == "metadata-dtor":
        vtable_symbol = "__ZTVNSt3__110__function6__funcIZN4Core6PlayerD1EvE3$_0NS_9allocatorIS3_EEFvvEEE"
    elif mode == "metadata-ctor":
        vtable_symbol = "__ZTVNSt3__110__function6__funcIZN4Core6PlayerC1EvE3$_0NS_9allocatorIS3_EEFvvEEE"
    elif mode == "metadata-operator":
        vtable_symbol = "__ZTVNSt3__110__function6__funcIZNK7Example6GadgeteqERKS0_E3$_0NS_9allocatorIS3_EEFvvEEE"
    elif mode == "metadata-long":
        long_name = (
            "recoverCallableTraitFromVeryLongCompilerMetadataArtifactName"
            "ThatSurvivesRttiVtableFunctionNameRecoveryAndKeepsGoingPast"
            "TheOldOneHundredSixtyCharacterLimitForStrippedBuilds"
        )
        vtable_symbol = (
            "__ZTVNSt3__110__function6__funcIZN4Core6Player"
            f"{len(long_name)}{long_name}EvE3$_0NS_9allocatorIS4_EEFvvEEE"
        )
    elif mode == "shared-ptr":
        vtable_symbol = "__ZTVNSt3__120__shared_ptr_pointerIPN7Example6WidgetENS_10shared_ptrIS3_E27__shared_ptr_default_deleteIS3_S3_EENS_9allocatorIS3_EEEE"
    add_string(vtable_symbol)
    strtab = bytes(strings)

    nlist = bytearray()
    syms = [
        ("_main", main_va, 1),
        (vtable_symbol, const_vmaddr, 2),
    ]
    for name, vm, sect in syms:
        nlist += struct.pack("<IBBHQ", sym_offs[name], 0x0F, sect, 0, vm)

    fn_starts = bytearray()
    prev = text_vmaddr
    for va in method_vas:
        fn_starts += uleb128(va - prev)
        prev = va
    fn_starts += b"\0"
    fn_starts = bytes(fn_starts)
    sym_off = link_file_off
    str_off = sym_off + len(nlist)
    fn_starts_off = align8(str_off + len(strtab))
    link_filesize = fn_starts_off + len(fn_starts) - link_file_off

    seg_link = bytearray()
    seg_link += struct.pack("<II", 0x19, 72)
    seg_link += b"__LINKEDIT".ljust(16, b"\0")
    seg_link += struct.pack("<QQQQ", const_vmaddr + PAGE, PAGE, link_file_off, link_filesize)
    seg_link += struct.pack("<IIII", 1, 1, 0, 0)

    lc_symtab = struct.pack("<IIIIII", 0x02, 24, sym_off, len(syms), str_off, len(strtab))
    lc_fnstarts = struct.pack("<IIII", 0x26, 16, fn_starts_off, len(fn_starts))
    lc_entry = struct.pack("<IIQQ", 0x80000028, 24, text_file_off, 0)
    lcs = bytes(seg_text) + bytes(seg_const) + bytes(seg_link) + lc_symtab + lc_fnstarts + lc_entry

    hdr = struct.pack(
        "<IIIIIIII",
        0xFEEDFACF,
        0x01000007,
        3,
        2,
        6,
        len(lcs),
        0x00200085,
        0,
    )

    out = bytearray()
    out += hdr
    out += lcs
    out += b"\0" * (text_file_off - len(out))
    out += code
    out += b"\0" * (const_file_off - len(out))
    out += const
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
