#!/usr/bin/env python3
"""Emit a tiny arm64 Mach-O that imports getpid through arm64e fixup chains.

The fixture has:
  main:    bl __stubs._getpid; mov w0, #0; ret
  read_rebased: load a chained-rebased pointer, then load the target value
  __stubs: adrp x16, __la_symbol_ptr; ldr x16, [x16]; br x16

There is intentionally no undefined nlist row for _getpid. The only import
name lives in LC_DYLD_CHAINED_FIXUPS as an ARM64E_USERLAND24 bind, so the
loader must synthesize the import and then connect the arm64 stub to it.
With --import-addend or --import-addend64, the chained imports table uses
DYLD_CHAINED_IMPORT_ADDEND or DYLD_CHAINED_IMPORT_ADDEND64 to exercise the
alternate name-offset encodings. With --auth-rebase, the chained rebase
pointer uses the authenticated arm64e rebase layout.
"""

import struct
import sys


PAGE = 0x1000
BASE = 0x100000000


def align8(v):
    return (v + 7) & ~7


def enc_bl(pc, target):
    imm26 = ((target - pc) >> 2) & 0x03FFFFFF
    return struct.pack("<I", 0x94000000 | imm26)


def enc_adrp(rd, pc, target):
    pc_page = pc & ~0xFFF
    target_page = target & ~0xFFF
    imm = (target_page - pc_page) >> 12
    imm &= (1 << 21) - 1
    immlo = imm & 0x3
    immhi = imm >> 2
    return struct.pack("<I", 0x90000000 | (immlo << 29) | (immhi << 5) | rd)


def enc_ldr_x(rt, rn, byte_off):
    return struct.pack("<I", 0xF9400000 | ((byte_off // 8) << 10) | (rn << 5) | rt)


def enc_ldr_w(rt, rn, byte_off):
    return struct.pack("<I", 0xB9400000 | ((byte_off // 4) << 10) | (rn << 5) | rt)


def enc_br(rn):
    return struct.pack("<I", 0xD61F0000 | (rn << 5))


def cstr_table(names):
    data = bytearray(b"\0")
    offs = {}
    for name in names:
        offs[name] = len(data)
        data.extend(name.encode("ascii") + b"\0")
    return bytes(data), offs


def main() -> int:
    args = sys.argv[1:]
    mode = "plain"
    if args and args[0] == "--auth-rebase":
        mode = "auth-rebase"
        args = args[1:]
    elif args and args[0] == "--import-addend":
        mode = "import-addend"
        args = args[1:]
    elif args and args[0] == "--import-addend64":
        mode = "import-addend64"
        args = args[1:]
    if len(args) != 1:
        print("usage: make_macho_arm64e_import.py "
              "[--auth-rebase|--import-addend|--import-addend64] "
              "<output-path>",
              file=sys.stderr)
        return 2
    out_path = args[0]

    text_file_off = PAGE
    data_file_off = PAGE * 2
    text_segment_vmaddr = BASE
    text_vmaddr = BASE + PAGE
    data_vmaddr = BASE + PAGE * 2
    main_vmaddr = text_vmaddr
    read_rebased_vmaddr = text_vmaddr + 12
    stub_vmaddr = text_vmaddr + 28
    slot_vmaddr = data_vmaddr
    rebase_slot_vmaddr = data_vmaddr + 8
    target_vmaddr = data_vmaddr + 16

    main_code = (
        enc_bl(main_vmaddr, stub_vmaddr) +
        struct.pack("<I", 0x52800000) +
        struct.pack("<I", 0xD65F03C0)
    )
    read_rebased_code = (
        enc_adrp(8, read_rebased_vmaddr, rebase_slot_vmaddr) +
        enc_ldr_x(8, 8, rebase_slot_vmaddr & 0xFFF) +
        enc_ldr_w(0, 8, 0) +
        struct.pack("<I", 0xD65F03C0)
    )
    stub_code = (
        enc_adrp(16, stub_vmaddr, slot_vmaddr) +
        enc_ldr_x(16, 16, slot_vmaddr & 0xFFF) +
        enc_br(16)
    )
    code = main_code + read_rebased_code + stub_code
    data = b"\0" * 8 + b"\0" * 8 + struct.pack("<I", 0xCAFEBABE)

    seg_text = bytearray()
    seg_text += struct.pack("<II", 0x19, 72 + 2 * 80)
    seg_text += b"__TEXT".ljust(16, b"\0")
    seg_text += struct.pack("<QQQQ", text_segment_vmaddr, PAGE * 2,
                            0, text_file_off + len(code))
    seg_text += struct.pack("<IIII", 5, 5, 2, 0)
    seg_text += b"__text".ljust(16, b"\0")
    seg_text += b"__TEXT".ljust(16, b"\0")
    seg_text += struct.pack("<QQ", main_vmaddr, len(main_code) + len(read_rebased_code))
    seg_text += struct.pack("<II", text_file_off, 2)
    seg_text += struct.pack("<IIIIII", 0, 0, 0x80000400, 0, 0, 0)
    seg_text += b"__stubs".ljust(16, b"\0")
    seg_text += b"__TEXT".ljust(16, b"\0")
    seg_text += struct.pack("<QQ", stub_vmaddr, len(stub_code))
    seg_text += struct.pack("<II", text_file_off + len(main_code) + len(read_rebased_code), 2)
    seg_text += struct.pack("<IIIIII", 0, 0, 0x80000408, 0, 12, 0)

    seg_data = bytearray()
    seg_data += struct.pack("<II", 0x19, 72 + 80)
    seg_data += b"__DATA".ljust(16, b"\0")
    seg_data += struct.pack("<QQQQ", data_vmaddr, PAGE, data_file_off, len(data))
    seg_data += struct.pack("<IIII", 3, 3, 1, 0)
    seg_data += b"__la_symbol_ptr".ljust(16, b"\0")
    seg_data += b"__DATA".ljust(16, b"\0")
    seg_data += struct.pack("<QQ", slot_vmaddr, len(data))
    seg_data += struct.pack("<II", data_file_off, 3)
    seg_data += struct.pack("<IIIIII", 0, 0, 0, 0, 0, 0)

    strtab, str_offs = cstr_table(["_main", "_read_rebased", "_g_target"])
    nlist = struct.pack("<IBBHQ", str_offs["_main"], 0x0F, 1, 0, main_vmaddr)
    nlist += struct.pack("<IBBHQ", str_offs["_read_rebased"], 0x0F, 1, 0, read_rebased_vmaddr)
    nlist += struct.pack("<IBBHQ", str_offs["_g_target"], 0x0F, 2, 0, target_vmaddr)

    chain = bytearray()
    starts_off = 32
    seg_count = 3
    starts_in_image_size = 4 + seg_count * 4
    data_seg_info_off = starts_in_image_size
    starts = bytearray()
    starts += struct.pack("<I", seg_count)
    starts += struct.pack("<III", 0, data_seg_info_off, 0)
    starts += struct.pack("<IHHQIH",
                          24, PAGE, 12, data_vmaddr - BASE, 0,
                          1)  # ARM64E_USERLAND24
    starts += struct.pack("<H", 0)
    imports_off = starts_off + len(starts)
    import_entry_size = 16 if mode == "import-addend64" else (
        8 if mode == "import-addend" else 4)
    imports_format = 3 if mode == "import-addend64" else (
        2 if mode == "import-addend" else 1)
    symbols_off = imports_off + import_entry_size
    symbols = b"_getpid\0"
    if mode == "import-addend64":
        # dyld_chained_import_addend64:
        #   lib_ordinal:16, weak_import:1, reserved:15, name_offset:32
        #   addend:64
        import_entry = struct.pack("<QQ", 0, 0)
    elif mode == "import-addend":
        # dyld_chained_import_addend:
        #   lib_ordinal:8, weak_import:1, name_offset:23
        #   addend:32
        import_entry = struct.pack("<II", 0, 0)
    else:
        import_entry = struct.pack("<I", 0)  # lib_ordinal=0, weak=0, name_offset=0
    chain += struct.pack(
        "<IIIIIII", 0, starts_off, imports_off, symbols_off, 1,
        imports_format, 0)
    chain += b"\0" * (starts_off - len(chain))
    chain += starts
    chain += import_entry
    chain += symbols

    # The bound pointer in __DATA,__la_symbol_ptr links to the rebase pointer
    # in the same chain. The second pointer is rebased to _g_target.
    data = struct.pack("<Q", (1 << 62) | (1 << 51))
    if mode == "auth-rebase":
        data += struct.pack("<Q", (1 << 63) | (target_vmaddr - BASE))
    else:
        data += struct.pack("<Q", target_vmaddr - BASE)
    data += struct.pack("<I", 0xCAFEBABE)

    link_file_off = align8(data_file_off + len(data))
    sym_off = link_file_off
    str_off = sym_off + len(nlist)
    chain_off = align8(str_off + len(strtab))
    link_filesize = chain_off + len(chain) - link_file_off

    seg_link = bytearray()
    seg_link += struct.pack("<II", 0x19, 72)
    seg_link += b"__LINKEDIT".ljust(16, b"\0")
    seg_link += struct.pack("<QQQQ", data_vmaddr + PAGE, PAGE, link_file_off, link_filesize)
    seg_link += struct.pack("<IIII", 1, 1, 0, 0)

    lc_symtab = struct.pack("<IIIIII", 0x02, 24, sym_off, 3, str_off, len(strtab))
    lc_fixups = struct.pack("<IIII", 0x80000034, 16, chain_off, len(chain))
    lc_main = struct.pack("<IIQQ", 0x80000028, 24, text_file_off, 0)

    lcs = bytes(seg_text) + bytes(seg_data) + bytes(seg_link) + lc_symtab + lc_fixups + lc_main
    hdr = struct.pack("<IIIIIIII",
                      0xFEEDFACF, 0x0100000C, 0, 2,
                      6, len(lcs), 0x00200085, 0)

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
    out += b"\0" * (chain_off - len(out))
    out += chain

    with open(out_path, "wb") as f:
        f.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
