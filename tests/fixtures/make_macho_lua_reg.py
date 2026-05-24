#!/usr/bin/env python3
"""Emit a tiny Mach-O with a stripped Lua-style C function registration table."""

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
    if len(sys.argv) != 2:
        print("usage: make_macho_lua_reg.py <output-path>", file=sys.stderr)
        return 2

    out_path = sys.argv[1]
    PAGE = 0x1000
    BASE = 0x100000000
    text_file_off = PAGE
    data_file_off = PAGE * 2
    link_file_off = PAGE * 3
    text_vmaddr = BASE + PAGE
    data_vmaddr = BASE + PAGE * 2
    main_va = text_vmaddr
    cfunc_va = text_vmaddr + 6
    metadata_fn_va = cfunc_va + 6
    const_metadata_fn_va = metadata_fn_va + 13
    local_metadata_fn_va = const_metadata_fn_va + 13
    reflect_metadata_fn_va = local_metadata_fn_va + 13
    reflect_event_fn_va = reflect_metadata_fn_va + 20
    reflect_property_fn_va = reflect_event_fn_va + 20

    main_code = bytes.fromhex("b800000000c3")
    cfunc_code = bytes.fromhex("b833000000c3")
    metadata_len = 7 + 5 + 1
    reflect_metadata_len = 7 * 2 + 5 + 1

    key = b"tick\0"
    metadata = b"ZN6Engine10ScriptHost6resumeEP9lua_StateE3$_0\0"
    const_metadata = b"ZNK6Engine10ScriptHost7inspectEP9lua_StateE3$_1\0"
    local_metadata = b"ZZN6Engine10ScriptHost8dispatchEP9lua_StateENK3$_2clEvE\0"
    reflect_member = b"performAction\0"
    reflect_metadata = b"N6Engine10Reflection13BoundFuncDescIN6Engine10ScriptHostEFviiELb0ELi2EEE\0"
    reflect_event_member = b"actionSignal\0"
    reflect_event = (
        b"N6Engine10Reflection9EventDescIN6Engine10ScriptHostEFviEN3rbx6signalIiEEMS2_FviEEE\0"
    )
    reflect_property_member = b"actionLevel\0"
    reflect_property = b"N6Engine10Reflection14PropDescriptorIN6Engine10ScriptHostEiEE\0"
    reflect_enum_property = (
        b"N6Engine10Reflection18EnumPropDescriptorIN6Engine10ScriptHostENS_10ActionTypeEEE\0"
    )
    string_off = align(
        len(main_code) + len(cfunc_code) + metadata_len * 3 +
        reflect_metadata_len * 3, 8)
    key_va = text_vmaddr + string_off
    metadata_va = key_va + len(key)
    const_metadata_va = metadata_va + len(metadata)
    local_metadata_va = const_metadata_va + len(const_metadata)
    reflect_member_va = local_metadata_va + len(local_metadata)
    reflect_metadata_va = reflect_member_va + len(reflect_member)
    reflect_event_member_va = reflect_metadata_va + len(reflect_metadata)
    reflect_event_va = reflect_event_member_va + len(reflect_event_member)
    reflect_property_member_va = reflect_event_va + len(reflect_event)
    reflect_property_va = reflect_property_member_va + len(reflect_property_member)
    metadata_next = metadata_fn_va + 7
    metadata_disp = metadata_va - metadata_next
    metadata_code = (
        b"\x48\x8d\x3d" + struct.pack("<i", metadata_disp) +
        bytes.fromhex("b844000000c3")
    )
    const_metadata_next = const_metadata_fn_va + 7
    const_metadata_disp = const_metadata_va - const_metadata_next
    const_metadata_code = (
        b"\x48\x8d\x3d" + struct.pack("<i", const_metadata_disp) +
        bytes.fromhex("b855000000c3")
    )
    local_metadata_next = local_metadata_fn_va + 7
    local_metadata_disp = local_metadata_va - local_metadata_next
    local_metadata_code = (
        b"\x48\x8d\x3d" + struct.pack("<i", local_metadata_disp) +
        bytes.fromhex("b866000000c3")
    )
    def rip_lea(opcode: bytes, instr_va: int, target_va: int) -> bytes:
        return opcode + struct.pack("<i", target_va - (instr_va + 7))

    def reflection_pair_code(fn_va: int, member_va: int, desc_va: int, ret_imm: int) -> bytes:
        code = bytearray()
        code += rip_lea(b"\x48\x8d\x3d", fn_va, member_va)
        code += rip_lea(b"\x48\x8d\x35", fn_va + 7, desc_va)
        code += b"\xb8" + struct.pack("<I", ret_imm) + b"\xc3"
        return bytes(code)

    reflect_metadata_code = reflection_pair_code(
        reflect_metadata_fn_va, reflect_member_va, reflect_metadata_va, 0x77)
    reflect_event_code = reflection_pair_code(
        reflect_event_fn_va, reflect_event_member_va, reflect_event_va, 0x88)
    reflect_property_code = reflection_pair_code(
        reflect_property_fn_va, reflect_property_member_va, reflect_property_va, 0x99)
    code = (
        main_code + cfunc_code + metadata_code +
        const_metadata_code + local_metadata_code + reflect_metadata_code +
        reflect_event_code + reflect_property_code
    )
    cstring_size = (
        len(key) + len(metadata) + len(const_metadata) +
        len(local_metadata) + len(reflect_member) + len(reflect_metadata) +
        len(reflect_event_member) + len(reflect_event) +
        len(reflect_property_member) + len(reflect_property) +
        len(reflect_enum_property)
    )
    text_filesize = string_off + cstring_size

    reg_table = struct.pack("<QQQQ", key_va, cfunc_va, 0, 0)

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
    seg_text += b"__cstring".ljust(16, b"\0")
    seg_text += b"__TEXT".ljust(16, b"\0")
    seg_text += struct.pack("<QQ", key_va, cstring_size)
    seg_text += struct.pack("<II", text_file_off + string_off, 3)
    seg_text += struct.pack("<IIIIII", 0, 0, 0x2, 0, 0, 0)

    seg_data = bytearray()
    seg_data += struct.pack("<II", 0x19, 72 + 80)
    seg_data += b"__DATA_CONST".ljust(16, b"\0")
    seg_data += struct.pack("<QQQQ", data_vmaddr, PAGE, data_file_off, len(reg_table))
    seg_data += struct.pack("<IIII", 3, 3, 1, 0)
    seg_data += b"__const".ljust(16, b"\0")
    seg_data += b"__DATA_CONST".ljust(16, b"\0")
    seg_data += struct.pack("<QQ", data_vmaddr, len(reg_table))
    seg_data += struct.pack("<II", data_file_off, 3)
    seg_data += struct.pack("<IIIIII", 0, 0, 0, 0, 0, 0)

    strings = bytearray(b"\0")
    main_name_off = len(strings)
    strings += b"_main\0"
    strtab = bytes(strings)
    nlist = struct.pack("<IBBHQ", main_name_off, 0x0F, 1, 0, main_va)

    fn_starts = (
        uleb128(cfunc_va - text_vmaddr) +
        uleb128(metadata_fn_va - cfunc_va) +
        uleb128(const_metadata_fn_va - metadata_fn_va) +
        uleb128(local_metadata_fn_va - const_metadata_fn_va) +
        uleb128(reflect_metadata_fn_va - local_metadata_fn_va) +
        uleb128(reflect_event_fn_va - reflect_metadata_fn_va) +
        uleb128(reflect_property_fn_va - reflect_event_fn_va) +
        b"\0"
    )
    sym_off = link_file_off
    str_off = sym_off + len(nlist)
    fn_starts_off = align8(str_off + len(strtab))
    link_filesize = fn_starts_off + len(fn_starts) - link_file_off

    seg_link = bytearray()
    seg_link += struct.pack("<II", 0x19, 72)
    seg_link += b"__LINKEDIT".ljust(16, b"\0")
    seg_link += struct.pack("<QQQQ", BASE + PAGE * 3, PAGE, link_file_off, link_filesize)
    seg_link += struct.pack("<IIII", 1, 1, 0, 0)

    lc_symtab = struct.pack("<IIIIII", 0x02, 24, sym_off, 1, str_off, len(strtab))
    lc_fnstarts = struct.pack("<IIII", 0x26, 16, fn_starts_off, len(fn_starts))
    lc_entry = struct.pack("<IIQQ", 0x80000028, 24, text_file_off, 0)
    lcs = bytes(seg_text) + bytes(seg_data) + bytes(seg_link) + lc_symtab + lc_fnstarts + lc_entry
    hdr = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x01000007, 3, 2, 6, len(lcs), 0x00200085, 0)

    out = bytearray()
    out += hdr
    out += lcs
    out += b"\0" * (text_file_off - len(out))
    out += code
    out += b"\0" * (text_file_off + string_off - len(out))
    out += key
    out += metadata
    out += const_metadata
    out += local_metadata
    out += reflect_member
    out += reflect_metadata
    out += reflect_event_member
    out += reflect_event
    out += reflect_property_member
    out += reflect_property
    out += reflect_enum_property
    out += b"\0" * (data_file_off - len(out))
    out += reg_table
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
