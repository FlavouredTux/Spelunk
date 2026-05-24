#!/usr/bin/env python3
"""Emit a tiny Mach-O with an anonymous function named by a log string."""

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
        print("usage: make_macho_string_names.py <output-path>", file=sys.stderr)
        return 2

    out_path = sys.argv[1]
    PAGE = 0x1000
    BASE = 0x100000000
    text_file_off = PAGE
    link_file_off = PAGE * 2
    text_vmaddr = BASE + PAGE
    main_va = text_vmaddr
    hidden_va = text_vmaddr + 6
    pretty_va = hidden_va + 13
    oper_va = pretty_va + 13
    dtor_va = oper_va + 13
    closure_va = dtor_va + 13
    emplace_va = closure_va + 13
    weak_result_va = emplace_va + 13
    exception_va = weak_result_va + 13
    local_va = exception_va + 13
    anon_va = local_va + 13
    free_va = anon_va + 13
    free_nested_va = free_va + 13
    mangled_dtor_va = free_nested_va + 13
    mangled_ctor_va = mangled_dtor_va + 13
    mangled_operator_va = mangled_ctor_va + 13
    mangled_conversion_va = mangled_operator_va + 13
    role_anchor_va = mangled_conversion_va + 13
    luau_telemetry_va = role_anchor_va + 13
    feature_anchor_va = luau_telemetry_va + 13

    log = b"[FLog::MacLuaApp] Core::Player::recoverName failed\0"
    pretty = b"static int recoverCachedValue(int token)\0"
    oper = b"bool Example::Box::operator==(const Example::Box&) const\0"
    dtor = b"[FLog::Lifetime] Example::Box::~Box() destroyed\0"
    closure = (
        b"NSt3__110__function6__funcIZN4Core6Player19recoverClosureValue"
        b"ENSt3__112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE"
        b"E3$_0NS5_ISB_EEFvvEEE\0"
    )
    emplace = (
        b"NSt3__120__shared_ptr_emplaceIZN4Core6Player34recoverSharedStateFromControlBlockEv"
        b"E11HiddenStateNS_9allocatorIS4_EEEE\0"
    )
    weak_result = (
        b"NSt3__118__weak_result_typeIZN4Core6Player87recoverCallableTraitFromVeryLongCompiler"
        b"MetadataArtifactNameThatSurvivesBinaryStrippingEvE3$_0EE\0"
    )
    exception_meta = (
        b"N5boost16exception_detail19error_info_injectorIN4Core6Player16HiddenExceptionEEE\0"
    )
    local_static = (
        b"NSt3__110__function6__funcIZL32recoverFileLocalCompilerArtifactvE3$_0"
        b"NS_9allocatorIS1_EEFvvEEE\0"
    )
    anon_static = (
        b"NSt3__110__function6__funcIZN12_GLOBAL__N_130recoverAnonymousNamespaceThingEv"
        b"E3$_0NS_9allocatorIS2_EEFvvEEE\0"
    )
    free_function = (
        b"NSt3__110__function6__funcIZ27recoverFreeFunctionArtifactvE3$_0"
        b"NS_9allocatorIS1_EEFvvEEE\0"
    )
    free_nested = (
        b"NSt3__110__function6__funcIZZ33recoverNestedFreeFunctionArtifactv"
        b"ENK3$_0clEvEUlvE_NS_9allocatorIS1_EEFvvEEE\0"
    )
    mangled_dtor = (
        b"NSt3__110__function6__funcIZN4Core6PlayerD1EvE3$_0"
        b"NS_9allocatorIS3_EEFvvEEE\0"
    )
    mangled_ctor = (
        b"NSt3__110__function6__funcIZN4Core6PlayerC1EvE3$_0"
        b"NS_9allocatorIS3_EEFvvEEE\0"
    )
    mangled_operator = (
        b"NSt3__110__function6__funcIZNK7Example6GadgeteqERKS0_E3$_0"
        b"NS_9allocatorIS3_EEFvvEEE\0"
    )
    mangled_conversion = (
        b"NSt3__110__function6__funcIZNK7Example4GatecvPN4Core6PlayerEEvE3$_0"
        b"NS_9allocatorIS6_EEFvvEEE\0"
    )
    role_anchor = b"SchedulerHeartbeatJob\0"
    luau_telemetry = b"luau-telemetry.bad-synchronize-call\0"
    feature_anchor = b"WorkspaceTaskQueue\0"
    # main: return 1
    main_code = bytes.fromhex("b801000000c3")
    # hidden: lea rdi, [rip + log]; mov eax, 77; ret
    hidden_len = 7 + 5 + 1
    pretty_len = 7 + 5 + 1
    oper_len = 7 + 5 + 1
    dtor_len = 7 + 5 + 1
    closure_len = 7 + 5 + 1
    emplace_len = 7 + 5 + 1
    weak_result_len = 7 + 5 + 1
    exception_len = 7 + 5 + 1
    local_len = 7 + 5 + 1
    anon_len = 7 + 5 + 1
    free_len = 7 + 5 + 1
    free_nested_len = 7 + 5 + 1
    mangled_dtor_len = 7 + 5 + 1
    mangled_ctor_len = 7 + 5 + 1
    mangled_operator_len = 7 + 5 + 1
    mangled_conversion_len = 7 + 5 + 1
    role_anchor_len = 7 + 5 + 1
    luau_telemetry_len = 7 + 5 + 1
    feature_anchor_len = 7 + 5 + 1
    string_off = align(
        len(main_code) + hidden_len + pretty_len + oper_len + dtor_len +
        closure_len + emplace_len + weak_result_len + exception_len +
        local_len + anon_len + free_len + free_nested_len + mangled_dtor_len +
        mangled_ctor_len + mangled_operator_len + mangled_conversion_len +
        role_anchor_len + luau_telemetry_len + feature_anchor_len,
        8)
    string_va = text_vmaddr + string_off
    pretty_string_va = string_va + len(log)
    oper_string_va = pretty_string_va + len(pretty)
    dtor_string_va = oper_string_va + len(oper)
    closure_string_va = dtor_string_va + len(dtor)
    emplace_string_va = closure_string_va + len(closure)
    weak_result_string_va = emplace_string_va + len(emplace)
    exception_string_va = weak_result_string_va + len(weak_result)
    local_string_va = exception_string_va + len(exception_meta)
    anon_string_va = local_string_va + len(local_static)
    free_string_va = anon_string_va + len(anon_static)
    free_nested_string_va = free_string_va + len(free_function)
    mangled_dtor_string_va = free_nested_string_va + len(free_nested)
    mangled_ctor_string_va = mangled_dtor_string_va + len(mangled_dtor)
    mangled_operator_string_va = mangled_ctor_string_va + len(mangled_ctor)
    mangled_conversion_string_va = mangled_operator_string_va + len(mangled_operator)
    role_anchor_string_va = mangled_conversion_string_va + len(mangled_conversion)
    luau_telemetry_string_va = role_anchor_string_va + len(role_anchor)
    feature_anchor_string_va = luau_telemetry_string_va + len(luau_telemetry)
    lea_next = hidden_va + 7
    disp = string_va - lea_next
    hidden_code = b"\x48\x8d\x3d" + struct.pack("<i", disp) + bytes.fromhex("b84d000000c3")
    pretty_lea_next = pretty_va + 7
    pretty_disp = pretty_string_va - pretty_lea_next
    pretty_code = b"\x48\x8d\x3d" + struct.pack("<i", pretty_disp) + bytes.fromhex("b858000000c3")
    oper_lea_next = oper_va + 7
    oper_disp = oper_string_va - oper_lea_next
    oper_code = b"\x48\x8d\x3d" + struct.pack("<i", oper_disp) + bytes.fromhex("b863000000c3")
    dtor_lea_next = dtor_va + 7
    dtor_disp = dtor_string_va - dtor_lea_next
    dtor_code = b"\x48\x8d\x3d" + struct.pack("<i", dtor_disp) + bytes.fromhex("b86f000000c3")
    closure_lea_next = closure_va + 7
    closure_disp = closure_string_va - closure_lea_next
    closure_code = (
        b"\x48\x8d\x3d" + struct.pack("<i", closure_disp) +
        bytes.fromhex("b87a000000c3")
    )
    emplace_lea_next = emplace_va + 7
    emplace_disp = emplace_string_va - emplace_lea_next
    emplace_code = (
        b"\x48\x8d\x3d" + struct.pack("<i", emplace_disp) +
        bytes.fromhex("b87b000000c3")
    )
    weak_result_lea_next = weak_result_va + 7
    weak_result_disp = weak_result_string_va - weak_result_lea_next
    weak_result_code = (
        b"\x48\x8d\x3d" + struct.pack("<i", weak_result_disp) +
        bytes.fromhex("b87c000000c3")
    )
    exception_lea_next = exception_va + 7
    exception_disp = exception_string_va - exception_lea_next
    exception_code = (
        b"\x48\x8d\x3d" + struct.pack("<i", exception_disp) +
        bytes.fromhex("b87d000000c3")
    )
    local_lea_next = local_va + 7
    local_disp = local_string_va - local_lea_next
    local_code = (
        b"\x48\x8d\x3d" + struct.pack("<i", local_disp) +
        bytes.fromhex("b87e000000c3")
    )
    anon_lea_next = anon_va + 7
    anon_disp = anon_string_va - anon_lea_next
    anon_code = (
        b"\x48\x8d\x3d" + struct.pack("<i", anon_disp) +
        bytes.fromhex("b87f000000c3")
    )
    free_lea_next = free_va + 7
    free_disp = free_string_va - free_lea_next
    free_code = (
        b"\x48\x8d\x3d" + struct.pack("<i", free_disp) +
        bytes.fromhex("b880000000c3")
    )
    free_nested_lea_next = free_nested_va + 7
    free_nested_disp = free_nested_string_va - free_nested_lea_next
    free_nested_code = (
        b"\x48\x8d\x3d" + struct.pack("<i", free_nested_disp) +
        bytes.fromhex("b881000000c3")
    )
    mangled_dtor_lea_next = mangled_dtor_va + 7
    mangled_dtor_disp = mangled_dtor_string_va - mangled_dtor_lea_next
    mangled_dtor_code = (
        b"\x48\x8d\x3d" + struct.pack("<i", mangled_dtor_disp) +
        bytes.fromhex("b882000000c3")
    )
    mangled_ctor_lea_next = mangled_ctor_va + 7
    mangled_ctor_disp = mangled_ctor_string_va - mangled_ctor_lea_next
    mangled_ctor_code = (
        b"\x48\x8d\x3d" + struct.pack("<i", mangled_ctor_disp) +
        bytes.fromhex("b883000000c3")
    )
    mangled_operator_lea_next = mangled_operator_va + 7
    mangled_operator_disp = mangled_operator_string_va - mangled_operator_lea_next
    mangled_operator_code = (
        b"\x48\x8d\x3d" + struct.pack("<i", mangled_operator_disp) +
        bytes.fromhex("b884000000c3")
    )
    mangled_conversion_lea_next = mangled_conversion_va + 7
    mangled_conversion_disp = mangled_conversion_string_va - mangled_conversion_lea_next
    mangled_conversion_code = (
        b"\x48\x8d\x3d" + struct.pack("<i", mangled_conversion_disp) +
        bytes.fromhex("b885000000c3")
    )
    role_anchor_lea_next = role_anchor_va + 7
    role_anchor_disp = role_anchor_string_va - role_anchor_lea_next
    role_anchor_code = (
        b"\x48\x8d\x3d" + struct.pack("<i", role_anchor_disp) +
        bytes.fromhex("b886000000c3")
    )
    luau_telemetry_lea_next = luau_telemetry_va + 7
    luau_telemetry_disp = luau_telemetry_string_va - luau_telemetry_lea_next
    luau_telemetry_code = (
        b"\x48\x8d\x3d" + struct.pack("<i", luau_telemetry_disp) +
        bytes.fromhex("b887000000c3")
    )
    feature_anchor_lea_next = feature_anchor_va + 7
    feature_anchor_disp = feature_anchor_string_va - feature_anchor_lea_next
    feature_anchor_code = (
        b"\x48\x8d\x3d" + struct.pack("<i", feature_anchor_disp) +
        bytes.fromhex("b888000000c3")
    )
    code = (
        main_code + hidden_code + pretty_code + oper_code + dtor_code +
        closure_code + emplace_code + weak_result_code + exception_code +
        local_code + anon_code + free_code + free_nested_code +
        mangled_dtor_code + mangled_ctor_code + mangled_operator_code +
        mangled_conversion_code + role_anchor_code + luau_telemetry_code +
        feature_anchor_code
    )
    cstring_size = (
        len(log) + len(pretty) + len(oper) + len(dtor) + len(closure) +
        len(emplace) + len(weak_result) + len(exception_meta) +
        len(local_static) + len(anon_static) + len(free_function) +
        len(free_nested) + len(mangled_dtor) + len(mangled_ctor) +
        len(mangled_operator) + len(mangled_conversion) + len(role_anchor) +
        len(luau_telemetry) + len(feature_anchor)
    )
    text_filesize = string_off + cstring_size

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
    seg_text += struct.pack("<QQ", string_va, cstring_size)
    seg_text += struct.pack("<II", text_file_off + string_off, 3)
    seg_text += struct.pack("<IIIIII", 0, 0, 0x2, 0, 0, 0)

    strings = bytearray(b"\0")
    main_name_off = len(strings)
    strings += b"_main\0"
    strtab = bytes(strings)
    nlist = struct.pack("<IBBHQ", main_name_off, 0x0F, 1, 0, main_va)

    fn_starts = (
        uleb128(hidden_va - text_vmaddr) +
        uleb128(pretty_va - hidden_va) +
        uleb128(oper_va - pretty_va) +
        uleb128(dtor_va - oper_va) +
        uleb128(closure_va - dtor_va) +
        uleb128(emplace_va - closure_va) +
        uleb128(weak_result_va - emplace_va) +
        uleb128(exception_va - weak_result_va) +
        uleb128(local_va - exception_va) +
        uleb128(anon_va - local_va) +
        uleb128(free_va - anon_va) +
        uleb128(free_nested_va - free_va) +
        uleb128(mangled_dtor_va - free_nested_va) +
        uleb128(mangled_ctor_va - mangled_dtor_va) +
        uleb128(mangled_operator_va - mangled_ctor_va) +
        uleb128(mangled_conversion_va - mangled_operator_va) +
        uleb128(role_anchor_va - mangled_conversion_va) +
        uleb128(luau_telemetry_va - role_anchor_va) +
        uleb128(feature_anchor_va - luau_telemetry_va) +
        b"\0"
    )
    sym_off = link_file_off
    str_off = sym_off + len(nlist)
    fn_starts_off = align8(str_off + len(strtab))
    link_filesize = fn_starts_off + len(fn_starts) - link_file_off

    seg_link = bytearray()
    seg_link += struct.pack("<II", 0x19, 72)
    seg_link += b"__LINKEDIT".ljust(16, b"\0")
    seg_link += struct.pack("<QQQQ", text_vmaddr + PAGE, PAGE, link_file_off, link_filesize)
    seg_link += struct.pack("<IIII", 1, 1, 0, 0)

    lc_symtab = struct.pack("<IIIIII", 0x02, 24, sym_off, 1, str_off, len(strtab))
    lc_fnstarts = struct.pack("<IIII", 0x26, 16, fn_starts_off, len(fn_starts))
    lc_entry = struct.pack("<IIQQ", 0x80000028, 24, text_file_off, 0)
    lcs = bytes(seg_text) + bytes(seg_link) + lc_symtab + lc_fnstarts + lc_entry
    hdr = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x01000007, 3, 2, 5, len(lcs), 0x00200085, 0)

    out = bytearray()
    out += hdr
    out += lcs
    out += b"\0" * (text_file_off - len(out))
    out += code
    out += b"\0" * (text_file_off + string_off - len(out))
    out += log
    out += pretty
    out += oper
    out += dtor
    out += closure
    out += emplace
    out += weak_result
    out += exception_meta
    out += local_static
    out += anon_static
    out += free_function
    out += free_nested
    out += mangled_dtor
    out += mangled_ctor
    out += mangled_operator
    out += mangled_conversion
    out += role_anchor
    out += luau_telemetry
    out += feature_anchor
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
