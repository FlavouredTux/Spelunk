#!/usr/bin/env python3
"""Emit a tiny x86_64 Mach-O with an ObjC stack-passed selector argument."""

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
    nil_varargs = bool(args and args[0] == "--nil-varargs")
    if nil_varargs:
        args = args[1:]
    if len(args) != 1:
        print("usage: make_macho_objc_stack_arg.py <output-path>", file=sys.stderr)
        return 2
    out_path = args[0]

    text_file_off = PAGE
    data_file_off = PAGE * 2
    text_vmaddr = BASE + PAGE
    data_vmaddr = BASE + PAGE * 2
    main_vmaddr = text_vmaddr
    msg_slot_vmaddr = data_vmaddr
    store_slot_vmaddr = data_vmaddr + 8
    release_slot_vmaddr = data_vmaddr + 16
    getprop_slot_vmaddr = data_vmaddr + 24
    setprop_slot_vmaddr = data_vmaddr + 32
    claim_slot_vmaddr = data_vmaddr + 40
    begin_catch_slot_vmaddr = data_vmaddr + 48
    nonatomic_setprop_slot_vmaddr = data_vmaddr + 56
    selref_vmaddr = data_vmaddr + 64
    methname_vmaddr = data_vmaddr + 72

    code = bytearray()

    def emit(b):
        code.extend(b)

    emit(b"\x55")                             # push rbp
    emit(b"\x48\x89\xe5")                     # mov rbp, rsp
    emit(b"\x48\x83\xec\x30")                 # sub rsp, 0x30
    dummy_call_off = len(code)
    emit(b"\xe8\x00\x00\x00\x00")             # clobber caller-saved regs
    emit(b"\x48\x8d\x7d\xf0")                 # lea rdi, [rbp - 0x10]
    emit(b"\xbe\x77\x07\x00\x00")             # mov esi, 0x777
    store_call_off = len(code)
    emit(b"\xe8\x00\x00\x00\x00")             # objc_storeStrong
    emit(b"\xbf\x88\x08\x00\x00")             # mov edi, 0x888
    release_call_off = len(code)
    emit(b"\xe8\x00\x00\x00\x00")             # objc_release
    emit(b"\x48\x89\xc7")                     # mov rdi, rax (stale void result)
    stale_call_off = len(code)
    emit(b"\xe8\x00\x00\x00\x00")             # must not consume objc_release result
    emit(b"\xbf\x11\x11\x00\x00")             # mov edi, 0x1111
    emit(b"\xbe\x22\x22\x00\x00")             # mov esi, 0x2222
    emit(b"\xba\x08\x00\x00\x00")             # mov edx, 8
    emit(b"\xb9\x01\x00\x00\x00")             # mov ecx, 1
    emit(b"\x41\xb8\x99\x09\x00\x00")         # mov r8d, 0x999 (stale extra)
    getprop_call_off = len(code)
    emit(b"\xe8\x00\x00\x00\x00")             # objc_getProperty
    emit(b"\xbf\x11\x11\x00\x00")             # mov edi, 0x1111
    emit(b"\xbe\x22\x22\x00\x00")             # mov esi, 0x2222
    emit(b"\xba\x33\x33\x00\x00")             # mov edx, 0x3333
    emit(b"\xb9\x08\x00\x00\x00")             # mov ecx, 8
    emit(b"\x41\xb8\x99\x09\x00\x00")         # mov r8d, 0x999 (stale extra)
    setprop_call_off = len(code)
    emit(b"\xe8\x00\x00\x00\x00")             # objc_setProperty_atomic_copy
    emit(b"\xbf\x11\x11\x00\x00")             # mov edi, 0x1111
    emit(b"\xbe\x22\x22\x00\x00")             # mov esi, 0x2222
    emit(b"\xba\x44\x44\x00\x00")             # mov edx, 0x4444
    emit(b"\xb9\x08\x00\x00\x00")             # mov ecx, 8
    emit(b"\x41\xb8\x99\x09\x00\x00")         # mov r8d, 0x999 (stale extra)
    nonatomic_setprop_call_off = len(code)
    emit(b"\xe8\x00\x00\x00\x00")             # objc_setProperty_nonatomic
    emit(b"\xbf\x11\x11\x00\x00")             # mov edi, 0x1111
    emit(b"\xbe\x22\x22\x00\x00")             # mov esi, 0x2222
    emit(b"\xba\x08\x00\x00\x00")             # mov edx, 8
    emit(b"\xb9\x01\x00\x00\x00")             # mov ecx, 1
    claim_source_call_off = len(code)
    emit(b"\xe8\x00\x00\x00\x00")             # objc_getProperty
    emit(b"\x48\x89\xc7")                     # mov rdi, rax
    claim_call_off = len(code)
    emit(b"\xe8\x00\x00\x00\x00")             # objc_unsafeClaimAutoreleasedReturnValue
    emit(b"\xbf\x44\x44\x00\x00")             # mov edi, 0x4444
    begin_catch_call_off = len(code)
    emit(b"\xe8\x00\x00\x00\x00")             # objc_begin_catch
    emit(b"\x48\x89\xc7")                     # mov rdi, rax
    catch_use_call_off = len(code)
    emit(b"\xe8\x00\x00\x00\x00")             # objc_release consumes catch object
    emit(b"\xbf\x55\x55\x00\x00")             # mov edi, 0x5555
    emit(b"\xbe\x99\x09\x00\x00")             # mov esi, 0x999 (stale extra)
    standalone_claim_call_off = len(code)
    emit(b"\xe8\x00\x00\x00\x00")             # objc_unsafeClaimAutoreleasedReturnValue
    emit(b"\xbf\x34\x12\x00\x00")             # mov edi, 0x1234
    ip = main_vmaddr + len(code)
    emit(b"\x48\x8b\x35" + struct.pack("<i", selref_vmaddr - (ip + 7)))
    emit(b"\xba\x78\x56\x00\x00")             # mov edx, 0x5678
    emit(b"\x48\xc7\x04\x24\x00\x00\x00\x00") # mov qword ptr [rsp], 0
    emit(b"\x48\xc7\x44\x24\x08\x00\x00\x00\x00")
    emit(b"\x48\xc7\x44\x24\x10\x00\x00\x00\x00")
    emit(b"\x48\xc7\x44\x24\x18\x00\x00\x00\x00")
    if nil_varargs:
        # Three object/key pairs cross the SysV register/stack boundary.
        emit(b"\xba\x11\x00\x00\x00")
        emit(b"\xb9\x22\x00\x00\x00")
        emit(b"\x41\xb8\x33\x00\x00\x00")
        emit(b"\x41\xb9\x44\x00\x00\x00")
        emit(b"\x48\xc7\x04\x24\x55\x00\x00\x00")
        emit(b"\x48\xc7\x44\x24\x08\x66\x00\x00\x00")
    call_off = len(code)
    emit(b"\xe8\x00\x00\x00\x00")             # patched below
    emit(b"\x31\xc0")                         # xor eax, eax
    emit(b"\xc9\xc3")                         # leave; ret

    stub_msg_vmaddr = main_vmaddr + len(code)
    code[dummy_call_off + 1:dummy_call_off + 5] = struct.pack(
        "<i", stub_msg_vmaddr - (main_vmaddr + dummy_call_off + 5))
    code[stale_call_off + 1:stale_call_off + 5] = struct.pack(
        "<i", stub_msg_vmaddr - (main_vmaddr + stale_call_off + 5))
    code[call_off + 1:call_off + 5] = struct.pack(
        "<i", stub_msg_vmaddr - (main_vmaddr + call_off + 5))
    emit(b"\xff\x25" + struct.pack("<i", msg_slot_vmaddr - (stub_msg_vmaddr + 6)))
    stub_store_vmaddr = main_vmaddr + len(code)
    code[store_call_off + 1:store_call_off + 5] = struct.pack(
        "<i", stub_store_vmaddr - (main_vmaddr + store_call_off + 5))
    emit(b"\xff\x25" + struct.pack("<i", store_slot_vmaddr - (stub_store_vmaddr + 6)))
    stub_release_vmaddr = main_vmaddr + len(code)
    code[release_call_off + 1:release_call_off + 5] = struct.pack(
        "<i", stub_release_vmaddr - (main_vmaddr + release_call_off + 5))
    emit(b"\xff\x25" + struct.pack("<i", release_slot_vmaddr - (stub_release_vmaddr + 6)))
    stub_getprop_vmaddr = main_vmaddr + len(code)
    code[getprop_call_off + 1:getprop_call_off + 5] = struct.pack(
        "<i", stub_getprop_vmaddr - (main_vmaddr + getprop_call_off + 5))
    emit(b"\xff\x25" + struct.pack("<i", getprop_slot_vmaddr - (stub_getprop_vmaddr + 6)))
    stub_setprop_vmaddr = main_vmaddr + len(code)
    code[setprop_call_off + 1:setprop_call_off + 5] = struct.pack(
        "<i", stub_setprop_vmaddr - (main_vmaddr + setprop_call_off + 5))
    emit(b"\xff\x25" + struct.pack("<i", setprop_slot_vmaddr - (stub_setprop_vmaddr + 6)))
    stub_nonatomic_setprop_vmaddr = main_vmaddr + len(code)
    code[nonatomic_setprop_call_off + 1:nonatomic_setprop_call_off + 5] = struct.pack(
        "<i", stub_nonatomic_setprop_vmaddr - (main_vmaddr + nonatomic_setprop_call_off + 5))
    emit(b"\xff\x25" + struct.pack(
        "<i", nonatomic_setprop_slot_vmaddr - (stub_nonatomic_setprop_vmaddr + 6)))
    code[claim_source_call_off + 1:claim_source_call_off + 5] = struct.pack(
        "<i", stub_getprop_vmaddr - (main_vmaddr + claim_source_call_off + 5))
    stub_claim_vmaddr = main_vmaddr + len(code)
    code[claim_call_off + 1:claim_call_off + 5] = struct.pack(
        "<i", stub_claim_vmaddr - (main_vmaddr + claim_call_off + 5))
    emit(b"\xff\x25" + struct.pack("<i", claim_slot_vmaddr - (stub_claim_vmaddr + 6)))
    code[standalone_claim_call_off + 1:standalone_claim_call_off + 5] = struct.pack(
        "<i", stub_claim_vmaddr - (main_vmaddr + standalone_claim_call_off + 5))
    stub_begin_catch_vmaddr = main_vmaddr + len(code)
    code[begin_catch_call_off + 1:begin_catch_call_off + 5] = struct.pack(
        "<i", stub_begin_catch_vmaddr - (main_vmaddr + begin_catch_call_off + 5))
    emit(b"\xff\x25" + struct.pack("<i", begin_catch_slot_vmaddr - (stub_begin_catch_vmaddr + 6)))
    code[catch_use_call_off + 1:catch_use_call_off + 5] = struct.pack(
        "<i", stub_release_vmaddr - (main_vmaddr + catch_use_call_off + 5))

    main_code_size = stub_msg_vmaddr - main_vmaddr
    data = (
        struct.pack(
            "<QQQQQQQQQ",
            stub_msg_vmaddr + 6,
            stub_store_vmaddr + 6,
            stub_release_vmaddr + 6,
            stub_getprop_vmaddr + 6,
            stub_setprop_vmaddr + 6,
            stub_claim_vmaddr + 6,
            stub_begin_catch_vmaddr + 6,
            stub_nonatomic_setprop_vmaddr + 6,
            methname_vmaddr,
        ) +
        (b"initWithObjectsAndKeys:\0" if nil_varargs else b"initWithFrame:configuration:\0")
    )

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
    seg_text += struct.pack("<QQ", stub_msg_vmaddr, len(code) - main_code_size)
    seg_text += struct.pack("<II", text_file_off + main_code_size, 2)
    seg_text += struct.pack("<IIIIII", 0, 0, 0x80000408, 0, 6, 0)

    seg_data = bytearray()
    seg_data += struct.pack("<II", 0x19, 72 + 3 * 80)
    seg_data += b"__DATA".ljust(16, b"\0")
    seg_data += struct.pack("<QQQQ", data_vmaddr, PAGE, data_file_off, len(data))
    seg_data += struct.pack("<IIII", 3, 3, 3, 0)
    seg_data += b"__la_symbol_ptr".ljust(16, b"\0")
    seg_data += b"__DATA".ljust(16, b"\0")
    seg_data += struct.pack("<QQ", msg_slot_vmaddr, 64)
    seg_data += struct.pack("<II", data_file_off, 3)
    seg_data += struct.pack("<IIIIII", 0, 0, 0x7, 0, 0, 0)
    seg_data += b"__objc_selrefs".ljust(16, b"\0")
    seg_data += b"__DATA".ljust(16, b"\0")
    seg_data += struct.pack("<QQ", selref_vmaddr, 8)
    seg_data += struct.pack("<II", data_file_off + 64, 3)
    seg_data += struct.pack("<IIIIII", 0, 0, 0, 0, 0, 0)
    seg_data += b"__objc_methname".ljust(16, b"\0")
    seg_data += b"__DATA".ljust(16, b"\0")
    seg_data += struct.pack("<QQ", methname_vmaddr, len(data) - 72)
    seg_data += struct.pack("<II", data_file_off + 72, 0)
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

    emit_lazy_bind(msg_slot_vmaddr, "_objc_msgSend")
    emit_lazy_bind(store_slot_vmaddr, "_objc_storeStrong")
    emit_lazy_bind(release_slot_vmaddr, "_objc_release")
    emit_lazy_bind(getprop_slot_vmaddr, "_objc_getProperty")
    emit_lazy_bind(setprop_slot_vmaddr, "_objc_setProperty_atomic_copy")
    emit_lazy_bind(nonatomic_setprop_slot_vmaddr, "_objc_setProperty_nonatomic")
    emit_lazy_bind(claim_slot_vmaddr, "_objc_unsafeClaimAutoreleasedReturnValue")
    emit_lazy_bind(begin_catch_slot_vmaddr, "_objc_begin_catch")
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
