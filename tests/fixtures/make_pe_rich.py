#!/usr/bin/env python3
"""Emit a richer x86_64 PE32+ executable for Windows-path regression tests.

Coverage:
  - regular imports
  - delay imports
  - TLS callback directory + callback array
  - export directory
  - .pdata function discovery for entry, export, and TLS callback
  - Win64 call with stack-passed arguments beyond rcx/rdx/r8/r9
  - trivial call/ret Win64 wrapper for arity/signature recovery
  - bounded x64 jump-table switch for CFG recovery

Usage:
  make_pe_rich.py <output-path>
"""

from __future__ import annotations

import struct
import sys


IMAGE_BASE = 0x180000000
SECTION_ALIGN = 0x1000
FILE_ALIGN = 0x200
MACHINE_AMD64 = 0x8664

IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020

SCN_CNT_CODE = 0x00000020
SCN_CNT_INITIALIZED = 0x00000040
SCN_MEM_EXECUTE = 0x20000000
SCN_MEM_READ = 0x40000000
SCN_MEM_WRITE = 0x80000000


def align(v: int, a: int) -> int:
    return (v + a - 1) & ~(a - 1)


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    out_path = sys.argv[1]

    rva_text = 0x1000
    rva_rdata = 0x2000
    rva_pdata = 0x3000

    entry_rva = rva_text + 0x000
    tls_callback_rva = rva_text + 0x040
    add7_rva = rva_text + 0x080
    open_file_rva = rva_text + 0x0C0
    wrap_add7_rva = rva_text + 0x100
    switch_rva = rva_text + 0x140
    debug_wrap_rva = rva_text + 0x180

    layout = {
        "iat_gettick": None,
        "iat_outputdebug": None,
        "iat_createfile": None,
        "delay_iat_sleep": None,
        "msg_tls": None,
        "file_name": None,
        "switch_table": None,
    }

    text = bytearray(b"\x90" * 0x200)

    def patch(off: int, data: bytes) -> None:
        text[off:off + len(data)] = data

    def rel32(ip_after: int, target: int) -> bytes:
        return struct.pack("<i", target - ip_after)

    rdata = bytearray()

    def here() -> int:
        return rva_rdata + len(rdata)

    def add_u16(v: int) -> int:
        off = len(rdata)
        rdata.extend(struct.pack("<H", v))
        return rva_rdata + off

    def add_u32(v: int) -> int:
        off = len(rdata)
        rdata.extend(struct.pack("<I", v))
        return rva_rdata + off

    def add_u64(v: int) -> int:
        off = len(rdata)
        rdata.extend(struct.pack("<Q", v))
        return rva_rdata + off

    def add_bytes(b: bytes) -> int:
        off = len(rdata)
        rdata.extend(b)
        return rva_rdata + off

    def align_rdata(a: int) -> None:
        while len(rdata) % a != 0:
            rdata.append(0)

    # ---- imports --------------------------------------------------------
    import_desc_off = len(rdata)
    rdata += b"\x00" * 20
    rdata += b"\x00" * 20

    import_int_rva = add_u64(0)
    add_u64(0)
    add_u64(0)
    add_u64(0)

    import_iat_rva = add_u64(0)
    layout["iat_gettick"] = import_iat_rva
    layout["iat_outputdebug"] = import_iat_rva + 8
    layout["iat_createfile"] = import_iat_rva + 16
    add_u64(0)
    add_u64(0)
    add_u64(0)

    hint_gettick = add_u16(0)
    add_bytes(b"GetTickCount\x00")
    align_rdata(2)
    hint_outputdebug = add_u16(0)
    add_bytes(b"OutputDebugStringA\x00")
    align_rdata(2)
    hint_createfile = add_u16(0)
    add_bytes(b"CreateFileA\x00")
    align_rdata(2)
    dll_kernel32_rva = add_bytes(b"KERNEL32.dll\x00")
    align_rdata(4)

    struct.pack_into("<QQQQ", rdata, import_int_rva - rva_rdata,
                     hint_gettick, hint_outputdebug, hint_createfile, 0)
    struct.pack_into("<QQQQ", rdata, import_iat_rva - rva_rdata,
                     hint_gettick, hint_outputdebug, hint_createfile, 0)
    struct.pack_into("<IIIII", rdata, import_desc_off,
                     import_int_rva, 0, 0, dll_kernel32_rva, import_iat_rva)

    # ---- delay imports --------------------------------------------------
    delay_desc_rva = here()
    delay_desc_off = len(rdata)
    rdata += b"\x00" * 32
    rdata += b"\x00" * 32

    delay_iat_rva = add_u64(0)
    layout["delay_iat_sleep"] = delay_iat_rva
    add_u64(0)
    delay_int_rva = add_u64(0)
    add_u64(0)

    hint_sleep = add_u16(0)
    add_bytes(b"Sleep\x00")
    align_rdata(2)

    struct.pack_into("<QQ", rdata, delay_iat_rva - rva_rdata, hint_sleep, 0)
    struct.pack_into("<QQ", rdata, delay_int_rva - rva_rdata, hint_sleep, 0)
    struct.pack_into("<IIIIIIII", rdata, delay_desc_off,
                     1, dll_kernel32_rva, 0, delay_iat_rva, delay_int_rva, 0, 0, 0)

    # ---- TLS ------------------------------------------------------------
    tls_dir_rva = here()
    tls_dir_off = len(rdata)
    rdata += b"\x00" * 40

    tls_callback_array_rva = add_u64(IMAGE_BASE + tls_callback_rva)
    add_u64(0)

    layout["msg_tls"] = add_bytes(b"tls callback fired\x00")
    layout["file_name"] = add_bytes(b"ashtrace.txt\x00")
    layout["switch_table"] = add_bytes(b"\x00" * 12)
    align_rdata(8)

    # ---- exports --------------------------------------------------------
    export_dir_rva = here()
    export_dir_off = len(rdata)
    rdata += b"\x00" * 40
    export_dllname_rva = add_bytes(b"pe_rich.dll\x00")
    align_rdata(4)
    export_eat_rva = add_u32(add7_rva)
    export_ent_rva = add_u32(0)
    export_eot_rva = add_u16(0)
    align_rdata(4)
    export_name_rva = add_bytes(b"add7\x00")
    struct.pack_into("<I", rdata, export_ent_rva - rva_rdata, export_name_rva)
    struct.pack_into("<IIHHIIIIIII", rdata, export_dir_off,
                     0, 0, 0, 0,
                     export_dllname_rva,
                     1, 1, 1,
                     export_eat_rva,
                     export_ent_rva,
                     export_eot_rva)

    # Finish TLS directory now that callback array RVA is known.
    struct.pack_into("<QQQQII", rdata, tls_dir_off,
                     0, 0, 0,
                     IMAGE_BASE + tls_callback_array_rva,
                     0, 0)

    # ---- code -----------------------------------------------------------
    entry = bytearray()
    entry += b"\x48\x83\xec\x28"                          # sub rsp, 0x28
    entry += b"\xff\x15" + rel32(entry_rva + len(entry) + 6, layout["iat_gettick"])
    entry += b"\xb9\x05\x00\x00\x00"                      # mov ecx, 5
    entry += b"\xff\x15" + rel32(entry_rva + len(entry) + 6, layout["delay_iat_sleep"])
    entry += b"\x31\xc0"                                  # xor eax, eax
    entry += b"\x48\x83\xc4\x28"                          # add rsp, 0x28
    entry += b"\xc3"                                      # ret
    patch(entry_rva - rva_text, entry)

    tls = bytearray()
    tls += b"\x48\x83\xec\x28"                            # sub rsp, 0x28
    tls += b"\x48\x8d\x0d" + rel32(tls_callback_rva + len(tls) + 7, layout["msg_tls"])
    tls += b"\xff\x15" + rel32(tls_callback_rva + len(tls) + 6, layout["iat_outputdebug"])
    tls += b"\x48\x83\xc4\x28"                            # add rsp, 0x28
    tls += b"\xc3"
    patch(tls_callback_rva - rva_text, tls)

    add7 = b"\x8d\x41\x07\xc3"                            # lea eax, [rcx+7]; ret
    patch(add7_rva - rva_text, add7)

    open_file = bytearray()
    open_file += b"\x48\x83\xec\x38"                      # sub rsp, 0x38
    open_file += b"\x48\xc7\x44\x24\x20\x03\x00\x00\x00"  # mov qword [rsp+0x20], 3
    open_file += b"\x48\xc7\x44\x24\x28\x00\x00\x00\x00"  # mov qword [rsp+0x28], 0
    open_file += b"\x48\xc7\x44\x24\x30\x00\x00\x00\x00"  # mov qword [rsp+0x30], 0
    open_file += b"\x48\x8d\x0d" + rel32(open_file_rva + len(open_file) + 7, layout["file_name"])
    open_file += b"\x31\xd2"                              # xor edx, edx
    open_file += b"\x45\x31\xc0"                          # xor r8d, r8d
    open_file += b"\x45\x31\xc9"                          # xor r9d, r9d
    open_file += b"\xff\x15" + rel32(open_file_rva + len(open_file) + 6, layout["iat_createfile"])
    open_file += b"\x48\x83\xc4\x38"                      # add rsp, 0x38
    open_file += b"\xc3"
    patch(open_file_rva - rva_text, open_file)

    wrap_add7 = bytearray()
    wrap_add7 += b"\x48\x83\xec\x28"                      # sub rsp, 0x28
    wrap_add7 += b"\xe8" + rel32(wrap_add7_rva + len(wrap_add7) + 5, add7_rva)
    wrap_add7 += b"\x48\x83\xc4\x28"                      # add rsp, 0x28
    wrap_add7 += b"\xc3"
    patch(wrap_add7_rva - rva_text, wrap_add7)

    switch_fn = bytearray()
    switch_fn += b"\x83\xf9\x02"                          # cmp ecx, 2
    switch_fn += b"\x77\x00"                              # ja default (patched below)
    lea_off = len(switch_fn)
    switch_fn += b"\x48\x8d\x15\x00\x00\x00\x00"      # lea rdx, [rip + table]
    switch_fn += b"\x48\x63\x04\x8a"                    # movsxd rax, dword [rdx + rcx*4]
    switch_fn += b"\x48\x01\xd0"                        # add rax, rdx
    switch_fn += b"\xff\xe0"                            # jmp rax
    case0_off = len(switch_fn)
    switch_fn += b"\xb8\x0a\x00\x00\x00\xc3"          # mov eax, 10; ret
    case1_off = len(switch_fn)
    switch_fn += b"\xb8\x14\x00\x00\x00\xc3"          # mov eax, 20; ret
    case2_off = len(switch_fn)
    switch_fn += b"\xb8\x1e\x00\x00\x00\xc3"          # mov eax, 30; ret
    default_off = len(switch_fn)
    switch_fn += b"\xb8\xff\xff\xff\xff\xc3"          # mov eax, -1; ret

    switch_fn[4] = default_off - 5
    lea_disp = layout["switch_table"] - (switch_rva + lea_off + 7)
    switch_fn[lea_off + 3:lea_off + 7] = struct.pack("<i", lea_disp)
    patch(switch_rva - rva_text, switch_fn)

    def switch_entry(case_off: int) -> int:
        return (switch_rva + case_off) - layout["switch_table"]

    struct.pack_into("<iii", rdata, layout["switch_table"] - rva_rdata,
                     switch_entry(case0_off),
                     switch_entry(case1_off),
                     switch_entry(case2_off))

    debug_wrap = bytearray()
    debug_wrap += b"\x48\x83\xec\x28"                      # sub rsp, 0x28
    debug_wrap += b"\xff\x15" + rel32(debug_wrap_rva + len(debug_wrap) + 6,
                                      layout["iat_outputdebug"])
    debug_wrap += b"\x48\x83\xc4\x28"                      # add rsp, 0x28
    debug_wrap += b"\xc3"
    patch(debug_wrap_rva - rva_text, debug_wrap)

    # ---- pdata ----------------------------------------------------------
    pdata = bytearray()
    unwind_rva = rva_pdata + 0x40
    pdata += struct.pack("<III", entry_rva, entry_rva + len(entry), unwind_rva)
    pdata += struct.pack("<III", tls_callback_rva, tls_callback_rva + len(tls), unwind_rva)
    pdata += struct.pack("<III", add7_rva, add7_rva + len(add7), unwind_rva)
    pdata += struct.pack("<III", open_file_rva, open_file_rva + len(open_file), unwind_rva)
    pdata += struct.pack("<III", wrap_add7_rva, wrap_add7_rva + len(wrap_add7), unwind_rva)
    pdata += struct.pack("<III", switch_rva, switch_rva + len(switch_fn), unwind_rva)
    pdata += struct.pack("<III", debug_wrap_rva, debug_wrap_rva + len(debug_wrap), unwind_rva)
    while len(pdata) < 0x40:
        pdata.append(0)
    pdata += b"\x01\x00\x00\x00"  # tiny non-zero unwind blob

    text_virt_size = len(text.rstrip(b"\x90"))
    if text_virt_size == 0:
        text_virt_size = len(text)
    rdata_virt_size = len(rdata)
    pdata_virt_size = len(pdata)

    foff_text = FILE_ALIGN
    foff_rdata = foff_text + align(text_virt_size, FILE_ALIGN)
    foff_pdata = foff_rdata + align(rdata_virt_size, FILE_ALIGN)

    text_raw_size = align(text_virt_size, FILE_ALIGN)
    rdata_raw_size = align(rdata_virt_size, FILE_ALIGN)
    pdata_raw_size = align(pdata_virt_size, FILE_ALIGN)
    file_end = foff_pdata + pdata_raw_size
    size_of_image = align(rva_pdata + pdata_virt_size, SECTION_ALIGN)
    size_of_headers = FILE_ALIGN

    dos = bytearray(b"\x00" * 0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)

    coff = struct.pack("<HHIIIHH",
                       MACHINE_AMD64,
                       3,
                       0, 0, 0,
                       240,
                       IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE)

    opt = bytearray()
    opt += struct.pack("<H", 0x20B)
    opt += struct.pack("<BB", 14, 0)
    opt += struct.pack("<III", text_raw_size, rdata_raw_size + pdata_raw_size, 0)
    opt += struct.pack("<I", entry_rva)
    opt += struct.pack("<I", rva_text)
    opt += struct.pack("<Q", IMAGE_BASE)
    opt += struct.pack("<II", SECTION_ALIGN, FILE_ALIGN)
    opt += struct.pack("<HHHHHH", 6, 0, 0, 0, 6, 0)
    opt += struct.pack("<I", 0)
    opt += struct.pack("<III", size_of_image, size_of_headers, 0)
    opt += struct.pack("<HH", 3, 0x8160)
    opt += struct.pack("<QQQQ", 0x100000, 0x1000, 0x100000, 0x1000)
    opt += struct.pack("<II", 0, 16)
    data_dirs = [(0, 0)] * 16
    data_dirs[0] = (export_dir_rva, 40)
    data_dirs[1] = (rva_rdata + import_desc_off, 40)
    data_dirs[3] = (rva_pdata, pdata_virt_size)
    data_dirs[9] = (tls_dir_rva, 40)
    data_dirs[13] = (delay_desc_rva, 64)
    for va, sz in data_dirs:
        opt += struct.pack("<II", va, sz)
    assert len(opt) == 240

    def section_hdr(name: bytes, vsize: int, vrva: int, rsize: int, roff: int, chars: int) -> bytes:
        return (name.ljust(8, b"\0")
                + struct.pack("<IIII", vsize, vrva, rsize, roff)
                + struct.pack("<IIHHI", 0, 0, 0, 0, chars))

    sec_tab = bytearray()
    sec_tab += section_hdr(b".text", text_virt_size, rva_text, text_raw_size, foff_text,
                           SCN_CNT_CODE | SCN_MEM_EXECUTE | SCN_MEM_READ)
    sec_tab += section_hdr(b".rdata", rdata_virt_size, rva_rdata, rdata_raw_size, foff_rdata,
                           SCN_CNT_INITIALIZED | SCN_MEM_READ)
    sec_tab += section_hdr(b".pdata", pdata_virt_size, rva_pdata, pdata_raw_size, foff_pdata,
                           SCN_CNT_INITIALIZED | SCN_MEM_READ)

    out = bytearray(file_end)
    out[0:0x40] = dos
    out[0x40:0x44] = b"PE\x00\x00"
    out[0x44:0x58] = coff
    out[0x58:0x58 + 240] = opt
    out[0x58 + 240:0x58 + 240 + len(sec_tab)] = sec_tab
    out[foff_text:foff_text + text_virt_size] = text[:text_virt_size]
    out[foff_rdata:foff_rdata + rdata_virt_size] = rdata
    out[foff_pdata:foff_pdata + pdata_virt_size] = pdata

    with open(out_path, "wb") as f:
        f.write(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
