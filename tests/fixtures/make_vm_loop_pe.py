#!/usr/bin/env python3
"""Emit a tiny PE32+ containing the canonical interpreter-style VM
dispatcher pattern, for use by the --vm-detect golden test:

    vm_loop:
        lea  rsi, [rip + handler_table]    ; load table base
        movzx eax, byte ptr [rdi]           ; opcode <- *pc
        inc  rdi                            ; pc++
        jmp  qword ptr [rsi + rax*8]        ; dispatch

    handler_table[16] :  16 handlers, each `xor eax, eax; ret; nop`

The handlers, table base, dispatch site, opcode register (al/eax),
pc register (rdi), and pc advance (+1) are all extractable by
detect_vm_dispatchers — exactly what phase 1a needs to lock in a
golden for.

A single PDATA entry covers vm_loop so ember sees it as a function
symbol; the handlers are reachable via the table walk and don't need
their own symbols.

Usage:
    make_vm_loop_pe.py <output-path>
"""

from __future__ import annotations

import struct
import sys


IMAGE_BASE         = 0x140000000
SECTION_ALIGN      = 0x1000
FILE_ALIGN         = 0x200
MACHINE_AMD64      = 0x8664

IMAGE_FILE_EXECUTABLE_IMAGE     = 0x0002
IMAGE_FILE_LARGE_ADDRESS_AWARE  = 0x0020

SCN_CNT_CODE         = 0x00000020
SCN_CNT_INITIALIZED  = 0x00000040
SCN_MEM_EXECUTE      = 0x20000000
SCN_MEM_READ         = 0x40000000


def align(v: int, a: int) -> int:
    return (v + a - 1) & ~(a - 1)


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    out_path = sys.argv[1]

    rva_text  = 0x1000
    rva_rdata = 0x2000
    rva_pdata = 0x3000

    foff_headers = 0
    foff_text    = FILE_ALIGN
    # foff_rdata / foff_pdata are computed after section sizes are
    # known — see "Sizes / file layout" below. The earlier shortcut
    # that assumed each section fit in one FILE_ALIGN block silently
    # truncated .text once the threaded handlers pushed it past 0x200.

    # ---- .text content -----------------------------------------------------
    # Functions exercising the detector:
    #
    #   vm_loop @ rva_text+0x00 — canonical clean dispatcher.
    #   vm_loop_obf @ rva_text+0x80 — same shape with four semantic-nop
    #       pads (90 / 48 87 c0 / 48 89 c9 / eb 00) inserted between
    #       byte-load and dispatch. is_semantic_nop must skip them.
    #   vm_loop_split @ rva_text+0x100 — byte-load and dispatch in
    #       different basic blocks, joined by `jmp imm` with 30 bytes
    #       of int3 padding. Jmp-imm-follow must walk through.
    #   ht_0..ht_7 @ rva_text+0x200..+0x270 — eight tail-dispatch
    #       "threaded" handlers each running an independent dispatch
    #       loop and feeding a shared threaded handler-table. Both
    #       the per-site primitives and the cluster-by-table grouping
    #       (entry vs threaded) get exercised here.
    vm_loop_rva       = rva_text + 0x00
    handler_base_rva  = vm_loop_rva + 0x18
    vm_loop_obf_rva   = rva_text + 0x80
    vm_loop_split_rva = rva_text + 0x100
    threaded_base_rva = rva_text + 0x200
    NUM_THREADED      = 8
    THREADED_SIZE     = 0x10        # 16 bytes per ht_N

    table_rva           = rva_rdata + 0x00
    bytecode_rva        = rva_rdata + 0x80
    threaded_table_rva  = rva_rdata + 0x100

    text = bytearray()

    # ---- vm_loop (clean) ----
    # lea rdi, [rip + bytecode_disp]
    rip_after_lea_pc = vm_loop_rva + 7
    text += b"\x48\x8D\x3D" + struct.pack("<i", bytecode_rva - rip_after_lea_pc)
    # lea rsi, [rip + table_disp]
    rip_after_lea_table = vm_loop_rva + 14
    text += b"\x48\x8D\x35" + struct.pack("<i", table_rva - rip_after_lea_table)
    # movzx eax, byte ptr [rdi]
    text += b"\x0F\xB6\x07"
    # inc rdi
    text += b"\x48\xFF\xC7"
    # jmp qword ptr [rsi + rax*8]
    text += b"\xFF\x24\xC6"
    # 1-byte nop pad so the handler table starts at a clean +0x18 offset.
    text += b"\x90"
    assert len(text) == 0x18, len(text)

    # ---- 16 handlers ---- (xor eax, eax; ret; nop)
    for _ in range(16):
        text += b"\x31\xC0\xC3\x90"
    assert len(text) == 0x18 + 16 * 4

    # ---- pad to vm_loop_obf_rva (0x80) ----
    while len(text) < (vm_loop_obf_rva - rva_text):
        text += b"\xCC"   # int3 padding

    # ---- vm_loop_obf (junk-padded) ----
    obf_start = len(text)
    rip_after_lea_pc_obf = vm_loop_obf_rva + 7
    text += b"\x48\x8D\x3D" + struct.pack("<i", bytecode_rva - rip_after_lea_pc_obf)
    rip_after_lea_table_obf = vm_loop_obf_rva + 14
    text += b"\x48\x8D\x35" + struct.pack("<i", table_rva - rip_after_lea_table_obf)
    # movzx eax, byte ptr [rdi]
    text += b"\x0F\xB6\x07"
    # --- junk pads between byte-load and dispatch ---
    text += b"\x90"             # nop
    text += b"\x48\x87\xC0"     # xchg rax, rax  (REX.W variant, 3 bytes)
    text += b"\x48\x89\xC9"     # mov rcx, rcx
    text += b"\xEB\x00"         # jmp $+0
    # inc rdi
    text += b"\x48\xFF\xC7"
    # jmp qword ptr [rsi + rax*8]
    text += b"\xFF\x24\xC6"
    obf_size = len(text) - obf_start

    # ---- pad to vm_loop_split_rva (0x100) ----
    while len(text) < (vm_loop_split_rva - rva_text):
        text += b"\xCC"

    # ---- vm_loop_split (cross-block) ----
    # Layout (offsets relative to vm_loop_split_rva):
    #   0x00: lea rdi, [rip + bytecode]                7 bytes
    #   0x07: lea rsi, [rip + handler_table]           7 bytes
    #   0x0E: movzx eax, byte ptr [rdi]                3 bytes
    #   0x11: jmp short +30 (eb 1e)                    2 bytes
    #   0x13..0x30: 30 bytes of int3 padding
    #   0x31: inc rdi                                  3 bytes
    #   0x34: jmp qword ptr [rsi + rax*8]              3 bytes
    split_start = len(text)
    rip_after_lea_pc_split = vm_loop_split_rva + 7
    text += b"\x48\x8D\x3D" + struct.pack("<i", bytecode_rva - rip_after_lea_pc_split)
    rip_after_lea_table_split = vm_loop_split_rva + 14
    text += b"\x48\x8D\x35" + struct.pack("<i", table_rva - rip_after_lea_table_split)
    text += b"\x0F\xB6\x07"           # movzx eax, byte ptr [rdi]
    text += b"\xEB\x1E"               # jmp short +30 — to offset 0x31
    text += b"\xCC" * 30              # int3 padding (would derail a linear sweep)
    text += b"\x48\xFF\xC7"           # inc rdi
    text += b"\xFF\x24\xC6"           # jmp qword ptr [rsi + rax*8]
    split_size = len(text) - split_start

    # ---- pad to threaded_base_rva (0x200) ----
    while len(text) < (threaded_base_rva - rva_text):
        text += b"\xCC"

    # ---- ht_0 .. ht_7 (threaded tail-dispatchers) ----
    # Each handler is exactly 16 bytes:
    #   48 8D 35 NN NN NN NN     lea rsi, [rip + threaded_table]
    #   0F B6 07                 movzx eax, byte ptr [rdi]
    #   48 FF C7                 inc rdi
    #   FF 24 C6                 jmp qword ptr [rsi + rax*8]
    threaded_handler_rvas = []
    for i in range(NUM_THREADED):
        hrva = threaded_base_rva + i * THREADED_SIZE
        threaded_handler_rvas.append(hrva)
        rip_after_lea = hrva + 7
        text += b"\x48\x8D\x35" + struct.pack("<i", threaded_table_rva - rip_after_lea)
        text += b"\x0F\xB6\x07"
        text += b"\x48\xFF\xC7"
        text += b"\xFF\x24\xC6"
        assert len(text) == (hrva - rva_text) + THREADED_SIZE

    text_virt_size = len(text)
    vm_loop_size       = 0x18 + 16 * 4   # PDATA range covers handlers too
    vm_loop_obf_size   = obf_size
    vm_loop_split_size = split_size

    # ---- .rdata content ----------------------------------------------------
    # 16-entry main handler table at rva_rdata+0x00, each absolute VA
    # pointing at handler_i (4 bytes each in .text).
    rdata = bytearray()
    for i in range(16):
        h_va = IMAGE_BASE + handler_base_rva + i * 4
        rdata += struct.pack("<Q", h_va)
    # Bytecode bytes (12 zeros — content irrelevant).
    rdata += b"\x00" * 12
    # Pad to threaded_table_rva (0x100).
    while len(rdata) < (threaded_table_rva - rva_rdata):
        rdata.append(0)
    # 8-entry threaded table — points at ht_0..ht_7. The detector
    # treats each ht_N as a threaded slot because its function_addr
    # IS in this table.
    for i in range(NUM_THREADED):
        rdata += struct.pack("<Q", IMAGE_BASE + threaded_handler_rvas[i])
    rdata_virt_size = len(rdata)

    # ---- .pdata content ----------------------------------------------------
    # One RUNTIME_FUNCTION per dispatcher. UnwindInfoAddress points at
    # the start of .pdata as a harmless sentinel — Ember doesn't chase
    # it. Without these, vm_detect would have nothing to scan from.
    pdata = bytearray()
    pdata += struct.pack("<III",
                         vm_loop_rva,
                         vm_loop_rva + vm_loop_size,
                         rva_pdata)
    pdata += struct.pack("<III",
                         vm_loop_obf_rva,
                         vm_loop_obf_rva + vm_loop_obf_size,
                         rva_pdata)
    pdata += struct.pack("<III",
                         vm_loop_split_rva,
                         vm_loop_split_rva + vm_loop_split_size,
                         rva_pdata)
    # One PDATA entry per threaded handler so each becomes a Function
    # symbol vm_detect can scan from.
    for hrva in threaded_handler_rvas:
        pdata += struct.pack("<III", hrva, hrva + THREADED_SIZE, rva_pdata)
    pdata_virt_size = len(pdata)

    # ---- Sizes / file layout ----------------------------------------------
    text_raw_size  = align(len(text),  FILE_ALIGN)
    rdata_raw_size = align(len(rdata), FILE_ALIGN)
    pdata_raw_size = align(len(pdata), FILE_ALIGN)
    foff_rdata = foff_text + text_raw_size
    foff_pdata = foff_rdata + rdata_raw_size
    file_end   = foff_pdata + pdata_raw_size

    size_of_image   = align(rva_pdata + pdata_virt_size, SECTION_ALIGN)
    size_of_headers = FILE_ALIGN

    # ---- DOS header --------------------------------------------------------
    dos = bytearray(b"\x00" * 0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)

    nt_sig = b"PE\x00\x00"

    # ---- COFF header -------------------------------------------------------
    coff = struct.pack("<HHIIIHH",
                       MACHINE_AMD64,
                       3,                         # 3 sections
                       0, 0, 0,
                       240,                       # SizeOfOptionalHeader
                       IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE)

    # ---- Optional header (PE32+) -------------------------------------------
    opt = bytearray()
    opt += struct.pack("<H", 0x20b)
    opt += struct.pack("<BB", 14, 0)
    opt += struct.pack("<III", text_raw_size,
                              rdata_raw_size + pdata_raw_size,
                              0)
    opt += struct.pack("<I", vm_loop_rva)              # AddressOfEntryPoint
    opt += struct.pack("<I", rva_text)                  # BaseOfCode
    opt += struct.pack("<Q", IMAGE_BASE)
    opt += struct.pack("<II", SECTION_ALIGN, FILE_ALIGN)
    opt += struct.pack("<HHHHHH", 6, 0, 0, 0, 6, 0)
    opt += struct.pack("<I", 0)
    opt += struct.pack("<III", size_of_image, size_of_headers, 0)
    opt += struct.pack("<HH", 3, 0x8160)
    opt += struct.pack("<QQQQ",
                       0x100000, 0x1000,
                       0x100000, 0x1000)
    opt += struct.pack("<II", 0, 16)
    data_dirs = [(0, 0)] * 16
    data_dirs[3] = (rva_pdata, pdata_virt_size)        # IMAGE_DIRECTORY_ENTRY_EXCEPTION
    for va, sz in data_dirs:
        opt += struct.pack("<II", va, sz)
    assert len(opt) == 240, len(opt)

    # ---- Section table -----------------------------------------------------
    def section_hdr(name: bytes, vsize: int, vrva: int, rsize: int,
                    roff: int, chars: int) -> bytes:
        return (name.ljust(8, b"\0")
              + struct.pack("<IIII", vsize, vrva, rsize, roff)
              + struct.pack("<IIHHI", 0, 0, 0, 0, chars))

    sec_tab  = section_hdr(b".text",  text_virt_size,  rva_text,
                            text_raw_size,  foff_text,
                            SCN_CNT_CODE | SCN_MEM_EXECUTE | SCN_MEM_READ)
    sec_tab += section_hdr(b".rdata", rdata_virt_size, rva_rdata,
                            rdata_raw_size, foff_rdata,
                            SCN_CNT_INITIALIZED | SCN_MEM_READ)
    sec_tab += section_hdr(b".pdata", pdata_virt_size, rva_pdata,
                            pdata_raw_size, foff_pdata,
                            SCN_CNT_INITIALIZED | SCN_MEM_READ)

    # ---- Write file --------------------------------------------------------
    out = bytearray(file_end)
    out[0:0x40]                = dos
    out[0x40:0x44]             = nt_sig
    out[0x44:0x58]             = coff
    out[0x58:0x58 + 240]       = opt
    out[0x58 + 240:0x58 + 240 + len(sec_tab)] = sec_tab

    out[foff_text :foff_text  + len(text)]  = text
    out[foff_rdata:foff_rdata + len(rdata)] = rdata
    out[foff_pdata:foff_pdata + len(pdata)] = pdata

    with open(out_path, "wb") as f:
        f.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
