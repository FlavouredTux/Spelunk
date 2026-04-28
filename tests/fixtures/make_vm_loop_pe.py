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

    vm_loop_rich_rva  = rva_text + 0x300
    rich_handler_rva  = rva_text + 0x320
    NUM_RICH          = 8
    RICH_SIZE         = 0x08        # 8 bytes per rich handler

    vm_loop_rip_rva   = rva_text + 0x380     # VMProtect-style RIP-capture VM

    vm_loop_stack_rva = rva_text + 0x400     # vm_stack_<arith> recogniser VM
    stack_handler_rva = vm_loop_stack_rva + 0x20
    NUM_STACK         = 8
    STACK_SIZE        = 0x08

    table_rva           = rva_rdata + 0x00
    bytecode_rva        = rva_rdata + 0x80
    threaded_table_rva  = rva_rdata + 0x100
    # 64-byte gap of zeros after threaded_table so the table walker
    # stops at the boundary instead of running into rich_table.
    rich_table_rva      = rva_rdata + 0x180
    # Same gap rationale between rich_table and rip_table.
    rip_table_rva       = rva_rdata + 0x200
    # Same gap rationale before stack_table.
    stack_table_rva     = rva_rdata + 0x280

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

    # ---- 16 handlers ---- (each 4 bytes; classifier exercise)
    # Slot mix is deliberate so the per-handler classifier emits more
    # than one HandlerKind on this VM. Slots 0..2 cover body-work
    # classifications (arith / load / store), slots 3..15 stay as bare
    # `ret`s so they classify as Return — which is what real-world
    # `vm_ret`-style trivial opcodes look like.
    text += b"\x48\x01\xC8\xC3"          # add rax, rcx; ret           — Arith
    text += b"\x8A\x01\xC3\x90"          # mov al, [rcx]; ret; nop     — Load
    text += b"\x88\x01\xC3\x90"          # mov [rcx], al; ret; nop     — Store
    for _ in range(13):
        text += b"\xC3\x90\x90\x90"      # ret; nop; nop; nop          — Return
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

    # ---- pad to vm_loop_rich_rva (0x300) ----
    while len(text) < (vm_loop_rich_rva - rva_text):
        text += b"\xCC"

    # ---- vm_loop_rich (central dispatcher with full classification mix) ----
    # Same canonical shape as vm_loop, just pointing at a different
    # table so the cluster comes out as a separate VM #3.
    rich_disp_start = len(text)
    rip_after_lea_pc_rich = vm_loop_rich_rva + 7
    text += b"\x48\x8D\x3D" + struct.pack("<i", bytecode_rva - rip_after_lea_pc_rich)
    rip_after_lea_table_rich = vm_loop_rich_rva + 14
    text += b"\x48\x8D\x35" + struct.pack("<i", rich_table_rva - rip_after_lea_table_rich)
    text += b"\x0F\xB6\x07"
    text += b"\x48\xFF\xC7"
    text += b"\xFF\x24\xC6"
    vm_loop_rich_size = len(text) - rich_disp_start
    # Pad to rich_handler_rva (0x320).
    while len(text) < (rich_handler_rva - rva_text):
        text += b"\xCC"

    # ---- 8 rich handlers (8 bytes each) — exercise every classifier kind ----
    # Slot table:
    #   [0] branch  — cmp rax, 0; jne $+1; ret; ret
    #   [1] call    — call $+5; ret; nop; nop      (calls into the ret at +5)
    #   [2] arith   — add rax, rcx; ret; nops
    #   [3] load    — mov rax, [rcx]; ret; nops
    #   [4] store   — mov [rcx], rax; ret; nops
    #   [5..7] return — ret; nops      (trivial vm_ret-style opcodes)
    text += b"\x48\x83\xF8\x00\x75\x01\xC3\xC3"   # [0] branch
    text += b"\xE8\x00\x00\x00\x00\xC3\x90\x90"   # [1] call
    text += b"\x48\x01\xC8\xC3\x90\x90\x90\x90"   # [2] arith add reg
    text += b"\x48\x8B\x07\xC3\x90\x90\x90\x90"   # [3] load operand (mov rax, [rdi])
    text += b"\x48\x89\x01\xC3\x90\x90\x90\x90"   # [4] store
    text += b"\xC3\x90\x90\x90\x90\x90\x90\x90"   # [5] return
    text += b"\xC3\x90\x90\x90\x90\x90\x90\x90"   # [6] return
    text += b"\xC3\x90\x90\x90\x90\x90\x90\x90"   # [7] return
    rich_handlers_size = NUM_RICH * RICH_SIZE
    assert len(text) == (rich_handler_rva - rva_text) + rich_handlers_size

    rich_handler_rvas = [rich_handler_rva + i * RICH_SIZE for i in range(NUM_RICH)]

    # ---- pad to vm_loop_rip_rva (0x380) ----
    while len(text) < (vm_loop_rip_rva - rva_text):
        text += b"\xCC"

    # ---- vm_loop_rip (RIP-capture via call+pop) ----
    # `call $+5; pop rsi` is the VMProtect-class trick for materialising
    # the current RIP into a register without using lea — equivalent to
    # `lea rsi, [rip+0]` placed at the pop's address. The detector's
    # call+pop lookahead must recognise this and prime a synthetic
    # LeaRipRel record on rsi so the dispatch's table-base resolution
    # path still works.
    rip_disp_start = len(text)
    text += b"\xE8\x00\x00\x00\x00"           # call $+5
    text += b"\x5E"                            # pop rsi
    text += b"\x0F\xB6\x07"                    # movzx eax, byte ptr [rdi]
    text += b"\x48\xFF\xC7"                    # inc rdi
    # jmp [rsi + rax*8 + disp32] — table at rip_table_rva, with disp
    # measured from the pop instruction's VA (= what rsi holds).
    pop_rsi_va = IMAGE_BASE + vm_loop_rip_rva + 5
    table_va   = IMAGE_BASE + rip_table_rva
    disp32     = table_va - pop_rsi_va
    text += b"\xFF\xA4\xC6" + struct.pack("<i", disp32)
    vm_loop_rip_size = len(text) - rip_disp_start

    # ---- pad to vm_loop_stack_rva (0x400) ----
    while len(text) < (vm_loop_stack_rva - rva_text):
        text += b"\xCC"

    # ---- vm_loop_stack (stack-arith handler-pattern recogniser) ----
    # Same canonical dispatcher shape as vm_loop_rich, dispatching into
    # 8 slots whose first two are vm_stack_<arith> handlers
    # (pop r1; pop r2; <arith> r1, r2; push r1; ret) and the remaining
    # six are bare `ret`s. Phase 1c's classify_vm_handler should label
    # slots 0..1 as `stack-arith` and 2..7 as `return`.
    stack_disp_start = len(text)
    rip_after_lea_pc_stack = vm_loop_stack_rva + 7
    text += b"\x48\x8D\x3D" + struct.pack("<i", bytecode_rva - rip_after_lea_pc_stack)
    rip_after_lea_table_stack = vm_loop_stack_rva + 14
    text += b"\x48\x8D\x35" + struct.pack("<i", stack_table_rva - rip_after_lea_table_stack)
    text += b"\x0F\xB6\x07"
    text += b"\x48\xFF\xC7"
    text += b"\xFF\x24\xC6"
    vm_loop_stack_size = len(text) - stack_disp_start
    while len(text) < (stack_handler_rva - rva_text):
        text += b"\xCC"

    # ---- 8 stack handlers (8 bytes each) ----
    #   [0] stack-arith add — pop rax; pop rcx; add rax, rcx; push rax; ret; nop
    #   [1] stack-arith xor — pop rax; pop rcx; xor rax, rcx; push rax; ret; nop
    #   [2..7] return — ret; nops
    text += b"\x58\x59\x48\x01\xC8\x50\xC3\x90"   # [0] stack-arith add
    text += b"\x58\x59\x48\x31\xC8\x50\xC3\x90"   # [1] stack-arith xor
    for _ in range(6):
        text += b"\xC3\x90\x90\x90\x90\x90\x90\x90"
    stack_handlers_size = NUM_STACK * STACK_SIZE
    assert len(text) == (stack_handler_rva - rva_text) + stack_handlers_size

    stack_handler_rvas = [stack_handler_rva + i * STACK_SIZE for i in range(NUM_STACK)]

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
    # Pad to rich_table_rva (0x140).
    while len(rdata) < (rich_table_rva - rva_rdata):
        rdata.append(0)
    # 8-entry rich-handler table — central VM #3.
    for i in range(NUM_RICH):
        rdata += struct.pack("<Q", IMAGE_BASE + rich_handler_rvas[i])
    # Pad to rip_table_rva (0x200).
    while len(rdata) < (rip_table_rva - rva_rdata):
        rdata.append(0)
    # 8-entry rip-capture-VM table — same handlers, just routed via
    # call+pop instead of lea. Lets the same handler bodies serve two
    # different dispatchers.
    for i in range(NUM_RICH):
        rdata += struct.pack("<Q", IMAGE_BASE + rich_handler_rvas[i])
    # Pad to stack_table_rva (0x280).
    while len(rdata) < (stack_table_rva - rva_rdata):
        rdata.append(0)
    # 8-entry stack-arith handler table.
    for i in range(NUM_STACK):
        rdata += struct.pack("<Q", IMAGE_BASE + stack_handler_rvas[i])
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
    # PDATA covering the rich central dispatcher only (its handlers
    # live in the table and are reached via the dispatch, not as
    # standalone functions).
    pdata += struct.pack("<III",
                         vm_loop_rich_rva,
                         vm_loop_rich_rva + vm_loop_rich_size,
                         rva_pdata)
    # And the RIP-capture central dispatcher.
    pdata += struct.pack("<III",
                         vm_loop_rip_rva,
                         vm_loop_rip_rva + vm_loop_rip_size,
                         rva_pdata)
    # And the stack-arith central dispatcher.
    pdata += struct.pack("<III",
                         vm_loop_stack_rva,
                         vm_loop_stack_rva + vm_loop_stack_size,
                         rva_pdata)
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
