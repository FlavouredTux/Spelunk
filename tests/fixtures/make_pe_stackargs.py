#!/usr/bin/env python3
"""Emit an x86_64 PE32+ executable exercising Win64 argument passing.

Three functions, each with a real UNWIND_INFO record (so .xdata-driven frame
analysis can recover the prologue RSP delta), no Windows toolchain needed:

  stack_sum (RVA 0x1000): int stack_sum(a, b, c, d, e, f)
      Six integer args - the first four in rcx/rdx/r8/r9, the 5th and 6th
      on the caller's stack. The body reads the stack args from
      [rsp+0x50] / [rsp+0x58] after a `sub rsp, 0x28` prologue, so the
      entry-relative offsets are 0x28 / 0x30 - the canonical Win64 5th/6th
      argument home slots. Exercises incoming-stack-arg naming (item 2):
      these should render as `a5` / `a6`, not raw `arg_50` stack loads.

  fp_pos    (RVA 0x1040): int fp_pos(int a, double b, int c)
      Win64 assigns argument registers by a single positional slot shared
      across the GPR and XMM files, so this is (rcx, xmm1, r8) - NOT
      (rcx, xmm0, rdx). The body returns a + c, reading ecx and r8d.
      With a declared signature the 3rd parameter `c` must map to r8
      (slot 2), proving positional fp/int arg mapping (item 1).

  cookie_return (RVA 0x1080): unsigned char cookie_return(void)
      Returns 1 through AL, then invokes an MSVC-style security-cookie helper
      with `saved_cookie ^ rsp`. The helper must not replace the real return
      value with an undefined post-call RAX clobber.

The image is structural-only (zero checksum, no real DOS stub) but passes
every check Ember's PeBinary loader performs.

Usage:
  make_pe_stackargs.py <output-path>
"""

import struct
import sys


IMAGE_BASE        = 0x140000000
SECTION_ALIGN     = 0x1000
FILE_ALIGN        = 0x200
MACHINE_AMD64     = 0x8664

IMAGE_FILE_EXECUTABLE_IMAGE    = 0x0002
IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020

SCN_CNT_CODE        = 0x00000020
SCN_CNT_INITIALIZED = 0x00000040
SCN_MEM_EXECUTE     = 0x20000000
SCN_MEM_READ        = 0x40000000


def align(v, a):
    return (v + a - 1) & ~(a - 1)


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    out_path = sys.argv[1]

    rva_text  = 0x1000
    rva_rdata = 0x2000
    rva_pdata = 0x3000

    foff_text  = FILE_ALIGN
    foff_rdata = foff_text + FILE_ALIGN

    stack_sum_rva = rva_text + 0x00
    fp_pos_rva    = rva_text + 0x40
    cookie_return_rva = rva_text + 0x80
    cookie_helper_rva = rva_text + 0xc0

    # .rdata layout is deterministic: stack_sum unwind (8), fp_pos unwind
    # (4), cookie_return unwind (8), alignment (4), then the cookie qword.
    cookie_rva = rva_rdata + 0x18

    def rel32(ip_after, target):
        return struct.pack("<i", target - ip_after)

    # ---- .text -----------------------------------------------------------
    # stack_sum: eax = ecx + edx + r8d + r9d + [rsp+0x50] + [rsp+0x58]
    stack_sum = (
        b"\x48\x83\xec\x28"      # sub rsp, 0x28          (prologue, delta 0x28)
        b"\x89\xc8"              # mov eax, ecx           ; a
        b"\x01\xd0"             # add eax, edx           ; + b
        b"\x44\x01\xc0"         # add eax, r8d           ; + c
        b"\x44\x01\xc8"         # add eax, r9d           ; + d
        b"\x03\x44\x24\x50"     # add eax, [rsp+0x50]    ; + e (5th, entry 0x28)
        b"\x03\x44\x24\x58"     # add eax, [rsp+0x58]    ; + f (6th, entry 0x30)
        b"\x48\x83\xc4\x28"     # add rsp, 0x28          (epilogue)
        b"\xc3"                 # ret
    )

    # fp_pos: eax = ecx + r8d  (a + c; double b in xmm1 is unused)
    fp_pos = (
        b"\x89\xc8"             # mov eax, ecx           ; a
        b"\x44\x01\xc0"        # add eax, r8d           ; + c (slot 2 -> r8)
        b"\xc3"                # ret
    )

    cookie_return = bytearray()
    cookie_return += b"\x48\x83\xec\x28"  # sub rsp, 0x28
    cookie_return += b"\x48\x8b\x05" + rel32(
        cookie_return_rva + len(cookie_return) + 7, cookie_rva)
    cookie_return += b"\x48\x31\xe0"      # xor rax, rsp
    cookie_return += b"\x48\x89\x44\x24\x20"  # mov [rsp+0x20], rax
    cookie_return += b"\xb8\x01\x00\x00\x00"  # mov eax, 1
    cookie_return += b"\x48\x8b\x4c\x24\x20"  # mov rcx, [rsp+0x20]
    cookie_return += b"\x48\x31\xe1"      # xor rcx, rsp
    cookie_return += b"\xe8" + rel32(
        cookie_return_rva + len(cookie_return) + 5, cookie_helper_rva)
    cookie_return += b"\x48\x83\xc4\x28"  # add rsp, 0x28
    cookie_return += b"\xc3"                  # ret

    text = bytearray()
    text += stack_sum
    while len(text) < (fp_pos_rva - stack_sum_rva):
        text.append(0)
    text += fp_pos
    while len(text) < (cookie_return_rva - stack_sum_rva):
        text.append(0)
    text += cookie_return
    while len(text) < (cookie_helper_rva - stack_sum_rva):
        text.append(0)
    text += b"\xc3"
    text_virt_size = len(text)

    # ---- .rdata: UNWIND_INFO blobs --------------------------------------
    rdata = bytearray()

    # stack_sum: version 1, size_of_prolog = 4, one UWOP_ALLOC_SMALL of
    # 0x28 (op_info = (0x28 - 8) / 8 = 4) at prologue offset 4.
    xdata_stack_sum_rva = rva_rdata + len(rdata)
    rdata += bytes([
        0x01,        # version 1, flags 0
        0x04,        # size_of_prolog (bytes)
        0x01,        # count_of_codes
        0x00,        # frame register / offset (none)
        0x04, 0x42,  # code: offset 4, op=UWOP_ALLOC_SMALL(2) op_info=4
        0x00, 0x00,  # padding (odd count -> one slot)
    ])

    # fp_pos: leaf, no prologue. version 1, no codes.
    xdata_fp_pos_rva = rva_rdata + len(rdata)
    rdata += bytes([0x01, 0x00, 0x00, 0x00])

    xdata_cookie_return_rva = rva_rdata + len(rdata)
    rdata += bytes([
        0x01, 0x04, 0x01, 0x00,
        0x04, 0x42, 0x00, 0x00,
    ])
    while len(rdata) % 8:
        rdata.append(0)
    assert rva_rdata + len(rdata) == cookie_rva
    rdata += struct.pack("<Q", 0x8877665544332211)

    rdata_virt_size = len(rdata)

    # ---- .pdata: RUNTIME_FUNCTION table ---------------------------------
    pdata = bytearray()
    pdata += struct.pack("<III", stack_sum_rva,
                         stack_sum_rva + len(stack_sum), xdata_stack_sum_rva)
    pdata += struct.pack("<III", fp_pos_rva,
                         fp_pos_rva + len(fp_pos), xdata_fp_pos_rva)
    pdata += struct.pack("<III", cookie_return_rva,
                         cookie_return_rva + len(cookie_return),
                         xdata_cookie_return_rva)
    pdata_virt_size = len(pdata)

    # ---- offsets + sizes ------------------------------------------------
    foff_pdata = foff_rdata + align(len(rdata), FILE_ALIGN)
    text_raw_size  = align(len(text),  FILE_ALIGN)
    rdata_raw_size = align(len(rdata), FILE_ALIGN)
    pdata_raw_size = align(len(pdata), FILE_ALIGN)
    file_end       = foff_pdata + pdata_raw_size

    size_of_image   = align(rva_pdata + pdata_virt_size, SECTION_ALIGN)
    size_of_headers = FILE_ALIGN

    # ---- headers --------------------------------------------------------
    dos = bytearray(b"\x00" * 0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)

    nt_sig = b"PE\x00\x00"

    coff = struct.pack("<HHIIIHH",
                       MACHINE_AMD64, 3, 0, 0, 0, 240,
                       IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE)

    opt = bytearray()
    opt += struct.pack("<H", 0x20b)
    opt += struct.pack("<BB", 14, 0)
    opt += struct.pack("<III", text_raw_size,
                       rdata_raw_size + pdata_raw_size, 0)
    opt += struct.pack("<I", stack_sum_rva)         # AddressOfEntryPoint
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
    data_dirs[3] = (rva_pdata, pdata_virt_size)     # Exception directory
    for va, sz in data_dirs:
        opt += struct.pack("<II", va, sz)
    assert len(opt) == 240, len(opt)

    def section_hdr(name, vsize, vrva, rsize, roff, chars):
        return (name.ljust(8, b"\0")
              + struct.pack("<IIII", vsize, vrva, rsize, roff)
              + struct.pack("<IIHHI", 0, 0, 0, 0, chars))

    sec_tab = bytearray()
    sec_tab += section_hdr(b".text",  text_virt_size,  rva_text,  text_raw_size,  foff_text,
                           SCN_CNT_CODE | SCN_MEM_EXECUTE | SCN_MEM_READ)
    sec_tab += section_hdr(b".rdata", rdata_virt_size, rva_rdata, rdata_raw_size, foff_rdata,
                           SCN_CNT_INITIALIZED | SCN_MEM_READ)
    sec_tab += section_hdr(b".pdata", pdata_virt_size, rva_pdata, pdata_raw_size, foff_pdata,
                           SCN_CNT_INITIALIZED | SCN_MEM_READ)

    out = bytearray(file_end)
    out[0:0x40]          = dos
    out[0x40:0x44]       = nt_sig
    out[0x44:0x58]       = coff
    out[0x58:0x58 + 240] = opt
    out[0x58 + 240:0x58 + 240 + len(sec_tab)] = sec_tab
    out[foff_text :foff_text  + len(text)]  = text
    out[foff_rdata:foff_rdata + len(rdata)] = rdata
    out[foff_pdata:foff_pdata + len(pdata)] = pdata

    with open(out_path, "wb") as f:
        f.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
