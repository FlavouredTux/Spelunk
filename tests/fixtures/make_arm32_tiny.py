#!/usr/bin/env python3
"""Emit a minimal ARM (A32 / ARMv7) ELF executable for golden tests.

Mirrors make_arm64_tiny.py, but 32-bit little-endian ELF with EM_ARM. The
entry function is:

    add r0, r0, #42      ; ALU immediate
    lsl r0, r0, #1       ; MOV-with-shift alias (barrel shifter)
    bx  lr               ; return (bx lr)

i.e. `return (arg0 + 42) << 1;`. Enough to drive the A32 decoder + lifter +
structurer + emitter end-to-end without an ARM cross-toolchain.

Usage:
    make_arm32_tiny.py <output-path>
"""

from __future__ import annotations

import pathlib
import struct
import sys


ET_EXEC     = 2
EV_CURRENT  = 1
PT_LOAD     = 1
PF_R        = 4
PF_X        = 1
EI_CLASS_32 = 1
EI_DATA_LE  = 1
EM_ARM      = 40  # 0x28

EHDR_SIZE = 52
PHDR_SIZE = 32

BASE_VADDR = 0x10000


def build() -> bytes:
    code_offset = EHDR_SIZE + PHDR_SIZE

    code  = struct.pack("<I", 0xE280002A)  # add r0, r0, #42
    code += struct.pack("<I", 0xE1A00080)  # lsl r0, r0, #1  (mov r0, r0, lsl #1)
    code += struct.pack("<I", 0xE12FFF1E)  # bx lr

    file_size = code_offset + len(code)
    entry = BASE_VADDR + code_offset

    ident = bytes([
        0x7F, ord("E"), ord("L"), ord("F"),
        EI_CLASS_32,
        EI_DATA_LE,
        1,    # EV_CURRENT
        0,    # ELFOSABI_SYSV
        0,    # ABI version
    ]) + bytes(7)

    ehdr = ident + struct.pack(
        "<HHIIIIIHHHHHH",
        ET_EXEC,
        EM_ARM,
        EV_CURRENT,
        entry,
        EHDR_SIZE,    # e_phoff
        0,            # e_shoff
        0,            # e_flags
        EHDR_SIZE,
        PHDR_SIZE,
        1,            # e_phnum
        0,            # e_shentsize
        0,            # e_shnum
        0,            # e_shstrndx
    )

    phdr = struct.pack(
        "<IIIIIIII",
        PT_LOAD,
        0,            # p_offset
        BASE_VADDR,
        BASE_VADDR,
        file_size,    # p_filesz
        file_size,    # p_memsz
        PF_R | PF_X,
        0x1000,
    )

    return ehdr + phdr + code


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: make_arm32_tiny.py <out>", file=sys.stderr)
        return 1
    out = pathlib.Path(sys.argv[1])
    out.write_bytes(build())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
