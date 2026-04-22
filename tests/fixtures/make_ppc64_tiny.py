#!/usr/bin/env python3
"""Emit a minimal PPC64 ELF executable in either endian mode.

The binary has one PT_LOAD segment covering the whole file and two
instructions at the entry point:

  addi r3, 42
  blr

`be-opd` emits a big-endian ELFv1-style entry point where `e_entry`
points at a 24-byte function descriptor whose first word points at the
real code.
"""

from __future__ import annotations

import pathlib
import struct
import sys


EM_PPC64 = 21
ET_EXEC = 2
EV_CURRENT = 1
PT_LOAD = 1
PF_R = 4
PF_X = 1

EI_CLASS_64 = 2
EI_DATA_LE = 1
EI_DATA_BE = 2

BASE_VADDR = 0x100000
EHDR_SIZE = 64
PHDR_SIZE = 56
CODE_OFFSET = EHDR_SIZE + PHDR_SIZE
OPD_VADDR = 0x102000


def build(mode: str) -> bytes:
    if mode not in {"le", "be", "be-opd"}:
        raise ValueError(mode)
    big = mode != "le"
    use_opd = mode == "be-opd"
    order = ">" if big else "<"
    ei_data = EI_DATA_BE if big else EI_DATA_LE

    phnum = 2 if use_opd else 1
    code_offset = EHDR_SIZE + PHDR_SIZE * phnum
    code = struct.pack(order + "I", 0x3860002A)
    code += struct.pack(order + "I", 0x4E800020)
    descriptor = b""
    entry = BASE_VADDR + code_offset
    if use_opd:
        descriptor_offset = code_offset + len(code)
        descriptor = struct.pack(
            order + "QQQ",
            BASE_VADDR + code_offset,  # function entry
            0,                         # TOC/base pointer
            0,                         # environment pointer
        )
        entry = OPD_VADDR
    file_size = code_offset + len(code) + len(descriptor)

    ident = bytes([
        0x7F, ord("E"), ord("L"), ord("F"),
        EI_CLASS_64,
        ei_data,
        1,   # EV_CURRENT
        0,   # ELFOSABI_SYSV
        0,   # ABI version
    ]) + bytes(7)

    ehdr = ident + struct.pack(
        order + "HHIQQQIHHHHHH",
        ET_EXEC,
        EM_PPC64,
        EV_CURRENT,
        entry,
        EHDR_SIZE,
        0,
        0,
        EHDR_SIZE,
        PHDR_SIZE,
        phnum,
        0,
        0,
        0,
    )

    phdr = struct.pack(
        order + "IIQQQQQQ",
        PT_LOAD,
        PF_R | PF_X,
        0,
        BASE_VADDR,
        BASE_VADDR,
        code_offset + len(code),
        code_offset + len(code),
        0x1000,
    )

    if not use_opd:
        return ehdr + phdr + code

    opd_phdr = struct.pack(
        order + "IIQQQQQQ",
        PT_LOAD,
        PF_R,
        descriptor_offset,
        OPD_VADDR,
        OPD_VADDR,
        len(descriptor),
        len(descriptor),
        8,
    )

    return ehdr + phdr + opd_phdr + code + descriptor


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] not in {"le", "be", "be-opd"}:
        print("usage: make_ppc64_tiny.py <le|be|be-opd> <out>", file=sys.stderr)
        return 1
    out = pathlib.Path(sys.argv[2])
    out.write_bytes(build(sys.argv[1]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
