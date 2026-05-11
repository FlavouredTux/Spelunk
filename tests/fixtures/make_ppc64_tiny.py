#!/usr/bin/env python3
"""Emit minimal PPC ELF and DOL fixtures.

The default ELF modes have one PT_LOAD segment covering the whole file and
two instructions at the entry point:

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


EM_PPC = 20
EM_PPC64 = 21
ET_EXEC = 2
EV_CURRENT = 1
PT_LOAD = 1
PF_R = 4
PF_X = 1

EI_CLASS_64 = 2
EI_CLASS_32 = 1
EI_DATA_LE = 1
EI_DATA_BE = 2

BASE_VADDR = 0x100000
EHDR_SIZE = 64
PHDR_SIZE = 56
CODE_OFFSET = EHDR_SIZE + PHDR_SIZE
OPD_VADDR = 0x102000


def build(mode: str) -> bytes:
    if mode not in {"le", "be", "be-opd", "32le", "32be", "32be-scalar", "dol-scalar"}:
        raise ValueError(mode)
    if mode == "dol-scalar":
        words = [
            0x9421FFF0,  # stwu r1, -16(r1)
            0x2C030000,  # cmpwi r3, 0
            0x41820028,  # beq +0x28
            0x80830000,  # lwz r4, 0(r3)
            0x88A30004,  # lbz r5, 4(r3)
            0xA0C30006,  # lhz r6, 6(r3)
            0x1C840003,  # mulli r4, r4, 3
            0x54A5103A,  # rlwinm r5, r5, 2, 0, 29
            0x7C642A14,  # add r3, r4, r5
            0x7C633214,  # add r3, r3, r6
            0x38210010,  # addi r1, r1, 16
            0x4E800020,  # blr
            0x38600000,  # li r3, 0
            0x38210010,  # addi r1, r1, 16
            0x4E800020,  # blr
            0x60000000,  # nop
            0x9421FFF0,  # stwu r1, -16(r1)
            0x3D808000,  # lis r12, 0x8000
            0x618C3160,  # ori r12, r12, 0x3160
            0x7D8903A6,  # mtctr r12
            0x4E800421,  # bctrl
            0x38210010,  # addi r1, r1, 16
            0x4E800020,  # blr
            0x60000000,  # nop
            0x9421FFF0,  # stwu r1, -16(r1)
            0x38600007,  # li r3, 7
            0x38210010,  # addi r1, r1, 16
            0x4E800020,  # blr
        ]
        code = b"".join(struct.pack(">I", w) for w in words)
        code_offset = 0x100
        code_addr = 0x80003100
        data_offset = code_offset + len(code)
        data_addr = 0x80004000
        data = struct.pack(">II", code_addr + 0x40, code_addr + 0x60)
        header = bytearray(0x100)
        for off, value in [
            (0x00, code_offset),
            (0x1C, data_offset),
            (0x48, code_addr),
            (0x64, data_addr),
            (0x90, len(code)),
            (0xAC, len(data)),
            (0xD8, 0x80004000),
            (0xDC, 0x100),
            (0xE0, code_addr),
        ]:
            header[off:off + 4] = struct.pack(">I", value)
        return bytes(header) + code + data
    is_32 = mode.startswith("32")
    big = mode not in {"le", "32le"}
    use_opd = mode == "be-opd"
    order = ">" if big else "<"
    ei_data = EI_DATA_BE if big else EI_DATA_LE

    if is_32:
        code_offset = 52 + 32
        words = [0x3860002A, 0x4E800020]
        if mode == "32be-scalar":
            words = [
                0x9421FFF0,  # stwu r1, -16(r1)
                0x2C030000,  # cmpwi r3, 0
                0x41820028,  # beq +0x28
                0x80830000,  # lwz r4, 0(r3)
                0x88A30004,  # lbz r5, 4(r3)
                0xA0C30006,  # lhz r6, 6(r3)
                0x1C840003,  # mulli r4, r4, 3
                0x54A5103A,  # rlwinm r5, r5, 2, 0, 29
                0x7C642A14,  # add r3, r4, r5
                0x7C633214,  # add r3, r3, r6
                0x38210010,  # addi r1, r1, 16
                0x4E800020,  # blr
                0x38600000,  # li r3, 0
                0x38210010,  # addi r1, r1, 16
                0x4E800020,  # blr
            ]
        code = b"".join(struct.pack(order + "I", w) for w in words)
        ident = bytes([
            0x7F, ord("E"), ord("L"), ord("F"),
            EI_CLASS_32,
            ei_data,
            1,
            0,
            0,
        ]) + bytes(7)
        ehdr = ident + struct.pack(
            order + "HHIIIIIHHHHHH",
            ET_EXEC,
            EM_PPC,
            EV_CURRENT,
            BASE_VADDR + code_offset,
            52,
            0,
            0,
            52,
            32,
            1,
            0,
            0,
            0,
        )
        phdr = struct.pack(
            order + "IIIIIIII",
            PT_LOAD,
            0,
            BASE_VADDR,
            BASE_VADDR,
            code_offset + len(code),
            code_offset + len(code),
            PF_R | PF_X,
            0x1000,
        )
        return ehdr + phdr + code

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
    modes = {"le", "be", "be-opd", "32le", "32be", "32be-scalar", "dol-scalar"}
    if len(sys.argv) != 3 or sys.argv[1] not in modes:
        print("usage: make_ppc64_tiny.py <le|be|be-opd|32le|32be|32be-scalar|dol-scalar> <out>", file=sys.stderr)
        return 1
    out = pathlib.Path(sys.argv[2])
    out.write_bytes(build(sys.argv[1]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
