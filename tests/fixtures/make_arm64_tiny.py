#!/usr/bin/env python3
"""Emit a minimal AArch64 ELF executable for cross-platform golden tests.

The binary mirrors `make_ppc64_tiny.py` in spirit: one PT_LOAD segment,
one entry point, no symbol table. Two instructions live at the entry:

    add x0, x0, #42        ; 64-bit immediate add
    ret                    ; ret x30 (link register)

That's enough to drive the AArch64 decoder + lifter + structurer +
emitter end-to-end without needing a real ARM toolchain.

Usage:
    make_arm64_tiny.py <output-path>
"""

from __future__ import annotations

import pathlib
import struct
import sys


# ELF constants we need.
ET_EXEC      = 2
EV_CURRENT   = 1
PT_LOAD      = 1
PF_R         = 4
PF_X         = 1
EI_CLASS_64  = 2
EI_DATA_LE   = 1
EM_AARCH64   = 183  # 0xb7

EHDR_SIZE = 64
PHDR_SIZE = 56

BASE_VADDR = 0x100000


def build() -> bytes:
    code_offset = EHDR_SIZE + PHDR_SIZE

    # add x0, x0, #42  (sf=1, op=add, sh=0, imm12=0x2a, Rn=0, Rd=0)
    # ret              (br opc=0010, Rn=30; encoding RET defaults to x30)
    # Encoding: sf<<31 | fixed<<23 | imm12<<10 — note imm12 sits in bits
    # 21:10, NOT bits 11:0; that's a frequent off-by-N when hand-coding.
    code  = struct.pack("<I", 0x9100A800)
    code += struct.pack("<I", 0xD65F03C0)

    file_size = code_offset + len(code)
    entry = BASE_VADDR + code_offset

    ident = bytes([
        0x7F, ord("E"), ord("L"), ord("F"),
        EI_CLASS_64,
        EI_DATA_LE,
        1,    # EV_CURRENT
        0,    # ELFOSABI_SYSV
        0,    # ABI version
    ]) + bytes(7)

    ehdr = ident + struct.pack(
        "<HHIQQQIHHHHHH",
        ET_EXEC,
        EM_AARCH64,
        EV_CURRENT,
        entry,
        EHDR_SIZE,    # e_phoff
        0,            # e_shoff (no section headers)
        0,            # e_flags
        EHDR_SIZE,
        PHDR_SIZE,
        1,            # e_phnum
        0,            # e_shentsize
        0,            # e_shnum
        0,            # e_shstrndx
    )

    phdr = struct.pack(
        "<IIQQQQQQ",
        PT_LOAD,
        PF_R | PF_X,
        0,            # p_offset
        BASE_VADDR,
        BASE_VADDR,
        file_size,    # p_filesz
        file_size,    # p_memsz
        0x1000,
    )

    return ehdr + phdr + code


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: make_arm64_tiny.py <out>", file=sys.stderr)
        return 1
    out = pathlib.Path(sys.argv[1])
    out.write_bytes(build())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
