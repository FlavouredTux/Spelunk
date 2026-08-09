#!/usr/bin/env python3
"""Build a minimal big-endian PPC32 ELF ET_REL object.

The fixture deliberately uses relocations in both code and data so Ember's
relocatable-object loader can be tested without requiring a cross compiler.
"""

import struct
import sys
from pathlib import Path


def align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & -alignment


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} OUTPUT")

    shstr = b"\0.text\0.data\0.rela.text\0.rela.data\0.symtab\0.strtab\0.shstrtab\0"
    shname = {name: shstr.index(name.encode()) for name in (
        ".text", ".data", ".rela.text", ".rela.data", ".symtab",
        ".strtab", ".shstrtab",
    )}
    strtab = b"\0local_entry\0external_call\0local_global\0"
    strname = {name: strtab.index(name.encode()) for name in (
        "local_entry", "external_call", "local_global",
    )}

    # bl external_call; lis r3, local_global@ha;
    # addi r3, r3, local_global@l; blr
    text = struct.pack(">IIII", 0x48000001, 0x3C600000, 0x38630000, 0x4E800020)
    data = bytes(4)

    def rela(offset: int, symbol: int, reloc_type: int, addend: int = 0) -> bytes:
        return struct.pack(">IIi", offset, (symbol << 8) | reloc_type, addend)

    rela_text = b"".join((
        rela(0, 2, 10),  # R_PPC_REL24 external_call
        # Big-endian halfword relocations name the immediate field itself,
        # which begins two bytes into each instruction.
        rela(6, 3, 6),   # R_PPC_ADDR16_HA local_global
        rela(10, 3, 4),  # R_PPC_ADDR16_LO local_global
    ))
    rela_data = rela(0, 1, 1)  # R_PPC_ADDR32 local_entry

    # ELF32 symbol layout: name, value, size, info, other, section index.
    symtab = bytes(16)
    symtab += struct.pack(">IIIBBH", strname["local_entry"], 0, len(text), 0x12, 0, 1)
    symtab += struct.pack(">IIIBBH", strname["external_call"], 0, 0, 0x12, 0, 0)
    symtab += struct.pack(">IIIBBH", strname["local_global"], 0, len(data), 0x11, 0, 2)

    contents = [b"", text, data, rela_text, rela_data, symtab, strtab, shstr]
    offsets = [0] * len(contents)
    blob = bytearray(52)
    for index in range(1, len(contents)):
        cursor = align(len(blob), 4)
        blob.extend(bytes(cursor - len(blob)))
        offsets[index] = cursor
        blob.extend(contents[index])

    shoff = align(len(blob), 4)
    blob.extend(bytes(shoff - len(blob)))

    # name, type, flags, addr, offset, size, link, info, alignment, entsize
    sections = [
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (shname[".text"], 1, 0x6, 0, offsets[1], len(text), 0, 0, 4, 0),
        (shname[".data"], 1, 0x3, 0, offsets[2], len(data), 0, 0, 4, 0),
        (shname[".rela.text"], 4, 0, 0, offsets[3], len(rela_text), 5, 1, 4, 12),
        (shname[".rela.data"], 4, 0, 0, offsets[4], len(rela_data), 5, 2, 4, 12),
        (shname[".symtab"], 2, 0, 0, offsets[5], len(symtab), 6, 1, 4, 16),
        (shname[".strtab"], 3, 0, 0, offsets[6], len(strtab), 0, 0, 1, 0),
        (shname[".shstrtab"], 3, 0, 0, offsets[7], len(shstr), 0, 0, 1, 0),
    ]
    for header in sections:
        blob.extend(struct.pack(">IIIIIIIIII", *header))

    ident = b"\x7fELF" + bytes((1, 2, 1, 0, 0)) + bytes(7)
    header = ident + struct.pack(
        ">HHIIIIIHHHHHH",
        1,       # ET_REL
        20,      # EM_PPC
        1,
        0,       # relocatable objects have no linked entry address
        0,
        shoff,
        0,
        52,
        0,
        0,
        40,
        len(sections),
        7,
    )
    blob[:52] = header
    Path(sys.argv[1]).write_bytes(blob)


if __name__ == "__main__":
    main()
