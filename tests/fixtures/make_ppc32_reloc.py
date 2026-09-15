#!/usr/bin/env python3
"""Build a minimal big-endian PPC32 ELF ET_REL object.

The fixture deliberately uses relocations in both code and data so Spelunk's
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
    # bl external_call; lis r3, local_global@ha;
    # addi r3, r3, local_global@l; blr; followed by relocation sentinels
    # and boundary/wraparound cases.
    text = struct.pack(
        ">IIIIIIIIIIIIII",
        0x48000001,
        0x3C600000,
        0x38630000,
        0x4E800020,
        0x49ABCDE3,
        0x38A55A5A,
        0x49BCDEF3,
        0x38C66B6B,
        0x48000003,
        0x38E71234,
        0x39080000,
        0x48000003,
        0x48000001,
        0x41820000,
    )
    # The final five bytes provide an unaligned four-byte sentinel window at
    # offset 13. An ordinary ADDR32 relocation must reject that site without
    # modifying the bytes (unlike R_PPC_UADDR32, which ELF does not support).
    data = bytes(12) + struct.pack(">IB", 0xA1B2C3D4, 0x5A)

    # name, value, size, info, other, section index. The tuple order defines
    # the symbol table order; relocations resolve indices through this map.
    symbols = (
        ("local_entry", 0, len(text), 0x12, 0, 1),
        ("external_call", 0, 0, 0x12, 0, 0),
        ("local_global", 0, len(data), 0x11, 0, 2),
        ("absolute_far", 0x02000000, 0, 0x12, 0, 0xFFF1),
        ("negative_far24", 0xFDFFFFFC, 0, 0x12, 0, 0xFFF1),
        ("negative_far16", 0xFFFF7FFF, 0, 0x11, 0, 0xFFF1),
        ("high_valid24", 0xFE000000, 0, 0x12, 0, 0xFFF1),
        ("high_valid16", 0xFFFF8000, 0, 0x11, 0, 0xFFF1),
        ("wrap_base", 0xFFFFFFF0, 0, 0x11, 0, 0xFFF1),
        ("common_global", 32, 12, 0x11, 0, 0xFFF2),
        ("positive_far16", 0x00008000, 0, 0x11, 0, 0xFFF1),
        ("absolute_zero", 0, 0, 0x11, 0, 0xFFF1),
    )
    symbol_names = tuple(symbol[0] for symbol in symbols)
    strtab = b"\0" + b"".join(
        name.encode() + b"\0" for name in symbol_names
    )
    strname = {name: strtab.index(name.encode()) for name in symbol_names}
    symbol_index = {
        name: index for index, (name, *_rest) in enumerate(symbols, start=1)
    }

    def rela(offset: int, symbol: int, reloc_type: int, addend: int = 0) -> bytes:
        return struct.pack(">IIi", offset, (symbol << 8) | reloc_type, addend)

    rela_text = b"".join((
        rela(0, symbol_index["external_call"], 10),
        # Big-endian halfword relocations name the immediate field itself,
        # which begins two bytes into each instruction.
        rela(6, symbol_index["local_global"], 6),
        rela(10, symbol_index["local_global"], 4),
        rela(16, symbol_index["absolute_far"], 2),
        rela(22, symbol_index["positive_far16"], 3),
        rela(24, symbol_index["negative_far24"], 2),
        rela(30, symbol_index["negative_far16"], 3),
        rela(32, symbol_index["high_valid24"], 2),
        rela(38, symbol_index["high_valid16"], 3),
        rela(42, symbol_index["wrap_base"], 3, 0x20),
        rela(44, symbol_index["wrap_base"], 2, 0x20),
        rela(48, symbol_index["wrap_base"], 10, 0x10000050),
        rela(52, symbol_index["wrap_base"], 11, 0x10000048),
    ))
    rela_data = b"".join((
        rela(0, symbol_index["local_entry"], 1),
        rela(4, symbol_index["common_global"], 1),
        rela(8, symbol_index["absolute_zero"], 1, 0x12345678),
        rela(13, symbol_index["local_entry"], 1),
    ))

    # ELF32 symbol layout: name, value, size, info, other, section index.
    symtab = bytes(16)
    for name, value, size, info, other, section_index in symbols:
        symtab += struct.pack(
            ">IIIBBH", strname[name], value, size, info, other, section_index
        )

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
