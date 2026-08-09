#!/usr/bin/env python3
"""Build a minimal version-3 Wii REL with three relocation streams."""

import struct
import sys
from pathlib import Path


MODULE_ID = 5


def relocation(delta: int, kind: int, section: int = 0, addend: int = 0) -> bytes:
    return struct.pack(">HBBI", delta, kind, section, addend)


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} OUTPUT")

    text_offset = 0x80
    data_offset = 0x90
    import_offset = 0x98
    reloc_offset = 0xB0

    # bl DOL target; lis/addi self data address; blr
    text = struct.pack(">IIII", 0x48000001, 0x3C600000, 0x38630000, 0x4E800020)
    data = bytes(8)

    self_stream = b"".join((
        relocation(0, 202, 1),       # R_DOLPHIN_SECTION: source .text
        relocation(4, 6, 2, 0),      # R_PPC_ADDR16_HA -> self .data
        relocation(4, 4, 2, 0),      # R_PPC_ADDR16_LO -> self .data
        relocation(0, 202, 2),       # R_DOLPHIN_SECTION: source .data
        relocation(0, 1, 1, 0),      # R_PPC_ADDR32 -> self _prolog
        relocation(0, 203),          # R_DOLPHIN_END
    ))
    dol_stream_offset = reloc_offset + len(self_stream)
    dol_stream = b"".join((
        relocation(0, 202, 1),
        relocation(0, 10, 0, 0x80001200),  # R_PPC_REL24 -> main.dol
        relocation(0, 203),
    ))
    external_stream_offset = dol_stream_offset + len(dol_stream)
    external_stream = b"".join((
        relocation(0, 202, 2),
        relocation(4, 1, 2, 0x10),   # unresolved module 7 .data reference
        relocation(0, 203),
    ))

    imports = b"".join((
        struct.pack(">II", MODULE_ID, reloc_offset),
        struct.pack(">II", 0, dol_stream_offset),
        struct.pack(">II", 7, external_stream_offset),
    ))

    blob = bytearray(external_stream_offset + len(external_stream))
    header = struct.pack(
        ">12I4B3I3I",
        MODULE_ID,
        0, 0,                    # next / prev are runtime fields
        4,                       # section count
        0x4C,                    # section table
        0, 0,                    # external name offset / size
        3,                       # REL version
        4,                       # BSS size
        reloc_offset,
        import_offset,
        len(imports),
        1, 0, 0, 0,              # prolog / epilog / unresolved / BSS section
        0, 0, 0,                 # function offsets
        4, 4,                    # section / BSS alignment
        reloc_offset,            # fix_size for self relocations
    )
    blob[:len(header)] = header

    sections = b"".join((
        struct.pack(">II", 0, 0),
        struct.pack(">II", text_offset | 1, len(text)),
        struct.pack(">II", data_offset, len(data)),
        struct.pack(">II", 0, 4),
    ))
    blob[0x4C:0x4C + len(sections)] = sections
    blob[text_offset:text_offset + len(text)] = text
    blob[data_offset:data_offset + len(data)] = data
    blob[import_offset:import_offset + len(imports)] = imports
    blob[reloc_offset:reloc_offset + len(self_stream)] = self_stream
    blob[dol_stream_offset:dol_stream_offset + len(dol_stream)] = dol_stream
    blob[external_stream_offset:external_stream_offset + len(external_stream)] = external_stream
    Path(sys.argv[1]).write_bytes(blob)


if __name__ == "__main__":
    main()
