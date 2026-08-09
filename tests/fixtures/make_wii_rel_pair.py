#!/usr/bin/env python3
"""Build two version-3 Wii RELs with cross-module code and data edges."""

import struct
import sys
from pathlib import Path


SOURCE_ID = 9
PEER_ID = 10


def relocation(delta: int, kind: int, section: int = 0, addend: int = 0) -> bytes:
    return struct.pack(">HBBI", delta, kind, section, addend)


def build_rel(module_id: int, text: bytes, data: bytes,
              external_id: int | None = None) -> bytes:
    text_offset = 0x80
    data_offset = 0x90
    import_offset = 0xA0
    reloc_offset = 0xB0

    self_stream = b"".join((
        relocation(0, 202, 1),  # R_DOLPHIN_SECTION: source .text
        relocation(0, 203),     # R_DOLPHIN_END
    ))
    streams = [self_stream]
    imports = [struct.pack(">II", module_id, reloc_offset)]

    if external_id is not None:
        external_offset = reloc_offset + len(self_stream)
        external_stream = b"".join((
            relocation(0, 202, 1),          # source .text
            relocation(0, 10, 1, 0),        # R_PPC_REL24 -> peer entry
            relocation(0, 202, 2),          # source .data
            relocation(0, 1, 2, 0),         # R_PPC_ADDR32 -> peer data
            relocation(0, 203),
        ))
        imports.append(struct.pack(">II", external_id, external_offset))
        streams.append(external_stream)

    import_bytes = b"".join(imports)
    relocation_bytes = b"".join(streams)
    blob = bytearray(reloc_offset + len(relocation_bytes))
    header = struct.pack(
        ">12I4B3I3I",
        module_id,
        0, 0,
        4,                       # section count
        0x4C,                    # section table
        0, 0,
        3,                       # REL version
        4,                       # BSS size
        reloc_offset,
        import_offset,
        len(import_bytes),
        1, 0, 0, 0,              # prolog / epilog / unresolved / BSS section
        0, 0, 0,
        4, 4,
        reloc_offset,            # fix_size / self stream
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
    blob[import_offset:import_offset + len(import_bytes)] = import_bytes
    blob[reloc_offset:reloc_offset + len(relocation_bytes)] = relocation_bytes
    return bytes(blob)


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(f"usage: {sys.argv[0]} SOURCE_REL PEER_REL")

    # Source begins with an unresolved `bl 0`; the context linker redirects it
    # to the peer prolog and fills the source data word with the peer data VA.
    source = build_rel(
        SOURCE_ID,
        struct.pack(">II", 0x48000001, 0x4E800020),
        bytes(4),
        external_id=PEER_ID,
    )
    peer = build_rel(
        PEER_ID,
        struct.pack(">I", 0x4E800020),
        struct.pack(">I", 0x12345678),
    )
    Path(sys.argv[1]).write_bytes(source)
    Path(sys.argv[2]).write_bytes(peer)


if __name__ == "__main__":
    main()
