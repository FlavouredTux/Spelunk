#!/usr/bin/env python3
"""Build two version-3 Wii RELs with cross-module code and data edges."""

import struct
import sys
from pathlib import Path

from wii_rel_fixture import build_rel, relocation


SOURCE_ID = 9
PEER_ID = 10


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(f"usage: {sys.argv[0]} SOURCE_REL PEER_REL")

    # Source begins with an unresolved `bl 0`; the context linker redirects it
    # to the peer prolog and fills the source data word with the peer data VA.
    external_stream = b"".join((
        relocation(0, 202, 1),          # source .text
        relocation(0, 10, 1, 0),        # R_PPC_REL24 -> peer entry
        relocation(0, 202, 2),          # source .data
        relocation(0, 1, 2, 0),         # R_PPC_ADDR32 -> peer data
        relocation(0, 203),
    ))
    self_stream = b"".join((
        relocation(0, 202, 1),          # source .text
        relocation(0, 203),
    ))
    source = build_rel(
        SOURCE_ID,
        struct.pack(">II", 0x48000001, 0x4E800020),
        bytes(4),
        ((PEER_ID, external_stream), (SOURCE_ID, self_stream)),
    )
    peer = build_rel(
        PEER_ID,
        struct.pack(">I", 0x4E800020),
        struct.pack(">I", 0x12345678),
        ((PEER_ID, self_stream),),
    )
    Path(sys.argv[1]).write_bytes(source)
    Path(sys.argv[2]).write_bytes(peer)


if __name__ == "__main__":
    main()
