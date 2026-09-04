#!/usr/bin/env python3
"""Build a minimal version-3 Wii REL with three relocation streams."""

import struct
import sys
from pathlib import Path

from wii_rel_fixture import build_rel, relocation


MODULE_ID = 5


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} OUTPUT")

    # bl DOL target; lis/addi self data address; blr
    text = struct.pack(">IIII", 0x48000001, 0x3C600000, 0x38630000, 0x4E800020)
    data = bytes(12)

    external_stream = b"".join((
        relocation(0, 202, 2),
        relocation(8, 1, 2, 0x10),   # unresolved module 7 .data reference
        relocation(0, 203),
    ))

    self_stream = b"".join((
        relocation(0, 202, 1),       # R_DOLPHIN_SECTION: source .text
        relocation(6, 6, 2, 0),      # R_PPC_ADDR16_HA -> self .data
        relocation(4, 4, 2, 0),      # R_PPC_ADDR16_LO -> self .data
        relocation(0, 202, 2),       # R_DOLPHIN_SECTION: source .data
        relocation(0, 1, 1, 0),      # R_PPC_ADDR32 -> self _prolog
        relocation(0, 203),          # R_DOLPHIN_END
    ))
    dol_stream = b"".join((
        relocation(0, 202, 1),
        relocation(0, 10, 0, 0x80001200),  # R_PPC_REL24 -> main.dol
        relocation(0, 203),
    ))

    blob = build_rel(
        MODULE_ID,
        text,
        data,
        (
            (7, external_stream),
            (MODULE_ID, self_stream),
            (0, dol_stream),
        ),
    )
    Path(sys.argv[1]).write_bytes(blob)


if __name__ == "__main__":
    main()
