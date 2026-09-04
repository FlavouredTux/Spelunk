"""Small helpers for constructing deterministic version-3 Wii REL fixtures."""

import struct
from collections.abc import Sequence


_SECTION_TABLE_OFFSET = 0x4C
_TEXT_OFFSET = 0x80
_DATA_OFFSET = 0x90
_IMPORT_OFFSET = 0xA0
_SECTION_SLOT_SIZE = 0x10
_RELOCATION_ALIGNMENT = 0x10


def relocation(delta: int, kind: int, section: int = 0,
               addend: int = 0) -> bytes:
    """Serialize one eight-byte REL relocation-stream record."""
    return struct.pack(">HBBI", delta, kind, section, addend)


def _align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) & -alignment


def build_rel(module_id: int, text: bytes, data: bytes,
              streams: Sequence[tuple[int, bytes]]) -> bytes:
    """Build a four-section version-3 REL from ordered import streams."""
    if len(text) > _SECTION_SLOT_SIZE or len(data) > _SECTION_SLOT_SIZE:
        raise ValueError("text and data fixture sections must fit their fixed slots")
    if not streams:
        raise ValueError("a REL fixture must contain at least one import stream")
    if any(len(stream) % 8 != 0 for _, stream in streams):
        raise ValueError("REL relocation streams must contain complete records")

    import_size = len(streams) * 8
    relocation_offset = _align_up(
        _IMPORT_OFFSET + import_size, _RELOCATION_ALIGNMENT)

    stream_offsets: list[int] = []
    cursor = relocation_offset
    fixed_boundary: int | None = None
    for target_module, stream in streams:
        stream_offsets.append(cursor)
        if fixed_boundary is None and target_module in (0, module_id):
            fixed_boundary = cursor
        cursor += len(stream)
    if fixed_boundary is None:
        fixed_boundary = cursor

    imports = b"".join(
        struct.pack(">II", target_module, stream_offset)
        for (target_module, _), stream_offset in zip(streams, stream_offsets)
    )
    relocation_data = b"".join(stream for _, stream in streams)

    blob = bytearray(cursor)
    header = struct.pack(
        ">12I4B3I3I",
        module_id,
        0, 0,                         # next / prev are runtime fields
        4,                            # section count
        _SECTION_TABLE_OFFSET,
        0, 0,                         # external name offset / size
        3,                            # REL version
        4,                            # BSS size
        relocation_offset,
        _IMPORT_OFFSET,
        len(imports),
        1, 0, 0, 0,                   # prolog / epilog / unresolved / BSS section
        0, 0, 0,                      # function offsets
        4, 4,                         # section / BSS alignment
        fixed_boundary,
    )
    blob[:len(header)] = header

    sections = b"".join((
        struct.pack(">II", 0, 0),
        struct.pack(">II", _TEXT_OFFSET | 1, len(text)),
        struct.pack(">II", _DATA_OFFSET, len(data)),
        struct.pack(">II", 0, 4),
    ))
    blob[_SECTION_TABLE_OFFSET:_SECTION_TABLE_OFFSET + len(sections)] = sections
    blob[_TEXT_OFFSET:_TEXT_OFFSET + len(text)] = text
    blob[_DATA_OFFSET:_DATA_OFFSET + len(data)] = data
    blob[_IMPORT_OFFSET:_IMPORT_OFFSET + len(imports)] = imports
    blob[relocation_offset:relocation_offset + len(relocation_data)] = (
        relocation_data
    )
    return bytes(blob)
