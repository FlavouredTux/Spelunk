#!/usr/bin/env python3
"""Emit a minidump that wraps the `pe_tiny` PE image as one in-memory module.

Produces a minidump structurally similar to make_minidump_tiny.py, but the
single Memory64 range covers the pe_tiny IMAGE_BASE (0x140000000) through
its SizeOfImage, and its bytes are the *file-mapped* layout of pe_tiny:
section raw bytes copied to their RVA offsets within the image, headers
included.

This exercises the A2 per-module PE walk inside MinidumpBinary: the loader
should pick up `add42` (an exported function) and `GetTickCount` (an IAT
import) from the module's in-memory PE headers, just as PeBinary does
when loading the same bytes from disk.

Usage:
  make_minidump_pe.py <pe_tiny-path> <output-path>
"""

import struct
import sys


ModuleListStream     = 4
SystemInfoStream     = 7
Memory64ListStream   = 9

PROCESSOR_ARCHITECTURE_AMD64 = 9

MDMP_SIGNATURE = 0x504D444D
MDMP_VERSION   = 0x0000A793


def utf16le_with_len(s: str) -> bytes:
    enc = s.encode("utf-16-le")
    return struct.pack("<I", len(enc)) + enc


def map_pe_image(pe_bytes: bytes) -> tuple[int, int, bytes]:
    """Reconstruct the in-memory image of a PE32+ from its on-disk bytes.

    Returns (image_base, size_of_image, image_bytes) where image_bytes
    is exactly size_of_image long and laid out as Windows would after
    mapping: headers at offset 0, then each section copied from its
    file offset to its RVA.
    """
    # DOS header → e_lfanew at 0x3C.
    e_lfanew = struct.unpack_from("<I", pe_bytes, 0x3C)[0]
    # COFF header right after PE\0\0 signature.
    coff_off = e_lfanew + 4
    num_sections = struct.unpack_from("<H", pe_bytes, coff_off + 2)[0]
    opt_size     = struct.unpack_from("<H", pe_bytes, coff_off + 0x10)[0]
    opt_off      = coff_off + 20

    image_base    = struct.unpack_from("<Q", pe_bytes, opt_off + 0x18)[0]
    sec_alignment = struct.unpack_from("<I", pe_bytes, opt_off + 0x20)[0]
    size_of_image = struct.unpack_from("<I", pe_bytes, opt_off + 0x38)[0]
    size_of_hdrs  = struct.unpack_from("<I", pe_bytes, opt_off + 0x3C)[0]

    image = bytearray(size_of_image)
    # Headers occupy [0, SizeOfHeaders) on disk and at the same offset
    # in memory.
    image[:size_of_hdrs] = pe_bytes[:size_of_hdrs]

    sec_tab_off = opt_off + opt_size
    for i in range(num_sections):
        s = sec_tab_off + i * 40
        vsize = struct.unpack_from("<I", pe_bytes, s + 0x08)[0]
        vrva  = struct.unpack_from("<I", pe_bytes, s + 0x0C)[0]
        rsize = struct.unpack_from("<I", pe_bytes, s + 0x10)[0]
        roff  = struct.unpack_from("<I", pe_bytes, s + 0x14)[0]
        backed = min(vsize, rsize)
        if backed:
            image[vrva:vrva + backed] = pe_bytes[roff:roff + backed]

    return image_base, size_of_image, bytes(image)


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    pe_path, out_path = sys.argv[1], sys.argv[2]

    with open(pe_path, "rb") as f:
        pe_bytes = f.read()
    module_base, module_size, image_bytes = map_pe_image(pe_bytes)

    blob = bytearray()
    # Header (32 bytes, patched later).
    blob.extend(b"\x00" * 32)

    nstreams = 3
    dir_rva  = len(blob)
    blob.extend(b"\x00" * (nstreams * 12))

    # SystemInfoStream.
    sysinfo_rva  = len(blob)
    sysinfo_data = bytearray(56)
    struct.pack_into("<H", sysinfo_data, 0, PROCESSOR_ARCHITECTURE_AMD64)
    blob.extend(sysinfo_data)

    # Memory64ListStream — header now, image bytes appended later.
    mem64_rva = len(blob)
    nranges = 1
    blob.extend(struct.pack("<Q", nranges))
    base_rva_off = len(blob)
    blob.extend(struct.pack("<Q", 0))
    blob.extend(struct.pack("<QQ", module_base, module_size))

    # ModuleListStream.
    modules_rva = len(blob)
    blob.extend(struct.pack("<I", 1))
    module_off = len(blob)
    blob.extend(b"\x00" * 108)
    name_rva_off = module_off + 0x14
    struct.pack_into("<Q", blob, module_off + 0x00, module_base)
    struct.pack_into("<I", blob, module_off + 0x08, module_size)

    # Memory bytes (referenced by Memory64List BaseRva).
    while len(blob) % 8:
        blob.append(0)
    memory_rva = len(blob)
    struct.pack_into("<Q", blob, base_rva_off, memory_rva)
    blob.extend(image_bytes)

    # Module name string. Use a recognisable basename so the
    # collision-prefix logic in MinidumpBinary has something stable
    # to chew on if/when a second module is added later.
    name_rva = len(blob)
    struct.pack_into("<I", blob, name_rva_off, name_rva)
    blob.extend(utf16le_with_len("pe_tiny.dll"))

    # Header.
    struct.pack_into("<I", blob, 0,  MDMP_SIGNATURE)
    struct.pack_into("<I", blob, 4,  MDMP_VERSION)
    struct.pack_into("<I", blob, 8,  nstreams)
    struct.pack_into("<I", blob, 12, dir_rva)

    sysinfo_size = 56
    mem64_size   = 16 + nranges * 16
    modules_size = 4 + 108

    def write_dir(i, stream_type, size, rva):
        off = dir_rva + i * 12
        struct.pack_into("<III", blob, off, stream_type, size, rva)

    write_dir(0, SystemInfoStream,   sysinfo_size, sysinfo_rva)
    write_dir(1, Memory64ListStream, mem64_size,   mem64_rva)
    write_dir(2, ModuleListStream,   modules_size, modules_rva)

    with open(out_path, "wb") as f:
        f.write(blob)
    return 0


if __name__ == "__main__":
    sys.exit(main())
