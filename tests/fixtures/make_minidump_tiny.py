#!/usr/bin/env python3
"""Emit a minimal x86_64 Microsoft minidump for cross-platform golden tests.

Streams included:
  * SystemInfoStream    — declares processor architecture = AMD64
  * Memory64ListStream  — one memory range carrying tiny x86_64 code
  * ModuleListStream    — one fake module pointing at the memory range,
                          name "tiny.dll" stored as a UTF-16LE string.

The code in the memory range matches `add42` from make_pe_tiny.py:

    lea eax, [rcx + 0x2a]   ; 8d 41 2a
    ret                     ; c3

Lifted+decompiled the result should read like the existing pe_tiny.add42
golden: returns its first arg + 0x2a under the Win64 ABI.

The minidump is structurally valid: signature, version, stream directory,
and per-stream RVAs all line up. It is not a real process snapshot —
there are no thread contexts, no exception record, no handle table. None
of those are needed to drive Ember's static-analysis pipeline.

Usage:
  make_minidump_tiny.py <output-path>
"""

import struct
import sys


# Stream type IDs from <DbgHelp.h>.
ModuleListStream     = 4
SystemInfoStream     = 7
Memory64ListStream   = 9

PROCESSOR_ARCHITECTURE_AMD64 = 9

MDMP_SIGNATURE = 0x504D444D   # 'MDMP'
MDMP_VERSION   = 0x0000A793   # low word == 0xA793

# The memory range we'll expose. Pick a high VA so it doesn't collide
# with anything else a real dumper might place.
MODULE_BASE = 0x00007FF600001000
MODULE_SIZE = 0x1000

# The actual code bytes that live at MODULE_BASE.
CODE_BYTES = bytes([
    0x8d, 0x41, 0x2a,   # lea eax, [rcx + 0x2a]
    0xc3,               # ret
])


def align(v, a):
    return (v + a - 1) & ~(a - 1)


def utf16le_with_len(s: str) -> bytes:
    """MINIDUMP_STRING: u32 length-in-bytes + UTF-16LE characters (no NUL)."""
    enc = s.encode("utf-16-le")
    return struct.pack("<I", len(enc)) + enc


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    out_path = sys.argv[1]

    # We grow the file linearly: header → directory → per-stream payloads.
    blob = bytearray()

    # Header is fixed-size (32 bytes); reserve and patch later.
    blob.extend(b"\x00" * 32)

    # Stream directory: 3 entries × 12 bytes. Reserve and patch.
    nstreams = 3
    dir_rva  = len(blob)
    blob.extend(b"\x00" * (nstreams * 12))

    # ---- SystemInfoStream payload ---------------------------------------
    # The struct is large in real DbgHelp; we only populate the prefix
    # Ember reads (u16 ProcessorArchitecture).
    sysinfo_rva  = len(blob)
    sysinfo_data = bytearray(56)   # full size of MINIDUMP_SYSTEM_INFO
    struct.pack_into("<H", sysinfo_data, 0, PROCESSOR_ARCHITECTURE_AMD64)
    blob.extend(sysinfo_data)

    # ---- Memory64ListStream payload -------------------------------------
    # Layout: u64 NumberOfMemoryRanges, u64 BaseRva, then N × (u64 va, u64 size).
    mem64_rva = len(blob)
    # We don't know BaseRva yet (it points at the memory bytes themselves
    # that come after the header+directory). Reserve and patch.
    nranges = 1
    blob.extend(struct.pack("<Q", nranges))
    base_rva_off = len(blob)
    blob.extend(struct.pack("<Q", 0))   # patched later
    blob.extend(struct.pack("<QQ", MODULE_BASE, MODULE_SIZE))

    # ---- ModuleListStream payload ---------------------------------------
    # Layout: u32 NumberOfModules, then N × MINIDUMP_MODULE (108 bytes).
    # Fields we set:
    #   u64  BaseOfImage       (MODULE_BASE)
    #   u32  SizeOfImage       (MODULE_SIZE)
    #   u32  CheckSum          (0)
    #   u32  TimeDateStamp     (0)
    #   u32  ModuleNameRva     (string_rva)
    #   ... rest zeroed (VS_FIXEDFILEINFO + CV record + misc record locators)
    modules_rva = len(blob)
    blob.extend(struct.pack("<I", 1))                   # NumberOfModules
    module_off = len(blob)
    blob.extend(b"\x00" * 108)
    # Reserve the ModuleNameRva position; the string itself lands later.
    name_rva_off = module_off + 0x14   # offset into the MINIDUMP_MODULE

    # Patch the fields we know.
    struct.pack_into("<Q", blob, module_off + 0x00, MODULE_BASE)
    struct.pack_into("<I", blob, module_off + 0x08, MODULE_SIZE)

    # ---- Memory bytes (referenced by Memory64List) ----------------------
    # Pad to 8-byte alignment for cleanliness, then drop the bytes.
    while len(blob) % 8:
        blob.append(0)
    memory_rva = len(blob)
    struct.pack_into("<Q", blob, base_rva_off, memory_rva)
    payload = bytearray(MODULE_SIZE)
    payload[:len(CODE_BYTES)] = CODE_BYTES
    blob.extend(payload)

    # ---- Module name string ---------------------------------------------
    name_rva = len(blob)
    struct.pack_into("<I", blob, name_rva_off, name_rva)
    blob.extend(utf16le_with_len("tiny.dll"))

    # ---- Header ---------------------------------------------------------
    struct.pack_into("<I", blob, 0,  MDMP_SIGNATURE)
    struct.pack_into("<I", blob, 4,  MDMP_VERSION)
    struct.pack_into("<I", blob, 8,  nstreams)
    struct.pack_into("<I", blob, 12, dir_rva)
    # CheckSum (12), TimeDateStamp (16), Flags (24) all left zero.

    # ---- Stream directory entries ---------------------------------------
    sysinfo_size = 56
    mem64_size   = len(blob) - mem64_rva  # everything from mem64_rva to EOF
                                          # — but trim back to just the list
    # Actually: the Memory64List "size" field is just the descriptor part
    # (header + entries), not the bytes themselves; the bytes live at
    # BaseRva and are referenced, not embedded.
    mem64_size = 16 + nranges * 16
    modules_size = 4 + 108

    # Fix the directory in-place.
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
