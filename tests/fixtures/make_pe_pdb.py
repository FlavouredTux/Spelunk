#!/usr/bin/env python3
"""Emit a tiny PE32+ and a matching v7 MSF PDB sidecar.

Used to lock the PE → CodeView (RSDS) → MSF → S_PUB32 → symbol-table
flow that ember does when a Microsoft binary lands next to its `.pdb`.
The PE has no imports/exports/PDATA — only the bare minimum that loads.

Two arguments: the output PE path and the output PDB path. The PE
embeds the basename of the PDB path in its CodeView RSDS record, so
ember's loader-side sidecar lookup picks it up by basename.

Usage:
    make_pe_pdb.py <output.exe> <output.pdb>
"""

from __future__ import annotations

import pathlib
import struct
import sys


# ---- PE constants -----------------------------------------------------

IMAGE_BASE          = 0x140000000
SECTION_ALIGN       = 0x1000
FILE_ALIGN          = 0x200
MACHINE_AMD64       = 0x8664

IMAGE_FILE_EXECUTABLE_IMAGE     = 0x0002
IMAGE_FILE_LARGE_ADDRESS_AWARE  = 0x0020

SCN_CNT_CODE         = 0x00000020
SCN_CNT_INITIALIZED  = 0x00000040
SCN_MEM_EXECUTE      = 0x20000000
SCN_MEM_READ         = 0x40000000

IMAGE_DIRECTORY_ENTRY_DEBUG = 6
IMAGE_DEBUG_TYPE_CODEVIEW   = 2


def align(v: int, a: int) -> int:
    return (v + a - 1) & ~(a - 1)


# ---- MSF / PDB v7 builder --------------------------------------------

V7_MAGIC = (
    b"Microsoft C/C++ MSF 7.00\r\n"
    b"\x1a"
    b"DS"
    b"\x00\x00\x00"
)
assert len(V7_MAGIC) == 32

BLOCK_SIZE = 1024


def build_dbi_header(sym_record_stream_idx: int) -> bytes:
    """NewDBI (v7). Only SymRecordStream is read by ember, the rest are
    placeholders that pass our header-size sanity check."""
    out = bytearray()
    out += struct.pack("<i", -1)                   # signature (NewDBI)
    out += struct.pack("<I", 19990903)             # version (V70)
    out += struct.pack("<I", 1)                    # age
    out += struct.pack("<H", 0xFFFF)               # GlobalStreamIndex (none)
    out += struct.pack("<H", 0)                    # BuildNumber
    out += struct.pack("<H", 0xFFFF)               # PublicStreamIndex (none)
    out += struct.pack("<H", 0)                    # PdbDllVersion
    out += struct.pack("<H", sym_record_stream_idx)
    out += struct.pack("<H", 0)                    # PdbDllRbld
    for _ in range(8):
        out += struct.pack("<I", 0)                # substream sizes (all empty)
    out += struct.pack("<H", 0)                    # Flags
    out += struct.pack("<H", 0x8664)               # Machine
    out += struct.pack("<I", 0)                    # Padding
    return bytes(out)


def build_s_pub32(name: str, flags: int, section_offset: int,
                  segment: int) -> bytes:
    """Encode an S_PUB32 record. Length excludes the length field itself;
    the body is f1/f2/f3-padded to a 4-byte multiple."""
    name_b = name.encode() + b"\x00"
    body = struct.pack("<I", flags) + struct.pack("<I", section_offset)
    body += struct.pack("<H", segment)
    body += name_b
    # Pad whole record (length + kind + body) to 4-byte alignment.
    total_unpadded = 4 + len(body)
    pad = (-total_unpadded) % 4
    pad_bytes = bytes()
    pads = (0xF3, 0xF2, 0xF1)
    for i in range(pad):
        pad_bytes += bytes([pads[(pad - 1 - i)]])
    body += pad_bytes
    reclen = 2 + len(body)                          # excludes length field
    return struct.pack("<H", reclen) + struct.pack("<H", 0x110E) + body


def build_msf(streams: list[bytes]) -> bytes:
    """Pack `streams` into a v7 MSF. Block layout:
       block 0: superblock
       block 1: free-block map (zeros — never read)
       blocks 2..: stream data blocks, in stream order
       last-1:   directory
       last:     directory block-map (one u32 → directory's block index)
    """
    def blocks_for(sz: int) -> int:
        return 0 if sz == 0 else (sz + BLOCK_SIZE - 1) // BLOCK_SIZE

    # Layout pass.
    next_block = 2
    stream_blocks: list[list[int]] = []
    for s in streams:
        bs = []
        for _ in range(blocks_for(len(s))):
            bs.append(next_block)
            next_block += 1
        stream_blocks.append(bs)
    dir_block      = next_block; next_block += 1
    dir_map_block  = next_block; next_block += 1
    num_blocks     = next_block

    # Directory bytes.
    d = bytearray()
    d += struct.pack("<I", len(streams))
    for s in streams:
        d += struct.pack("<I", len(s))
    for bs in stream_blocks:
        for b in bs:
            d += struct.pack("<I", b)
    dir_size = len(d)
    assert dir_size <= BLOCK_SIZE, "directory must fit in one block"

    out = bytearray(num_blocks * BLOCK_SIZE)

    # Superblock.
    sb = bytearray()
    sb += V7_MAGIC
    sb += struct.pack("<I", BLOCK_SIZE)
    sb += struct.pack("<I", 1)              # free-block-map block index
    sb += struct.pack("<I", num_blocks)
    sb += struct.pack("<I", dir_size)
    sb += struct.pack("<I", 0)              # unknown
    sb += struct.pack("<I", dir_map_block)
    out[0:len(sb)] = sb

    # Stream blocks.
    for s, bs in zip(streams, stream_blocks):
        for i, b in enumerate(bs):
            chunk = s[i * BLOCK_SIZE:(i + 1) * BLOCK_SIZE]
            off = b * BLOCK_SIZE
            out[off:off + len(chunk)] = chunk

    # Directory.
    out[dir_block * BLOCK_SIZE:dir_block * BLOCK_SIZE + len(d)] = d

    # Directory block-map (one u32 → directory's block index).
    dm = struct.pack("<I", dir_block)
    out[dir_map_block * BLOCK_SIZE:dir_map_block * BLOCK_SIZE + 4] = dm

    return bytes(out)


def build_pdb() -> bytes:
    # Stream 0: old directory (empty).
    # Stream 1: PDB info (we put 4 bytes; ember doesn't validate it).
    # Stream 2: TPI (empty).
    # Stream 3: DBI header (sym records in stream 4).
    # Stream 4: symbol records: two S_PUB32.
    sym_record_stream = 4
    dbi = build_dbi_header(sym_record_stream)
    sym = b""
    sym += build_s_pub32(
        "extracted_main",
        flags=0x2,                  # function
        section_offset=0x000,
        segment=1,
    )
    sym += build_s_pub32(
        "extracted_helper",
        flags=0x2,
        section_offset=0x010,
        segment=1,
    )
    streams = [
        b"",
        struct.pack("<I", 20140508),
        b"",
        dbi,
        sym,
    ]
    return build_msf(streams)


# ---- PE builder ------------------------------------------------------

def build_pe(pdb_basename: str) -> bytes:
    rva_text  = 0x1000
    rva_rdata = 0x2000

    # .text: two functions, each `xor eax, eax; ret`.
    #   sub_140001000:  31 c0 c3
    #   sub_140001010:  31 c0 c3   (at +0x10)
    text = bytearray()
    text += b"\x31\xC0\xC3"          # sub_140001000
    while len(text) < 0x10:
        text += b"\xCC"              # int3 padding
    text += b"\x31\xC0\xC3"          # sub_140001010

    # .rdata: IMAGE_DEBUG_DIRECTORY entry + CodeView RSDS record.
    rdata = bytearray()
    debug_dir_off = len(rdata)
    # Skip 28 bytes for the debug-directory entry; back-patched later
    # once we know the RSDS RVA.
    rdata += b"\x00" * 28
    cv_rva_in_rdata = rva_rdata + len(rdata)
    rdata += b"RSDS"
    rdata += b"\x00" * 16            # GUID — value irrelevant for our parser
    rdata += struct.pack("<I", 1)    # Age
    rdata += pdb_basename.encode() + b"\x00"
    cv_size = len(rdata) - (cv_rva_in_rdata - rva_rdata)

    # Back-patch IMAGE_DEBUG_DIRECTORY[0]:
    #   +0  Characteristics  u32 (0)
    #   +4  TimeDateStamp    u32
    #   +8  Major/Minor      u16,u16
    # +12  Type              u32 (CODEVIEW = 2)
    # +16  SizeOfData        u32
    # +20  AddressOfRawData  u32 (RVA)
    # +24  PointerToRawData  u32 (file offset; we'll fill after we know)
    # We back-patch SizeOfData + AddressOfRawData now; the file-offset
    # field is computed once .rdata's file offset is fixed below.
    struct.pack_into("<IIHHIII", rdata, debug_dir_off,
                     0, 0, 0, 0,
                     IMAGE_DEBUG_TYPE_CODEVIEW,
                     cv_size,
                     cv_rva_in_rdata)

    rdata_virt_size = len(rdata)

    # File layout:
    #   foff_headers = 0
    #   foff_text    = FILE_ALIGN
    #   foff_rdata   = foff_text + FILE_ALIGN
    foff_headers = 0
    foff_text    = FILE_ALIGN
    foff_rdata   = foff_text + FILE_ALIGN

    # Now we know foff_rdata, so compute the CV record's file offset and
    # back-patch the PointerToRawData field.
    cv_file_off = foff_rdata + (cv_rva_in_rdata - rva_rdata)
    struct.pack_into("<I", rdata, debug_dir_off + 24, cv_file_off)

    # Pad section bytes to FILE_ALIGN.
    text_padded  = bytes(text)
    text_padded += b"\x00" * (align(len(text_padded), FILE_ALIGN) - len(text_padded))
    rdata_padded = bytes(rdata)
    rdata_padded += b"\x00" * (align(len(rdata_padded), FILE_ALIGN) - len(rdata_padded))

    file_size = foff_rdata + len(rdata_padded)

    # ---- DOS header + stub ---------------------------------------------
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)   # e_lfanew

    # ---- NT signature + COFF header ------------------------------------
    nt = bytearray()
    nt += b"PE\x00\x00"
    nt += struct.pack("<H", MACHINE_AMD64)
    nt += struct.pack("<H", 2)                 # NumberOfSections (text + rdata)
    nt += struct.pack("<I", 0)                 # TimeDateStamp
    nt += struct.pack("<I", 0)                 # PointerToSymbolTable
    nt += struct.pack("<I", 0)                 # NumberOfSymbols
    nt += struct.pack("<H", 240)               # SizeOfOptionalHeader (PE32+)
    nt += struct.pack("<H",
        IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE)

    # ---- Optional header (PE32+) ---------------------------------------
    opt = bytearray()
    opt += struct.pack("<H", 0x020B)           # Magic (PE32+)
    opt += struct.pack("<BB", 14, 0)           # Linker version
    opt += struct.pack("<I", len(text))        # SizeOfCode
    opt += struct.pack("<I", rdata_virt_size)  # SizeOfInitializedData
    opt += struct.pack("<I", 0)                # SizeOfUninitializedData
    opt += struct.pack("<I", rva_text)         # AddressOfEntryPoint
    opt += struct.pack("<I", rva_text)         # BaseOfCode
    opt += struct.pack("<Q", IMAGE_BASE)       # ImageBase
    opt += struct.pack("<I", SECTION_ALIGN)
    opt += struct.pack("<I", FILE_ALIGN)
    opt += struct.pack("<HH", 6, 0)            # OS version
    opt += struct.pack("<HH", 0, 0)            # Image version
    opt += struct.pack("<HH", 6, 0)            # Subsystem version
    opt += struct.pack("<I", 0)                # Win32VersionValue
    opt += struct.pack("<I", rva_rdata + align(rdata_virt_size, SECTION_ALIGN))
    opt += struct.pack("<I", FILE_ALIGN)       # SizeOfHeaders
    opt += struct.pack("<I", 0)                # CheckSum
    opt += struct.pack("<H", 3)                # Subsystem (CONSOLE)
    opt += struct.pack("<H", 0x8160)           # DllCharacteristics
    opt += struct.pack("<Q", 0x100000)         # SizeOfStackReserve
    opt += struct.pack("<Q", 0x1000)           # SizeOfStackCommit
    opt += struct.pack("<Q", 0x100000)         # SizeOfHeapReserve
    opt += struct.pack("<Q", 0x1000)           # SizeOfHeapCommit
    opt += struct.pack("<I", 0)                # LoaderFlags
    opt += struct.pack("<I", 16)               # NumberOfRvaAndSizes

    # 16 data directory entries; only DEBUG (index 6) populated.
    debug_rva = rva_rdata + debug_dir_off
    debug_size = 28
    for i in range(16):
        if i == IMAGE_DIRECTORY_ENTRY_DEBUG:
            opt += struct.pack("<II", debug_rva, debug_size)
        else:
            opt += struct.pack("<II", 0, 0)

    # ---- Section table ------------------------------------------------
    sec_text = bytearray(40)
    sec_text[0:8] = b".text\x00\x00\x00"
    struct.pack_into("<IIIIIIHHI", sec_text, 8,
                     len(text),                 # VirtualSize
                     rva_text,                  # VirtualAddress
                     align(len(text), FILE_ALIGN),
                     foff_text,
                     0, 0, 0, 0,
                     SCN_CNT_CODE | SCN_MEM_EXECUTE | SCN_MEM_READ)

    sec_rdata = bytearray(40)
    sec_rdata[0:8] = b".rdata\x00\x00"
    struct.pack_into("<IIIIIIHHI", sec_rdata, 8,
                     rdata_virt_size,
                     rva_rdata,
                     align(rdata_virt_size, FILE_ALIGN),
                     foff_rdata,
                     0, 0, 0, 0,
                     SCN_CNT_INITIALIZED | SCN_MEM_READ)

    headers = bytes(dos) + bytes(nt) + bytes(opt) + bytes(sec_text) + bytes(sec_rdata)
    headers += b"\x00" * (FILE_ALIGN - len(headers))

    out = bytearray(file_size)
    out[foff_headers:foff_headers + len(headers)] = headers
    out[foff_text:foff_text + len(text_padded)] = text_padded
    out[foff_rdata:foff_rdata + len(rdata_padded)] = rdata_padded
    return bytes(out)


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: make_pe_pdb.py <out.exe> <out.pdb>", file=sys.stderr)
        return 2
    exe_path = pathlib.Path(sys.argv[1])
    pdb_path = pathlib.Path(sys.argv[2])
    pe_bytes  = build_pe(pdb_path.name)
    pdb_bytes = build_pdb()
    exe_path.write_bytes(pe_bytes)
    pdb_path.write_bytes(pdb_bytes)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
