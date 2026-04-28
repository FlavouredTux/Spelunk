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

# extracted_main is hand-assembled as a 25-byte function with two
# stack-resident `int` locals — exercised by the PDB merge below.
EXTRACTED_MAIN_LEN   = 0x19
EXTRACTED_HELPER_OFF = 0x20

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


def build_dbi_header(sym_record_stream_idx: int,
                     mod_info_size: int = 0) -> bytes:
    """NewDBI (v7). SymRecordStream + ModInfoSize are the fields ember
    actually consumes; the rest are placeholders that pass our header-
    size sanity check."""
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
    out += struct.pack("<I", mod_info_size)        # ModInfoSize
    for _ in range(7):
        out += struct.pack("<I", 0)                # remaining substream sizes (empty)
    out += struct.pack("<H", 0)                    # Flags
    out += struct.pack("<H", 0x8664)               # Machine
    out += struct.pack("<I", 0)                    # Padding
    return bytes(out)


def build_mod_info(mod_sym_stream: int, sym_byte_size: int) -> bytes:
    """One ModInfo entry pointing at a per-module symbol stream.
    Whole record is 4-byte aligned via trailing zero pads."""
    out = bytearray()
    out += struct.pack("<I", 0)                    # Unused1
    out += b"\x00" * 28                            # SectionContribEntry (zeros)
    out += struct.pack("<H", 0)                    # Flags
    out += struct.pack("<H", mod_sym_stream)       # ModuleSymStream
    out += struct.pack("<I", sym_byte_size)        # SymByteSize
    out += struct.pack("<I", 0)                    # C11ByteSize
    out += struct.pack("<I", 0)                    # C13ByteSize
    out += struct.pack("<H", 0)                    # SourceFileCount
    out += struct.pack("<H", 0)                    # Padding
    out += struct.pack("<I", 0)                    # Unused2
    out += struct.pack("<I", 0)                    # SourceFileNameIndex
    out += struct.pack("<I", 0)                    # PdbFilePathNameIndex
    out += b"a.obj\x00"                            # ModuleName
    out += b"a.obj\x00"                            # ObjFileName
    while len(out) % 4 != 0:
        out += b"\x00"
    return bytes(out)


def _pad_record(reclen_so_far: int, body: bytearray) -> bytearray:
    """CodeView record padding: f1/f2/f3 trailers so total record length
    (length+kind+body) is a multiple of 4."""
    pad = (-(4 + len(body))) % 4
    pads = (0xF3, 0xF2, 0xF1)
    for i in range(pad):
        body += bytes([pads[(pad - 1 - i)]])
    return body


def build_cv_record(kind: int, body: bytes) -> bytes:
    body = _pad_record(4 + len(body), bytearray(body))
    reclen = 2 + len(body)
    return struct.pack("<H", reclen) + struct.pack("<H", kind) + bytes(body)


def build_lf_arglist(types: list[int]) -> bytes:
    body = struct.pack("<I", len(types))
    for t in types:
        body += struct.pack("<I", t)
    return build_cv_record(0x1201, body)


def build_lf_procedure(return_ti: int, param_count: int, arg_list_ti: int) -> bytes:
    body = struct.pack("<I", return_ti)
    body += struct.pack("<BB", 0, 0)            # CallConv, FuncAttrs
    body += struct.pack("<H", param_count)
    body += struct.pack("<I", arg_list_ti)
    return build_cv_record(0x1008, body)


def build_tpi_stream(records: list[bytes], ti_begin: int) -> bytes:
    """TPI v8 header (56 bytes) + concatenated records. TypeIndexEnd is
    ti_begin + len(records) so lookups stay in range."""
    records_bytes = b"".join(records)
    header = bytearray()
    header += struct.pack("<I", 20040203)        # Version (V80)
    header += struct.pack("<I", 56)              # HeaderSize
    header += struct.pack("<I", ti_begin)
    header += struct.pack("<I", ti_begin + len(records))
    header += struct.pack("<I", len(records_bytes))
    header += struct.pack("<H", 0xFFFF)          # HashStreamIndex
    header += struct.pack("<H", 0xFFFF)          # HashAuxStreamIndex
    header += struct.pack("<I", 0)               # HashKeySize
    header += struct.pack("<I", 0)               # NumHashBuckets
    header += struct.pack("<I", 0); header += struct.pack("<I", 0)  # HashValue
    header += struct.pack("<I", 0); header += struct.pack("<I", 0)  # IndexOffset
    header += struct.pack("<I", 0); header += struct.pack("<I", 0)  # HashAdj
    return bytes(header) + records_bytes


def build_s_gproc32(name: str, type_index: int, section_offset: int,
                    segment: int, code_size: int) -> bytes:
    body = bytearray()
    body += struct.pack("<I", 0)                 # Parent
    body += struct.pack("<I", 0)                 # End
    body += struct.pack("<I", 0)                 # Next
    body += struct.pack("<I", code_size)         # CodeSize
    body += struct.pack("<I", 0)                 # DbgStart
    body += struct.pack("<I", code_size)         # DbgEnd
    body += struct.pack("<I", type_index)        # TypeIndex
    body += struct.pack("<I", section_offset)    # Offset
    body += struct.pack("<H", segment)           # Segment
    body += struct.pack("<B", 0)                 # Flags
    body += name.encode() + b"\x00"
    return build_cv_record(0x1110, bytes(body))


def build_s_regrel32(name: str, frame_offset: int, type_index: int,
                     reg: int) -> bytes:
    body = struct.pack("<I", frame_offset & 0xFFFFFFFF)
    body += struct.pack("<I", type_index)
    body += struct.pack("<H", reg)
    body += name.encode() + b"\x00"
    return build_cv_record(0x1111, body)


def build_s_end() -> bytes:
    return build_cv_record(0x0006, b"")


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
    # Streams:
    #   0: old directory (empty)
    #   1: PDB info (we put 4 bytes; ember doesn't validate it)
    #   2: TPI — LF_ARGLIST(int,int), LF_PROCEDURE(int <- int,int)
    #   3: DBI header + 1 ModInfo entry pointing at stream 5
    #   4: global symbol-record stream — two S_PUB32
    #   5: module stream — S_GPROC32 for extracted_main, two S_REGREL32
    #      naming the locals "i" and "j", S_END.
    sym_record_stream = 4
    mod_sym_stream    = 5
    ti_begin          = 0x1000
    t_int4            = 0x74

    # TPI: 0x1000 = arglist(int,int); 0x1001 = proc returning int.
    tpi = build_tpi_stream(
        [build_lf_arglist([t_int4, t_int4]),
         build_lf_procedure(t_int4, 2, ti_begin)],
        ti_begin)

    # Module stream: signature 4 (C13) followed by:
    #   S_GPROC32 covering extracted_main (RVA 0x1000, length 0x19),
    #   S_REGREL32 "i" at [rsp+0x20], "j" at [rsp+0x24] — both int,
    #   S_END to close the proc scope.
    mod_records = b""
    mod_records += build_s_gproc32(
        name="extracted_main",
        type_index=ti_begin + 1,
        section_offset=0x000,
        segment=1,
        code_size=EXTRACTED_MAIN_LEN,
    )
    mod_records += build_s_regrel32("i", 0x20, t_int4, 332)   # CV_AMD64_RSP
    mod_records += build_s_regrel32("j", 0x24, t_int4, 332)
    mod_records += build_s_end()
    mod_stream = struct.pack("<I", 4) + mod_records           # C13 signature
    mod_sym_byte_size = len(mod_stream)

    mod_info  = build_mod_info(mod_sym_stream, mod_sym_byte_size)
    dbi       = build_dbi_header(sym_record_stream,
                                  mod_info_size=len(mod_info)) + mod_info

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
        section_offset=EXTRACTED_HELPER_OFF,
        segment=1,
    )
    streams = [
        b"",
        struct.pack("<I", 20140508),
        tpi,
        dbi,
        sym,
        mod_stream,
    ]
    return build_msf(streams)


# ---- PE builder ------------------------------------------------------

def build_pe(pdb_basename: str) -> bytes:
    rva_text  = 0x1000
    rva_rdata = 0x2000

    # .text: extracted_main has a real 25-byte stack frame; the body is
    # `int extracted_main(int a, int b) { int i = a; int j = b; return i + j; }`.
    # extracted_helper stays a 3-byte stub at RVA 0x20.
    text = bytearray()
    text += b"\x48\x83\xEC\x28"      # sub  rsp, 0x28
    text += b"\x89\x4C\x24\x20"      # mov  [rsp+0x20], ecx   ; i = a
    text += b"\x89\x54\x24\x24"      # mov  [rsp+0x24], edx   ; j = b
    text += b"\x8B\x44\x24\x20"      # mov  eax, [rsp+0x20]
    text += b"\x03\x44\x24\x24"      # add  eax, [rsp+0x24]
    text += b"\x48\x83\xC4\x28"      # add  rsp, 0x28
    text += b"\xC3"                  # ret
    assert len(text) == EXTRACTED_MAIN_LEN
    while len(text) < EXTRACTED_HELPER_OFF:
        text += b"\xCC"              # int3 padding
    text += b"\x31\xC0\xC3"          # extracted_helper: xor eax, eax; ret

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
