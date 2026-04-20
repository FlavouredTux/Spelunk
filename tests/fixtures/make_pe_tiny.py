#!/usr/bin/env python3
"""Emit a minimal x86_64 PE32+ executable for cross-platform golden tests.

The fixture exercises every parser path our loader depends on:

  - DOS stub + NT signature + COFF + PE32+ optional header
  - Three sections: `.text` (executable), `.rdata` (import+export tables +
    hint-name strings), `.pdata` (RUNTIME_FUNCTION entries)
  - One IAT import:  KERNEL32.dll!GetTickCount
  - One named export: add42
  - Two PDATA entries (one per defined function)
  - Entry point `main` calls the import via `call qword ptr [rip + disp]`,
    so the import-at-got resolution path gets exercised end-to-end

Two functions are emitted:

  main  (RVA 0x1000): `sub rsp, 0x28; call [GetTickCount]; add rsp, 0x28; ret`
  add42 (RVA 0x1010): `lea eax, [rcx + 0x2a]; ret`   — Win64: arg0 in rcx

The binary is not actually runnable (it isn't signed, the PE checksum is
zero, and there's no DOS stub payload), but it passes every structural
check Ember's PeBinary loader performs.

Usage:
  make_pe_tiny.py <output-path>
"""

import struct
import sys


IMAGE_BASE         = 0x140000000
SECTION_ALIGN      = 0x1000
FILE_ALIGN         = 0x200
MACHINE_AMD64      = 0x8664

# PE characteristic flags used in the COFF header.
IMAGE_FILE_EXECUTABLE_IMAGE      = 0x0002
IMAGE_FILE_LARGE_ADDRESS_AWARE   = 0x0020

# IMAGE_SCN_MEM_* + CNT_* flags used in the section table.
SCN_CNT_CODE         = 0x00000020
SCN_CNT_INITIALIZED  = 0x00000040
SCN_MEM_EXECUTE      = 0x20000000
SCN_MEM_READ         = 0x40000000


def align(v, a):
    return (v + a - 1) & ~(a - 1)


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    out_path = sys.argv[1]

    # ---- Layout ----------------------------------------------------------
    # RVAs grow by SECTION_ALIGN; file offsets grow by FILE_ALIGN.
    rva_text  = 0x1000
    rva_rdata = 0x2000
    rva_pdata = 0x3000

    # Size of the PE headers (DOS + NT + section table) must fit in one
    # FILE_ALIGN block so section raw data starts at a clean boundary.
    foff_headers = 0
    foff_text    = FILE_ALIGN
    foff_rdata   = foff_text + FILE_ALIGN   # headers + text in one block each

    # ---- .text content ---------------------------------------------------
    # main @ rva_text + 0x00:
    #   sub rsp, 0x28      48 83 ec 28                     (4 bytes)
    #   call qword [rip+d] ff 15 <rel32>                   (6 bytes)
    #   add rsp, 0x28      48 83 c4 28                     (4 bytes)
    #   ret                c3                              (1 byte)
    # The rel32 for the call is chosen so the target is the IAT slot for
    # GetTickCount (an RVA computed below).
    #
    # add42 @ rva_text + 0x10:
    #   lea eax, [rcx+0x2a]  8d 41 2a                      (3 bytes)
    #   ret                  c3                            (1 byte)

    main_rva  = rva_text + 0x00
    add42_rva = rva_text + 0x10

    main_size  = 15
    add42_size = 4

    # ---- .rdata content --------------------------------------------------
    # Laid out as a byte buffer so we can compute every RVA before we pack
    # the final bytes. Layout:
    #   +0x00  IMAGE_IMPORT_DESCRIPTOR[0]     (20 bytes)
    #   +0x14  IMAGE_IMPORT_DESCRIPTOR[1]     (20 bytes, terminator)
    #   +0x28  INT: u64[] of hint-name RVAs   (16 bytes: GetTickCount, 0)
    #   +0x38  IAT: u64[] of hint-name RVAs   (16 bytes: GetTickCount, 0)
    #   +0x48  IMAGE_IMPORT_BY_NAME           (2 + len("GetTickCount")+1)
    #   +0x58  DLL name "KERNEL32.dll\0"
    #   +0x65  (align to 4)
    #   +...   IMAGE_EXPORT_DIRECTORY         (40 bytes)
    #   +...   export name string "pe_tiny.dll\0"
    #   +...   export AddressOfFunctions      (4 bytes: add42_rva)
    #   +...   export AddressOfNames          (4 bytes: name string RVA)
    #   +...   export AddressOfNameOrdinals   (2 bytes: 0)
    #   +...   export name "add42\0"

    rdata = bytearray()

    def here():
        return rva_rdata + len(rdata)

    def pad_to(rva_target):
        while here() < rva_target:
            rdata.append(0)

    # Placeholders; filled in after we know each field's RVA.
    desc_off = len(rdata)
    rdata += b"\x00" * 20   # import descriptor [0]
    rdata += b"\x00" * 20   # terminator

    int_off = len(rdata)
    int_rva = rva_rdata + int_off
    rdata += b"\x00" * 16   # INT

    iat_off = len(rdata)
    iat_rva = rva_rdata + iat_off
    rdata += b"\x00" * 16   # IAT

    hintname_rva = here()
    rdata += struct.pack("<H", 0)              # hint
    rdata += b"GetTickCount\x00"

    # 2-byte align before the DLL name to keep things tidy.
    while len(rdata) % 2 != 0:
        rdata.append(0)

    dllname_rva = here()
    rdata += b"KERNEL32.dll\x00"

    # 4-byte align before the export directory.
    while len(rdata) % 4 != 0:
        rdata.append(0)

    export_dir_rva = here()
    export_dir_off = len(rdata)
    rdata += b"\x00" * 40   # placeholder

    exp_dllname_rva = here()
    rdata += b"pe_tiny.dll\x00"

    while len(rdata) % 4 != 0:
        rdata.append(0)

    eat_rva = here()
    rdata += struct.pack("<I", add42_rva)

    ent_name_rva_slot = here()
    rdata += struct.pack("<I", 0)          # filled after name written

    eot_rva = here()
    rdata += struct.pack("<H", 0)          # ordinal index 0 into EAT

    exp_name_rva = here()
    rdata += b"add42\x00"

    # Back-patch import descriptor.
    struct.pack_into("<IIIII", rdata, desc_off,
                     int_rva,            # OriginalFirstThunk
                     0,                  # TimeDateStamp
                     0,                  # ForwarderChain
                     dllname_rva,        # Name
                     iat_rva)            # FirstThunk

    # INT + IAT point at the single hint-name record; second slot is the
    # zero terminator.
    struct.pack_into("<QQ", rdata, int_off, hintname_rva, 0)
    struct.pack_into("<QQ", rdata, iat_off, hintname_rva, 0)

    # Back-patch export directory.
    struct.pack_into("<IIHHIIIIIII", rdata, export_dir_off,
                     0,                     # Characteristics
                     0,                     # TimeDateStamp
                     0, 0,                  # Major/Minor version
                     exp_dllname_rva,       # Name
                     1,                     # Base (ordinal base)
                     1,                     # NumberOfFunctions
                     1,                     # NumberOfNames
                     eat_rva,               # AddressOfFunctions
                     ent_name_rva_slot,     # AddressOfNames
                     eot_rva)               # AddressOfNameOrdinals
    # Back-patch the ENT entry with the export-name RVA.
    struct.pack_into("<I", rdata,
                     ent_name_rva_slot - rva_rdata,
                     exp_name_rva)

    rdata_virt_size = len(rdata)

    # Now we know every RVA — build the main function bytes. The call
    # displacement encodes the absolute difference between (RIP after the
    # call instruction) and the IAT slot.
    iat_slot_rva = iat_rva           # first (and only) IAT entry
    call_ip      = main_rva + 4      # after the `sub rsp, 0x28`
    rel32        = iat_slot_rva - (call_ip + 6)

    main_code = (
        b"\x48\x83\xec\x28"                                # sub rsp, 0x28
      + b"\xff\x15" + struct.pack("<i", rel32)             # call [rip+rel32]
      + b"\x48\x83\xc4\x28"                                # add rsp, 0x28
      + b"\xc3"                                            # ret
    )
    assert len(main_code) == main_size, len(main_code)

    add42_code = b"\x8d\x41\x2a\xc3"
    assert len(add42_code) == add42_size, len(add42_code)

    text = bytearray()
    text += main_code
    # Pad to align add42 at rva_text + 0x10.
    while len(text) < (add42_rva - main_rva):
        text.append(0)
    text += add42_code

    text_virt_size = len(text)

    # ---- .pdata content --------------------------------------------------
    # x86_64 RUNTIME_FUNCTION: 12 bytes { Begin, End, UnwindInfo } as RVAs.
    # UnwindInfoAddress is required to be non-zero by the Windows loader;
    # our parser doesn't chase it, so pointing at the start of .pdata is a
    # harmless sentinel.
    pdata = bytearray()
    sentinel_unwind_rva = rva_pdata
    pdata += struct.pack("<III", main_rva,  main_rva  + main_size,  sentinel_unwind_rva)
    pdata += struct.pack("<III", add42_rva, add42_rva + add42_size, sentinel_unwind_rva)
    pdata_virt_size = len(pdata)

    # ---- Compute file offsets + sizes -----------------------------------
    foff_pdata = foff_rdata + align(len(rdata), FILE_ALIGN)

    text_raw_size  = align(len(text),  FILE_ALIGN)
    rdata_raw_size = align(len(rdata), FILE_ALIGN)
    pdata_raw_size = align(len(pdata), FILE_ALIGN)
    file_end       = foff_pdata + pdata_raw_size

    size_of_image   = align(rva_pdata + pdata_virt_size, SECTION_ALIGN)
    size_of_headers = FILE_ALIGN

    # ---- Headers --------------------------------------------------------
    # DOS header with only MZ magic + e_lfanew at 0x3C. We point e_lfanew
    # at 0x40 so the PE sig sits immediately after the DOS header (no DOS
    # stub — Ember doesn't execute the stub and Windows ignores an empty
    # one for our purposes).
    dos = bytearray(b"\x00" * 0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)

    # NT signature.
    nt_sig = b"PE\x00\x00"

    # COFF header (IMAGE_FILE_HEADER), 20 bytes.
    coff = struct.pack("<HHIIIHH",
                       MACHINE_AMD64,             # Machine
                       3,                         # NumberOfSections
                       0,                         # TimeDateStamp
                       0,                         # PointerToSymbolTable
                       0,                         # NumberOfSymbols
                       240,                       # SizeOfOptionalHeader
                       IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE)

    # Optional header (PE32+), 240 bytes.
    # Layout (all u32 unless marked): Magic(u16), LinkerMaj(u8), LinkerMin(u8),
    # SizeOfCode, SizeOfInitData, SizeOfUninitData, AddressOfEntryPoint,
    # BaseOfCode, ImageBase(u64), SectionAlignment, FileAlignment,
    # Major/Minor OS/Image/Subsystem (6 * u16), Win32VersionValue,
    # SizeOfImage, SizeOfHeaders, CheckSum, Subsystem(u16),
    # DllCharacteristics(u16), 4 * u64 stack/heap sizes, LoaderFlags,
    # NumberOfRvaAndSizes, DataDirectory[16] (8 bytes each).
    opt = bytearray()
    opt += struct.pack("<H", 0x20b)                    # Magic = PE32+
    opt += struct.pack("<BB", 14, 0)                   # Linker major/minor
    opt += struct.pack("<III", text_raw_size,          # SizeOfCode
                              rdata_raw_size + pdata_raw_size,  # SizeOfInitData
                              0)                       # SizeOfUninitData
    opt += struct.pack("<I", main_rva)                 # AddressOfEntryPoint
    opt += struct.pack("<I", rva_text)                 # BaseOfCode
    opt += struct.pack("<Q", IMAGE_BASE)               # ImageBase
    opt += struct.pack("<II", SECTION_ALIGN, FILE_ALIGN)
    opt += struct.pack("<HHHHHH",
                       6, 0,                           # Major/Minor OS
                       0, 0,                           # Major/Minor Image
                       6, 0)                           # Major/Minor Subsystem
    opt += struct.pack("<I", 0)                        # Win32VersionValue
    opt += struct.pack("<III", size_of_image, size_of_headers, 0)  # SizeOfImage, SizeOfHeaders, CheckSum
    opt += struct.pack("<HH", 3, 0x8160)               # Subsystem=CUI, DllCharacteristics
    opt += struct.pack("<QQQQ",
                       0x100000, 0x1000,               # Stack reserve, commit
                       0x100000, 0x1000)               # Heap reserve, commit
    opt += struct.pack("<II", 0, 16)                   # LoaderFlags, NumberOfRvaAndSizes
    # Data directories. Index 0 = Export, 1 = Import, 3 = Exception.
    data_dirs = [(0, 0)] * 16
    data_dirs[0] = (export_dir_rva, 40)
    data_dirs[1] = (rva_rdata,      40)  # import descriptor table + terminator
    data_dirs[3] = (rva_pdata,      pdata_virt_size)
    for va, sz in data_dirs:
        opt += struct.pack("<II", va, sz)
    assert len(opt) == 240, len(opt)

    # Section table: 3 entries of 40 bytes.
    def section_hdr(name, vsize, vrva, rsize, roff, chars):
        return (name.ljust(8, b"\0")
              + struct.pack("<IIII", vsize, vrva, rsize, roff)
              + struct.pack("<IIHHI", 0, 0, 0, 0, chars))

    sec_tab = bytearray()
    sec_tab += section_hdr(b".text",  text_virt_size, rva_text,  text_raw_size,  foff_text,
                           SCN_CNT_CODE | SCN_MEM_EXECUTE | SCN_MEM_READ)
    sec_tab += section_hdr(b".rdata", rdata_virt_size, rva_rdata, rdata_raw_size, foff_rdata,
                           SCN_CNT_INITIALIZED | SCN_MEM_READ)
    sec_tab += section_hdr(b".pdata", pdata_virt_size, rva_pdata, pdata_raw_size, foff_pdata,
                           SCN_CNT_INITIALIZED | SCN_MEM_READ)

    # ---- Write file ------------------------------------------------------
    out = bytearray(file_end)
    # Headers live in the first FILE_ALIGN bytes.
    out[0:0x40]               = dos
    out[0x40:0x44]            = nt_sig
    out[0x44:0x58]            = coff
    out[0x58:0x58 + 240]      = opt
    out[0x58 + 240:0x58 + 240 + len(sec_tab)] = sec_tab
    # Section contents.
    out[foff_text :foff_text  + len(text)]  = text
    out[foff_rdata:foff_rdata + len(rdata)] = rdata
    out[foff_pdata:foff_pdata + len(pdata)] = pdata

    with open(out_path, "wb") as f:
        f.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
