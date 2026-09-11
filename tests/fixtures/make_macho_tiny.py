#!/usr/bin/env python3
"""Emit a minimal x86_64 Mach-O executable for cross-platform golden tests.

The fixture carries __TEXT and __DATA segments with three functions:
  entry (0x100001000): mov eax, 0x2a; ret                → returns 42
  add42 (0x100001006): lea eax, [rdi + 0x2a]; ret        → returns a1+42
  read_answer          : mov eax, [rip + g_answer]; ret  → returns g_answer

By default LC_MAIN points at entry; --unixthread emits LC_UNIXTHREAD instead
and intentionally omits the _main symbol so the loader must synthesize it
from the thread-state PC. LC_SYMTAB lists the other functions and g_answer.
No dynamic imports / dyld-info - we only want to exercise the loader's
header, segment, symtab, entry-command, and LC_FUNCTION_STARTS paths.
--fat wraps the same thin x86_64 slice in a Universal Mach-O header, with an
unsupported dummy slice first so the loader must choose the supported slice.

Usage:
  make_macho_tiny.py [--unixthread|--exports-trie|--data-in-code|--fat] <output-path>
"""

import struct
import sys


def align(v, a):
    return (v + a - 1) & ~(a - 1)


def align8(v):
    return align(v, 8)


def uleb128(v):
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def main() -> int:
    mode = "main"
    args = sys.argv[1:]
    if args and args[0] == "--unixthread":
        mode = "unixthread"
        args = args[1:]
    elif args and args[0] == "--exports-trie":
        mode = "exports-trie"
        args = args[1:]
    elif args and args[0] == "--data-in-code":
        mode = "data-in-code"
        args = args[1:]
    elif args and args[0] == "--fat":
        mode = "fat"
        args = args[1:]
    elif args and args[0] == "--x64-signatures":
        mode = "x64-signatures"
        args = args[1:]
    elif args and args[0] == "--zero-base":
        mode = "zero-base"
        args = args[1:]
    if len(args) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    out_path = args[0]

    PAGE = 0x1000
    BASE = 0 if mode == "zero-base" else 0x100000000

    # Machine code:
    #  entry:   b8 2a 00 00 00   mov eax, 42
    #           c3               ret
    #  add42:   8d 47 2a         lea eax, [rdi + 42]
    #           c3               ret
    #  read_answer:
    #           8b 05 xx xx xx xx mov eax, dword ptr [rip + g_answer]
    #           c3               ret

    # Layout:
    #   file offset 0           : mach_header_64 + load commands (< 1 page)
    #   file offset PAGE        : __TEXT contents (code)
    #   file offset PAGE * 2    : __DATA contents
    text_file_off = PAGE
    data_file_off = PAGE * 2
    text_vmaddr   = BASE + PAGE
    data_vmaddr   = BASE + PAGE * 2
    entry_vmaddr  = text_vmaddr + 0
    add42_vmaddr  = text_vmaddr + 6
    read_vmaddr   = text_vmaddr + 10
    text_vmsize   = PAGE
    data_vmsize   = PAGE

    next_after_mov = read_vmaddr + 6
    disp = data_vmaddr - next_after_mov
    read_answer = b"\x8b\x05" + struct.pack("<i", disp) + b"\xc3"
    code = bytes.fromhex("b82a000000c3") + bytes.fromhex("8d472ac3") + read_answer
    data_guard_vmaddr = text_vmaddr + len(code)
    enc_call_data = b"\xe8" + struct.pack("<i", add42_vmaddr - (data_guard_vmaddr + 10))
    data_guard = bytes.fromhex("b801000000") + enc_call_data + bytes.fromhex("b802000000c3")
    if mode == "data-in-code":
        code += data_guard
    extra_symbols = []
    if mode == "x64-signatures":
        def function(name, body):
            extra_symbols.append((name, text_vmaddr + len(code), 1))
            return body
        # Incoming float lanes, with an untouched integer return carrier.
        code += function("_store_floats", bytes.fromhex(
            "f30f1107 f30f114f04 f30f115708 f30f115f0c c3"))
        # A void early exit plus incidental EAX on the writing path.
        code += function("_optional_store", bytes.fromhex(
            "4885ff 7407 b82a000000 8907 c3"))
        # Seventh SysV argument forwarded to a one-argument callee.
        start = text_vmaddr + len(code)
        code += function("_stack_forward", bytes.fromhex("55 4889e5 488b7d10 e8") +
                         struct.pack("<i", add42_vmaddr - (start + 13)) +
                         bytes.fromhex("5d c3"))
    data = struct.pack("<I", 0x12345678)

    # Build the __TEXT segment load command (72 header + 80-byte section entry).
    seg_text = bytearray()
    seg_text += struct.pack("<II", 0x19, 72 + 80)        # cmd=LC_SEGMENT_64, cmdsize
    seg_text += b"__TEXT".ljust(16, b"\0")                # segname[16]
    seg_text += struct.pack("<QQQQ",
                            0 if mode == "zero-base" else text_vmaddr,
                            PAGE * 2 if mode == "zero-base" else text_vmsize,
                            0 if mode == "zero-base" else text_file_off,
                            PAGE + len(code) if mode == "zero-base" else len(code))
    seg_text += struct.pack("<IIII", 5, 5, 1, 0)          # maxprot, initprot, nsects, flags
    seg_text += b"__text".ljust(16, b"\0")                # sectname[16]
    seg_text += b"__TEXT".ljust(16, b"\0")                # segname[16]
    seg_text += struct.pack("<QQ", text_vmaddr, len(code))  # addr, size
    seg_text += struct.pack("<II", text_file_off, 4)      # offset, align
    # reloff, nreloc, flags, reserved1, reserved2, reserved3 = 6 × u32
    seg_text += struct.pack("<IIIIII", 0, 0, 0x80000400, 0, 0, 0)

    # __DATA segment holding a named global.
    seg_data = bytearray()
    seg_data += struct.pack("<II", 0x19, 72 + 80)
    seg_data += b"__DATA".ljust(16, b"\0")
    seg_data += struct.pack("<QQQQ",
                            data_vmaddr, data_vmsize,
                            data_file_off, len(data))
    seg_data += struct.pack("<IIII", 3, 3, 1, 0)          # rw-
    seg_data += b"__data".ljust(16, b"\0")
    seg_data += b"__DATA".ljust(16, b"\0")
    seg_data += struct.pack("<QQ", data_vmaddr, len(data))
    seg_data += struct.pack("<II", data_file_off, 2)
    seg_data += struct.pack("<IIIIII", 0, 0, 0, 0, 0, 0)

    # __LINKEDIT segment holding symtab + strtab.
    link_file_off = align8(data_file_off + len(data))

    # nlist_64: n_strx(4), n_type(1), n_sect(1), n_desc(2), n_value(8) = 16
    # Symbols: _main → entry, _add42 → add42, _read_answer → read_answer,
    #          _g_answer → __DATA,__data.
    strings = bytearray(b"\0")
    sym_offs = {}

    def add_string(s):
        sym_offs[s] = len(strings)
        strings.extend(s.encode("ascii") + b"\0")

    if mode in ("main", "fat"):
        add_string("_main")
    if mode not in ("exports-trie", "zero-base"):
        add_string("_add42")
    if mode != "zero-base":
        add_string("_read_answer")
    if mode == "data-in-code":
        add_string("_data_guard")
    add_string("_g_answer")
    for name, _, _ in extra_symbols:
        add_string(name)
    strtab = bytes(strings)

    nlist = bytearray()
    syms = []
    if mode in ("main", "fat"):
        syms.append(("_main", entry_vmaddr, 1))
    if mode not in ("exports-trie", "zero-base"):
        syms.append(("_add42", add42_vmaddr, 1))
    if mode != "zero-base":
        syms.append(("_read_answer", read_vmaddr, 1))
    if mode == "data-in-code":
        syms.append(("_data_guard", data_guard_vmaddr, 1))
    syms.append(("_g_answer", data_vmaddr, 2))
    syms.extend(extra_symbols)
    for name, vm, sect in syms:
        nlist += struct.pack("<IBBHQ", sym_offs[name], 0x0F, sect, 0, vm)  # N_SECT|N_EXT
    # LC_FUNCTION_STARTS data: ULEB128 deltas from __TEXT base.
    #   first delta = entry - text_vmaddr = 0 → terminator, can't use 0
    # The on-disk encoding uses non-zero deltas; first delta is (entry - text_vmaddr),
    # which here is 0. Workaround: place entry at text_vmaddr+6 and add42 at +0?
    # Simpler: use a one-entry starts list skipping entry=0 is awkward, so
    # fall back to just listing add42 at delta 6. Linker tools treat the
    # __TEXT base itself as implicitly a function start when the first
    # delta is non-zero - matches what we want for coverage anyway.
    fn_starts = (
        (uleb128(text_vmaddr) if mode == "zero-base" else b"") +
        uleb128(add42_vmaddr - text_vmaddr) +
        uleb128(read_vmaddr - add42_vmaddr) +
        (uleb128(data_guard_vmaddr - read_vmaddr) if mode == "data-in-code" else b"") +
        b"\0"
    )
    def export_trie(symbol: str, image_offset: int) -> bytes:
        terminal = uleb128(0) + uleb128(image_offset)  # flags, address offset
        child = uleb128(len(terminal)) + terminal + bytes([0])
        edge = symbol.encode("ascii") + b"\0"
        child_off = 0
        while True:
            root = uleb128(0) + bytes([1]) + edge + uleb128(child_off)
            new_child_off = len(root)
            if new_child_off == child_off:
                return root + child
            child_off = new_child_off

    exports = export_trie("_exported_add42", add42_vmaddr - text_vmaddr) if mode == "exports-trie" else b""
    data_in_code = b""
    if mode == "data-in-code":
        data_in_code = struct.pack("<IHH",
                                   text_file_off + (data_guard_vmaddr - text_vmaddr) + 5,
                                   len(enc_call_data),
                                   1)

    # Align everything to 8.
    sym_off = link_file_off
    str_off = sym_off + len(nlist)
    fn_starts_off = align8(str_off + len(strtab))
    data_in_code_off = align8(fn_starts_off + len(fn_starts))
    exports_off = align8(data_in_code_off + len(data_in_code))
    link_filesize = exports_off + len(exports) - link_file_off

    seg_link = bytearray()
    seg_link += struct.pack("<II", 0x19, 72)
    seg_link += b"__LINKEDIT".ljust(16, b"\0")
    seg_link += struct.pack("<QQQQ",
                            data_vmaddr + data_vmsize, PAGE,
                            link_file_off, link_filesize)
    seg_link += struct.pack("<IIII", 1, 1, 0, 0)   # r--

    # LC_SYMTAB: cmd(4) cmdsize(4) symoff(4) nsyms(4) stroff(4) strsize(4)
    lc_symtab = struct.pack("<IIIIII", 0x02, 24, sym_off, len(syms), str_off, len(strtab))

    # LC_FUNCTION_STARTS (linkedit_data_command): cmd cmdsize dataoff datasize
    lc_fnstarts = struct.pack("<IIII", 0x26, 16, fn_starts_off, len(fn_starts))
    lc_exports = b""
    if mode == "exports-trie":
        lc_exports = struct.pack("<IIII", 0x80000033, 16, exports_off, len(exports))
    lc_data_in_code = b""
    if mode == "data-in-code":
        lc_data_in_code = struct.pack("<IIII", 0x29, 16, data_in_code_off, len(data_in_code))

    # LC_MAIN: cmd cmdsize entryoff stacksize. LC_UNIXTHREAD: cmd cmdsize,
    # flavor/count, then x86_thread_state64_t with RIP at register slot 16.
    if mode == "unixthread":
        regs = [0] * 21
        regs[16] = entry_vmaddr
        lc_entry = struct.pack("<IIII", 0x05, 16 + 21 * 8, 0x04, 42)
        lc_entry += struct.pack("<" + "Q" * 21, *regs)
    else:
        lc_entry = struct.pack("<IIQQ", 0x80000028, 24, text_file_off, 0)

    lcs = (bytes(seg_text) + bytes(seg_data) + bytes(seg_link) + lc_symtab +
           lc_fnstarts + lc_exports + lc_data_in_code + lc_entry)
    ncmds = 7 if mode in ("exports-trie", "data-in-code") else 6
    sizeofcmds = len(lcs)

    hdr = struct.pack("<IIIIIIII",
                      0xFEEDFACF,      # magic (LE 64-bit Mach-O)
                      0x01000007,      # cputype = x86_64
                      3,               # cpusubtype = ALL
                      2,               # filetype = MH_EXECUTE
                      ncmds,
                      sizeofcmds,
                      0x00200085,      # flags: NOUNDEFS|DYLDLINK|TWOLEVEL|PIE
                      0)               # reserved

    # Glue everything together.
    out = bytearray()
    out += hdr
    out += lcs
    out += b"\0" * (text_file_off - len(out))
    out += code
    out += b"\0" * (data_file_off - len(out))
    out += data
    out += b"\0" * (sym_off - len(out))
    out += nlist
    out += strtab
    out += b"\0" * (fn_starts_off - len(out))
    out += fn_starts
    out += b"\0" * (data_in_code_off - len(out))
    out += data_in_code
    out += b"\0" * (exports_off - len(out))
    out += exports

    if mode == "fat":
        thin = bytes(out)
        header_size = 8 + 2 * 20
        dummy = b"\0\0\0\0"
        dummy_off = align(header_size, 4)
        thin_off = align(dummy_off + len(dummy), PAGE)

        fat = bytearray()
        fat += struct.pack(">II", 0xCAFEBABE, 2)
        # Unsupported first slice: proves the loader skips to a supported arch.
        fat += struct.pack(">IIIII", 0x00000012, 0, dummy_off, len(dummy), 2)
        fat += struct.pack(">IIIII", 0x01000007, 3, thin_off, len(thin), 12)
        fat += b"\0" * (dummy_off - len(fat))
        fat += dummy
        fat += b"\0" * (thin_off - len(fat))
        fat += thin
        out = fat

    with open(out_path, "wb") as f:
        f.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
