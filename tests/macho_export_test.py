"""Check standalone C exports and execute scope/record regressions end to end."""
import argparse
import ctypes
import pathlib
import random
import re
import shutil
import struct
import sys
import tempfile

import macho_pipeline_test as support
from check_pseudocode import check_source


def main(args):
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
    from unicorn.x86_const import UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RSP, UC_X86_REG_RIP, UC_X86_REG_RAX, UC_X86_REG_XMM0
    root = support.ROOT
    run = support.run
    source = pathlib.Path(__file__).parent / 'support' / 'macho_exports.c'
    obj, binary, native_file = [root / x for x in ('export.o', 'export.dylib', 'native.so')]
    run([args.clang, '--target=x86_64-apple-macos10.15', '-O2', '-c', source, '-o', obj])
    run([args.ld64, '-arch', 'x86_64', '-platform_version', 'macos', '10.15', '10.15', '-dylib',
         '-undefined', 'dynamic_lookup', '-o', binary, obj])
    run([args.clang, '-O2', '-shared', '-fPIC', '-Wl,-Bsymbolic-functions', source, '-o', native_file])
    addresses = support.symbols(args.nm, binary)
    annotation = root / 'export.anns'
    annotation.write_text(f'sig {addresses["parse_scale"]:#x} double|const char*|text\n'
                          f'sig {addresses["parse_other"]:#x} double|const char*|text\n'
                          f'sig {addresses["record_message"]:#x} void|const char*|message\n')
    names = ['branch_scale', 'read_brightness', 'update_packed', 'start_record', 'call_join']
    # The C spelling of each source return type. The execution checks below
    # set ctypes restype themselves and read the ABI return register, so they
    # never consult the emitted declaration and cannot see a wrong return type
    # - a `double` function exported as `void` still passes them. Check the
    # emitted signature directly.
    # start_record's source type is u32, but it returns a bare literal 1 with
    # no width-carrying arithmetic, so the binary cannot distinguish u32 from
    # u64 and the decompiler's uint64_t default stands. Execution still
    # compares the low 32 bits.
    returns = {'branch_scale': 'float', 'read_brightness': 'float',
               'update_packed': 'uint64_t', 'start_record': 'uint64_t',
               'call_join': 'double', 'next_handle': 'uint32_t',
               'length_or_zero': 'uint64_t', 'call_atof_bridge': 'double'}
    exported = ''
    for name in names + ['next_handle', 'length_or_zero', 'call_atof_bridge']:
        text = run([args.spelunk, '--no-cache', '--emit-c', '--annotations', annotation, '-s', name, binary])
        (root / (name + '.c')).write_text(text)
        # No hand-written preamble: exports must include their declarations.
        diagnostics = check_source(text, compiler=args.clang, filename=name + '.c')
        assert not diagnostics, (name, diagnostics)
        assert 'unresolved' not in text and 'STRUCTURER_FAIL' not in text, (name, text)
        definition = re.search(r'^(\w[\w \*]*?)\s+' + re.escape(name) + r'\(', text, re.M)
        assert definition, (name, 'no definition found in export')
        assert definition.group(1) == returns[name], (
            name, 'exported return type', definition.group(1), 'want', returns[name])
        if name in names:
            exported += text + '\n'
    translation = root / 'exported.c'
    translation.write_text(exported)
    native = ctypes.CDLL(str(native_file))
    libs = [native]
    for opt in ['0', '2']:
        target = root / f'exported-O{opt}.so'
        run([args.clang, '-O' + opt, '-shared', '-fPIC', translation, native_file, '-o', target])
        libs.append(ctypes.CDLL(str(target)))
    event_count = ctypes.c_uint64.in_dll(native, 'event_count')
    event_value = ctypes.c_uint64.in_dll(native, 'event_value')
    native_callback = ctypes.cast(native.record_event, ctypes.c_void_p).value
    machine = Uc(UC_ARCH_X86, UC_MODE_64)
    for va, length, data in support.segments(binary):
        machine.mem_map(va, (length + 4095) & ~4095)
        machine.mem_write(va, data)
    data_base, stack, stop = 0x10000000, 0x20008000, 0x2000f000
    machine.mem_map(data_base, 4096)
    machine.mem_map(0x20000000, 0x10000)
    rng = random.Random(0x5CA1E)
    cases = []
    for text in [None, '', '0', '3', '9']:
        initial = bytearray(rng.randbytes(256))
        initial[224:228] = (text or '').encode().ljust(4, b'\0')
        cases.append(('branch_scale', 0, None if text is None else 224, bytes(initial)))
    for selector in [0, 1]:
        for text in ['0', '3', '9']:
            initial = bytearray(rng.randbytes(256))
            struct.pack_into('<Q', initial, 0, selector)
            initial[224:228] = text.encode().ljust(4, b'\0')
            cases.append(('call_join', 0, 224, bytes(initial)))
    for owner in [0, 1, 17, (1 << 63) + 7]:
        for supplied in [owner, owner ^ 1]:
            for value in [-0.0, 0.0625, 0.75, 1.0]:
                initial = bytearray(rng.randbytes(256))
                struct.pack_into('<Q', initial, 0, owner)
                struct.pack_into('<f', initial, 124, value)
                cases.append(('read_brightness', 0, supplied, bytes(initial)))
    cases.append(('read_brightness', None, 1, bytes(256)))
    for offset in [0, 1, 3]:
        for delta in [0, 1, 0xff, (1 << 32) - 1, (1 << 64) - 1]:
            cases.append(('update_packed', offset, delta, rng.randbytes(256)))
    for value in [0, 17, (1 << 63) + 3]:
        initial = bytearray(256)
        struct.pack_into('<Q', initial, 0, value)
        cases.append(('start_record', 0, 0, bytes(initial)))

    def prepare(initial, name, base, callback):
        data = bytearray(initial)
        if name == 'start_record':
            struct.pack_into('<Q', data, 8, base + 128)
            struct.pack_into('<Q', data, 184, callback)
        return data

    def normalize(data, name):
        data = bytearray(data)
        if name == 'start_record':
            data[8:16] = bytes(8)
            data[184:192] = bytes(8)
        return bytes(data)

    for name, first, second, initial in cases:
        machine.mem_write(data_base, bytes(prepare(initial, name, data_base, addresses['record_event'])))
        machine.mem_write(addresses['event_count'], bytes(8))
        machine.mem_write(addresses['event_value'], bytes(8))
        machine.mem_write(stack, struct.pack('<Q', stop))
        machine.reg_write(UC_X86_REG_RSP, stack)
        machine.reg_write(UC_X86_REG_RDI, 0 if first is None else data_base + first)
        text_argument = name in ('branch_scale', 'call_join')
        machine.reg_write(UC_X86_REG_RSI, (0 if second is None else data_base + second) if text_argument else second)
        machine.emu_start(addresses[name], stop, count=10000)
        assert machine.reg_read(UC_X86_REG_RIP) == stop, (name, 'step limit')
        floating = name in ('branch_scale', 'read_brightness', 'call_join')
        width = 8 if name == 'call_join' else 4 if floating or name == 'start_record' else 8
        returned = machine.reg_read(UC_X86_REG_XMM0 if floating else UC_X86_REG_RAX) & ((1 << (8 * width)) - 1)
        expected = (returned.to_bytes(width, 'little'), normalize(machine.mem_read(data_base, 256), name),
                    int.from_bytes(machine.mem_read(addresses['event_count'], 8), 'little'),
                    int.from_bytes(machine.mem_read(addresses['event_value'], 8), 'little'))
        for index, lib in enumerate(libs):
            storage = (ctypes.c_uint64 * 32)()
            base = ctypes.addressof(storage)
            ctypes.memmove(base, bytes(prepare(initial, name, base, native_callback)), 256)
            event_count.value = event_value.value = 0
            function = getattr(lib, name)
            function.argtypes = [ctypes.c_void_p, ctypes.c_void_p if text_argument else ctypes.c_uint64]
            function.restype = ctypes.c_double if name == 'call_join' else ctypes.c_float if floating else ctypes.c_uint32 if width == 4 else ctypes.c_uint64
            value = function(None if first is None else base + first,
                             (None if second is None else base + second) if text_argument else second)
            actual = (struct.pack('<d' if name == 'call_join' else '<f' if floating else '<I' if width == 4 else '<Q', value),
                      normalize(bytes(storage), name), event_count.value, event_value.value)
            assert actual == expected, (name, first, second, index, actual, expected)
    runner = root / 'ubsan.c'
    runner.write_text('''#include "exported.c"
int main(void) {
    uint8_t storage[256] = {0};
    if (branch_scale(storage, NULL) != 1.0f) return 1;
    if (branch_scale(storage, "3") != 3.25f) return 2;
    if (update_packed(storage + 1, UINT64_MAX) != 0) return 3;
    memset(storage, 0, sizeof(storage));
    if (read_brightness(storage, 1) != 1.0f) return 4;
    return 0;
}
''')
    executable = root / 'ubsan'
    run([args.clang, '-O2', '-fsanitize=undefined', '-fno-sanitize-recover=all', runner, native_file, '-o', executable])
    run([executable])
    print(f'{len(cases)} C export cases match Mach-O code, native C, and O0/O2 exports, including null branches and unaligned mixed-width writes')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    for tool in ['spelunk', 'clang', 'ld64', 'nm']:
        parser.add_argument('--' + tool, required=True)
    args = parser.parse_args()
    try:
        import unicorn
    except ImportError:
        print('SKIP: Python unicorn is required')
        raise SystemExit(77)
    support.ROOT = pathlib.Path(tempfile.mkdtemp(prefix='spelunk-c-export-'))
    try:
        main(args)
    except Exception:
        print(f'Artifacts retained at {support.ROOT}')
        raise
    else:
        shutil.rmtree(support.ROOT)
