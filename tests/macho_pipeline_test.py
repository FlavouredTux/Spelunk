"""Execute real compiler-generated Mach-O functions and their emitted C."""
import argparse
import ctypes
import json
import pathlib
import random
import re
import shutil
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'scripts'))
from check_pseudocode import check_source

ROOT = None
COMMAND = 0


def run(command, **kwargs):
    global COMMAND
    result = subprocess.run([str(x) for x in command], text=True, capture_output=True,
                            timeout=90, **kwargs)
    stem = ROOT / f'command-{COMMAND}'
    COMMAND += 1
    stem.with_suffix('.json').write_text(json.dumps([str(x) for x in command]))
    stem.with_suffix('.stdout').write_text(result.stdout)
    stem.with_suffix('.stderr').write_text(result.stderr)
    if result.returncode:
        raise RuntimeError(f'{command}: {result.stderr[-5000:]}')
    return result.stdout


def symbols(nm, path):
    return {m[2].removeprefix('_'): int(m[1], 16)
            for line in run([nm, '--defined-only', path]).splitlines()
            if (m := re.match(r'^([0-9a-fA-F]+) [A-Za-z] (.+)$', line))}


def segments(path):
    data = path.read_bytes()
    assert struct.unpack_from('<I', data)[0] == 0xfeedfacf
    result = []
    offset = 32
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        cmd, size = struct.unpack_from('<II', data, offset)
        if cmd == 0x19:
            va, length, fileoff, filesize = struct.unpack_from('<QQQQ', data, offset + 24)
            if length:
                result.append((va, length, data[fileoff:fileoff + filesize]))
        offset += size
    return result


SIGNATURES = {
    'fp_stack_helper': 'float|uint64_t|tag|float|a|float|b|float|c|float|d|float|e|float|f|float|g|float|h|float|i',
    'mixed_helper': 'double|uint64_t|first|float|x|double|y|uint64_t|last',
    'float_helper': 'float|uint64_t|tag|float|x',
    'stack_helper': 'double|uint64_t|a|double|x|uint64_t|b|float|y|uint64_t|c|uint64_t|d|uint64_t|e|uint64_t|f|uint64_t|g|double|z',
}
NAMES = ['mixed_call', 'mixed_tail', 'float_call', 'two_mixed_calls', 'stack_call', 'fp_stack_call', 'indirect_call', 'memory_update']
NAMES += ['literal_inf', 'literal_nan', 'literal_negative_zero', 'literal_division']
FLOAT_RESULTS = {'float_call', 'fp_stack_call', 'literal_inf', 'literal_negative_zero'}
PREAMBLE = '''#include <stdint.h>
#include <stdbool.h>
static double cvtss2sd(float x) { return (double)x; }
static float cvtsd2ss(double x) { return (float)x; }
'''


def main(args):
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
    from unicorn.x86_const import (UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX,
                                  UC_X86_REG_RSP, UC_X86_REG_RAX, UC_X86_REG_XMM0)
    from unicorn.x86_const import UC_X86_REG_RIP
    source = pathlib.Path(__file__).parent / 'support' / 'macho_calls.c'
    obj, binary, stripped, native_file = [ROOT / x for x in ['calls.o', 'calls.dylib', 'stripped.dylib', 'native.so']]
    run([args.clang, '--target=x86_64-apple-macos10.15', '-O2', '-c', source, '-o', obj])
    run([args.ld64, '-arch', 'x86_64', '-platform_version', 'macos', '10.15', '10.15', '-dylib', '-o', binary, obj])
    run([args.strip, '-s', '-o', stripped, binary])
    run([args.clang, '-O2', '-shared', '-fPIC', '-Wl,-Bsymbolic-functions', source, '-o', native_file])
    addresses = symbols(args.nm, binary)
    annotations = ROOT / 'calls.anns'
    annotations.write_text('\n'.join(f'sig {addresses[name]:#x} {sig}' for name, sig in SIGNATURES.items()))
    native = ctypes.CDLL(str(native_file))
    native_count = ctypes.c_uint64.in_dll(native, 'trace_count')
    native_ints = (ctypes.c_uint64 * 32).in_dll(native, 'trace_ints')
    native_floats = (ctypes.c_double * 32).in_dll(native, 'trace_floats')
    native_pointer = ctypes.c_void_p.in_dll(native, 'mixed_pointer')
    libraries = []
    # The helper signatures are explicit ABI oracles. Wrappers remain inferred.
    prototypes = '\n'.join(sig.split('|')[0] + ' ' + name + '(' + ', '.join(sig.split('|')[1::2]) + ');'
                           for name, sig in SIGNATURES.items())
    inferred_prototypes = '''double mixed_helper(uint64_t, uint64_t, float, double);
float float_helper(uint64_t, float);
'''
    for label, path in [('named', binary), ('stripped', stripped), ('inferred', binary)]:
        inventory = json.loads(run([args.ember, '--no-cache', '--functions', '--json', path]))
        entries = {int(row['addr'], 16) for row in inventory}
        assert all(addresses[name] in entries for name in NAMES), (label, 'lost function entry')
        selected = [name for name in NAMES if label != 'inferred' or name not in ('stack_call', 'fp_stack_call')]
        text = PREAMBLE + (inferred_prototypes if label == 'inferred' else prototypes) + '\n'
        annotation_args = [] if label == 'inferred' else ['--annotations', annotations]
        for name in selected:
            output = run([args.ember, '--no-cache', *annotation_args, '-p', '-s',
                          name if label == 'named' else hex(addresses[name]), path])
            # Exports survive stripping; bind the fixture entry name independently.
            (ROOT / f'{label}-{name}.c').write_text(output)
            text += output + '\n'
        generated = ROOT / f'{label}.c'
        generated.write_text(text)
        diagnostics = check_source(text, compiler=args.clang, filename=str(generated))
        assert not diagnostics, diagnostics
        for opt in ['0', '2']:
            destination = ROOT / f'{label}-O{opt}.so'
            run([args.clang, '-O' + opt, '-shared', '-fPIC', '-Werror=implicit-function-declaration',
                 '-Werror=incompatible-pointer-types', '-Werror=return-type',
                 '-Werror=unreachable-code-aggressive', generated, native_file, '-o', destination])
            libraries.append((ctypes.CDLL(str(destination)), selected))

    machine = Uc(UC_ARCH_X86, UC_MODE_64)
    for va, length, data in segments(binary):
        machine.mem_map(va, (length + 4095) & ~4095)
        machine.mem_write(va, data)
    base, stack, stop = 0x10000000, 0x20008000, 0x2000f000
    machine.mem_map(base, 4096)
    machine.mem_map(0x20000000, 0x10000)
    zero_trace = bytes(256)
    rng = random.Random(20260911)
    cases = [(name, tag, value, bytes(128)) for name in NAMES if name != 'memory_update' and not name.startswith('literal_')
             for tag in [0, 1, 17, (1 << 32) + 3]
             for value in [-8.0, -0.0, 0.0625, 1.5, 1048576.0]]
    cases += [(name, 0, 0.0, bytes(128)) for name in NAMES if name.startswith('literal_')]
    for n in [0, 1, 2, 5, 12]:
        for stop_index in [0, 1, 3, 16]:
            cases.append(('memory_update', n, stop_index, rng.randbytes(128)))

    def observed(lib, name, a, b, initial):
        if name == 'indirect_call':
            helper = 'alternate_helper' if a & 1 else 'mixed_helper'
            native_pointer.value = ctypes.cast(getattr(native, helper), ctypes.c_void_p).value
        native_count.value = 0
        ctypes.memset(ctypes.addressof(native_ints), 0, 256)
        ctypes.memset(ctypes.addressof(native_floats), 0, 256)
        buffer = (ctypes.c_uint64 * 16).from_buffer_copy(initial)
        fn = getattr(lib, name)
        if name == 'memory_update':
            fn.argtypes = [ctypes.POINTER(ctypes.c_uint64), ctypes.c_uint64, ctypes.c_uint64]
            fn.restype = ctypes.c_uint64
            result = struct.pack('<Q', fn(buffer, a, b))
        else:
            fp = ctypes.c_float if name in FLOAT_RESULTS else ctypes.c_double
            fn.argtypes, fn.restype = ([] if name.startswith('literal_') else [ctypes.c_uint64, fp]), fp
            value = fn() if name.startswith('literal_') else fn(a, b)
            result = struct.pack('<f' if name in FLOAT_RESULTS else '<d', value)
        return result, bytes(buffer), native_count.value, bytes(native_ints), bytes(native_floats)

    for name, a, b, initial in cases:
        machine.mem_write(base, initial)
        machine.mem_write(addresses['trace_count'], bytes(8))
        machine.mem_write(addresses['trace_ints'], zero_trace)
        machine.mem_write(addresses['trace_floats'], zero_trace)
        machine.mem_write(stack, struct.pack('<Q', stop))
        machine.reg_write(UC_X86_REG_RSP, stack)
        if name == 'indirect_call':
            helper = 'alternate_helper' if a & 1 else 'mixed_helper'
            machine.mem_write(addresses['mixed_pointer'], struct.pack('<Q', addresses[helper]))
        if name == 'memory_update':
            for register, value in [(UC_X86_REG_RDI, base), (UC_X86_REG_RSI, a), (UC_X86_REG_RDX, b)]:
                machine.reg_write(register, value)
        else:
            machine.reg_write(UC_X86_REG_RDI, a)
            machine.reg_write(UC_X86_REG_XMM0, int.from_bytes(struct.pack('<f' if name in FLOAT_RESULTS else '<d', b), 'little'))
        machine.emu_start(addresses[name], stop, count=10000)
        assert machine.reg_read(UC_X86_REG_RIP) == stop, (name, 'instruction limit exceeded')
        assert machine.reg_read(UC_X86_REG_RSP) == stack + 8, (name, 'did not return')
        width = 4 if name in FLOAT_RESULTS else 8
        result_register = UC_X86_REG_RAX if name == 'memory_update' else UC_X86_REG_XMM0
        value = machine.reg_read(result_register) & ((1 << (width * 8)) - 1)
        expected = (value.to_bytes(width, 'little'), bytes(machine.mem_read(base, 128)),
                    int.from_bytes(machine.mem_read(addresses['trace_count'], 8), 'little'),
                    bytes(machine.mem_read(addresses['trace_ints'], 256)),
                    bytes(machine.mem_read(addresses['trace_floats'], 256)))
        for i, (lib, supported) in enumerate([(native, NAMES)] + libraries):
            if name not in supported:
                continue
            actual = observed(lib, name, a, b, initial)
            assert actual == expected, (name, a, b, i, actual, expected)
    print(f'{len(cases)} cases: Mach-O machine code, native C, and named/stripped emitted C at O0/O2 agree on returns, all buffer bytes, and ordered helper argument traces; register-only wrappers also pass without signatures')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    for tool in ['ember', 'clang', 'ld64', 'strip', 'nm']:
        parser.add_argument('--' + tool, required=True)
    args = parser.parse_args()
    try:
        import unicorn
    except ImportError:
        print('SKIP: Python unicorn is required')
        raise SystemExit(77)
    ROOT = pathlib.Path(tempfile.mkdtemp(prefix='ember-macho-pipeline-'))
    try:
        main(args)
    except Exception:
        print(f'Artifacts retained at {ROOT}')
        raise
    else:
        shutil.rmtree(ROOT)
