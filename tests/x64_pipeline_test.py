"""Compare native fixtures, pre/post-cleanup integer SSA, and emitted C."""
import ctypes
import pathlib
import random
import re
import subprocess
import sys
import tempfile

EMBER, PROBE, CC, SUPPORT = sys.argv[1:]
SUPPORT = pathlib.Path(SUPPORT)
MASK = (1 << 64) - 1


def run(args, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True, **kwargs).stdout


HELPERS = r'''
#include <stdint.h>
#include <stdbool.h>
static uint64_t helper_high(uint64_t a, uint64_t b) {
    return (uint64_t)(((unsigned __int128)a * b) >> 64);
}
static uint64_t helper_signed_high(uint64_t a, uint64_t b) {
    return (uint64_t)(((__int128)(int64_t)a * (int64_t)b) >> 64);
}
static uint64_t helper_low(uint64_t a, uint64_t b) { return a * b; }
static uint32_t helper_high32(uint32_t a, uint32_t b) { return ((uint64_t)a * b) >> 32; }
static uint32_t helper_low32(uint32_t a, uint32_t b) { return a * b; }
/* Only fixtures whose outputs do not depend on entry PF use this stub. */
static bool parity(void) { return false; }
/* Flag-initialization fixtures use a 32-bit ADD. */
static bool overflow_add(uint32_t a, uint32_t b) {
    return ((~(a ^ b) & (a ^ (a + b))) >> 31) != 0;
}
#define ROTATE(W,T) \
static T rotr##W(T a, uint64_t n) { n %= W; return n ? (T)(((uint64_t)a >> n) | ((uint64_t)a << (W-n))) : a; } \
static T rotl##W(T a, uint64_t n) { n %= W; return n ? (T)(((uint64_t)a << n) | ((uint64_t)a >> (W-n))) : a; }
ROTATE(8,uint8_t)
ROTATE(16,uint16_t)
ROTATE(32,uint32_t)
ROTATE(64,uint64_t)
'''


def main(directory):
    root = pathlib.Path(directory)
    assembly = root / 'assembly.o'
    typed = root / 'typed.o'
    native_path = root / 'native.so'
    run([CC, '-c', '-fPIC', str(SUPPORT / 'x64_pipeline.S'), '-o', str(assembly)])
    run([CC, '-O2', '-g', '-c', '-fPIC', str(SUPPORT / 'x64_pipeline_types.c'), '-o', str(typed)])
    run([CC, '-shared', str(assembly), str(typed), '-o', str(native_path)])
    native = ctypes.CDLL(str(native_path))
    bmi = native.cpu_bmi()
    cases = []

    def add(name, a=0, b=0, c=0):
        if name.startswith('andn') and not bmi & 1:
            return
        if name.startswith('mulx') and not bmi & 2:
            return
        cases.append((name, a & MASK, b & MASK, c & MASK))

    values = [0, 1, 2, 3, 7, 0x80, 0x8000, 0x80000000,
              0x7fffffffffffffff, 1 << 63, MASK]
    rng = random.Random(0xE8BE)
    values += [rng.getrandbits(64) for _ in range(8)]
    for a in values:
        for b in [0, 1, 2, 7, MASK]:
            for name in ['xchg_pair', 'mul_high', 'mul_signed_high', 'mul_square_high',
                         'mulx_high', 'mulx_low', 'mulx_alias', 'mulx32_high',
                         'andn_zf', 'andn_cf', 'andn_sf', 'andn_of']:
                add(name, a, b)
        for name in ['logical_from_signed', 'arithmetic_from_unsigned',
                     'logical32_from_signed', 'arithmetic32_from_unsigned']:
            add(name, a)
        for bits in [8, 16, 32, 64]:
            for count in [0, 1, bits - 1, bits, 32, 64, 65, 255]:
                for op in ['rol', 'ror']:
                    add(f'{op}{bits}_c', a, 0, count)
                    if count & (63 if bits == 64 else 31) in [0, 1]:
                        add(f'{op}{bits}_o', a, 0, count)
                for op in ['shl', 'shr', 'sar']:
                    add(f'{op}{bits}_pf', a, 0, count)
                    add(f'{op}{bits}_sahf_pf', a, 0, count)
        for count in [0, 1, 31, 32, 63, 64, 65, 128, 255]:
            for op in ['shld', 'shrd']:
                add(op + '_zero', a, 0x813579BDF2468ACE, count)
                add(op + '32_zero', a, 0xF2468ACE, count)
                for flag in ['c', 'z', 's', 'p']:
                    add(op + '_' + flag, a, 0x813579BDF2468ACE, count)
                if count & 63 in [0, 1]:
                    add(op + '_o', a, 0x813579BDF2468ACE, count)
    add('shift_pf')
    add('ror_zero_cf')
    add('xchg_address', 16)
    names = sorted({case[0] for case in cases})

    code = HELPERS
    for name in names:
        # The address-alias probe checks native memory against IR. Its
        # inferred void-pointer signature is outside the emitter probes.
        if name == 'xchg_address':
            continue
        output = run([EMBER, '--no-cache', '-p', '-s', name, str(native_path)])
        (root / (name + '.pseudo.c')).write_text(output)
        # Intrinsics have explicit semantics here; only their invalid C names
        # are adapted. Never rewrite arithmetic or casts in generated output.
        for old, new in [('mulh.u.64', 'helper_high'), ('mulh.s.64', 'helper_signed_high'),
                         ('mulx.high32', 'helper_high32'), ('mulx.low32', 'helper_low32'),
                         ('mulx.high', 'helper_high'), ('mulx.low', 'helper_low')]:
            output = output.replace(old, new)
        code += output + '\n'
    generated = root / 'generated.c'
    generated.write_text(code)
    libraries = []
    for opt in ['0', '2']:
        path = root / ('generated_O' + opt + '.so')
        run([CC, '-O' + opt, '-shared', '-fPIC', str(generated), '-o', str(path)])
        libraries.append(ctypes.CDLL(str(path)))

    probe_input = ''.join(f'{n} {a} {b} {c}\n' for n, a, b, c in cases)
    result = run([PROBE, str(native_path)], input=probe_input).splitlines()
    if len(result) != len(cases):
        raise AssertionError('IR probe returned the wrong number of cases')

    failures = []
    for (name, a, b, c), ir in zip(cases, result):
        label, before, after, memory = ir.split()
        assert label == name
        width = 32 if name in ['logical32_from_signed', 'arithmetic32_from_unsigned'] else 64
        # Flag fixtures return a byte; emitted C may use uint8_t rather than
        # the original zero-extending assembly's 64-bit ABI return container.
        if re.search(r'_(?:c|o|z|s|p|pf|sahf_pf|cf|sf|of|zf)$', name):
            width = 8
        mask = (1 << width) - 1
        observed = []
        stored = []
        for lib in [native] + ([] if name == 'xchg_address' else libraries):
            fn = getattr(lib, name)
            fn.argtypes = [ctypes.c_uint64] * 4
            fn.restype = ctypes.c_uint8 if width == 8 else ctypes.c_uint64
            if name == 'xchg_address':
                cell = ctypes.c_uint64(3)
                ptr = ctypes.addressof(cell)
                observed.append(fn(ptr, b, c, 0) & mask)
                stored.append(16 if cell.value == ptr else cell.value)
            else:
                observed.append(fn(a, b, c, 0) & mask)
        expected = observed[0]
        if any(v != expected for v in observed[1:] + [int(before) & mask, int(after) & mask]):
            failures.append(f'{name}({a:#x},{b:#x},{c}): native/C0/C2={observed}, IR={before}/{after}')
        if name == 'xchg_address' and stored + [int(memory)] != [16] * 2:
            failures.append(f'{name}: memory={stored}, IR memory={memory}')
    if failures:
        raise AssertionError('\n'.join(failures[:25]) + f'\n{len(failures)} failing cases; artifacts: {root}')

    # Execute emitted C in a separate process with UBSan; a zero-count
    # double shift must never evaluate a width-sized shift, even at -O0.
    runner = root / 'ubsan.c'
    runner.write_text('#include "generated.c"\nint main(void) { return '
                      'shrd_zero(1,2,0) != 1 || shld_zero(1,2,64) != 1; }\n')
    exe = root / 'ubsan'
    run([CC, '-O0', '-fsanitize=undefined', '-fno-sanitize-recover=undefined',
         str(runner), '-o', str(exe)])
    run([str(exe)])
    print(f'OK: {len(cases)} cases across {len(names)} functions; native, SSA, cleaned SSA; '
          f'C -O0/-O2 for {len(names) - 1} functions; UBSan zero-count shifts. BMI mask={bmi}')


if __name__ == '__main__':
    # Retain failures for inspection; remove successful run artifacts.
    directory = tempfile.mkdtemp(prefix='ember-x64-pipeline-')
    try:
        main(directory)
    except subprocess.CalledProcessError as error:
        print(error.stdout, error.stderr, f'Artifacts: {directory}', file=sys.stderr)
        raise
    else:
        import shutil
        shutil.rmtree(directory)
