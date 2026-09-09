"""Compare native fixtures, pre/post-cleanup integer SSA, and emitted C."""
import ctypes
from dataclasses import dataclass
import pathlib
import random
import re
import subprocess
import sys
import tempfile

EMBER, PROBE, CC, SUPPORT = sys.argv[1:]
SUPPORT = pathlib.Path(SUPPORT)
MASK = (1 << 64) - 1


@dataclass(frozen=True)
class Case:
    name: str
    args: tuple[int, int, int]
    memory: bytes = bytes(128)
    pointer_args: tuple[int, ...] = ()
    pointer_slots: tuple[int, ...] = ()


def execute(lib, case, width, counter):
    # uint64_t storage supplies alignment; every backend gets a fresh copy.
    storage = (ctypes.c_uint64 * (len(case.memory) // 8)).from_buffer_copy(case.memory)
    base = ctypes.addressof(storage)
    args = list(case.args)
    for index in case.pointer_args:
        args[index] += base
    fn = getattr(lib, case.name)
    fn.argtypes = [ctypes.c_uint64] * 4
    fn.restype = ctypes.c_uint8 if width == 8 else ctypes.c_uint64
    counter.pipeline_reset_calls()
    result = fn(*args, 0) & ((1 << width) - 1)
    memory = bytearray(storage)
    # Normalize only slots explicitly known to contain pointers. Integer
    # bytes are never heuristically rewritten to make two executions agree.
    for offset in case.pointer_slots:
        value = int.from_bytes(memory[offset:offset + 8], 'little')
        if base <= value < base + len(memory):
            memory[offset:offset + 8] = (value - base).to_bytes(8, 'little')
    return result, bytes(memory), counter.pipeline_get_calls()


def run(args, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True, **kwargs).stdout


HELPERS = r'''
#include <stdint.h>
#include <stdbool.h>
extern uint64_t call_step(uint64_t, uint64_t);
extern uint64_t call_mutate(uint64_t*, uint64_t);
extern uint64_t call_clobber(uint64_t);
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
    calls = root / 'calls.o'
    native_path = root / 'native.so'
    run([CC, '-c', '-fPIC', str(SUPPORT / 'x64_pipeline.S'), '-o', str(assembly)])
    run([CC, '-O2', '-g', '-c', '-fPIC', str(SUPPORT / 'x64_pipeline_types.c'), '-o', str(typed)])
    run([CC, '-O2', '-g', '-c', '-fPIC', str(SUPPORT / 'x64_pipeline_calls.c'), '-o', str(calls)])
    run([CC, '-shared', '-Wl,-Bsymbolic-functions', str(assembly), str(typed), str(calls), '-o', str(native_path)])
    native = ctypes.CDLL(str(native_path))
    native.pipeline_get_calls.restype = ctypes.c_uint64
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
    for x in values:
        for y in [0, 1, 7, MASK]:
            add('branch_early', x, y)
            for choose in [0, 1]:
                add('branch_diamond', x, y, choose)
                add('branch_phi', x, y, choose)
        for n in [0, 1, 2, 3, 8, 16]:
            add('loop_sum', n, x)
            add('loop_pair', n, x, 3)
            add('loop_call_result', n, x, 7)
            add('loop_call_preserve', n, x, 3)
            for stop in range(n + 2):
                add('loop_early', n, stop, x)
                add('loop_call_exit', n, stop, x)
    cases = [Case(name, (a, b, c)) for name, a, b, c in cases]
    for seed in range(8):
        initial = rng.randbytes(128)
        cases.append(Case('xchg_address', (16, 0, 0), initial, (0,), (16,)))
        for index in [0, 1, 3, 7]:
            cases.append(Case('void_index', (16, index, MASK), initial, (0,)))
        for q in [16, 24, 48]:
            for value in [0, 1, MASK, rng.getrandbits(64)]:
                cases.append(Case('alias_snapshot', (16, q, value), initial, (0, 1)))
            for choose in [0, 1]:
                cases.append(Case('branch_memory', (16, q, choose), initial, (0, 1)))
            for n in [0, 1, 2, 3, 4]:
                cases.append(Case('loop_alias', (16, q, n), initial, (0, 1)))
                cases.append(Case('loop_call_memory', (16, q, n), initial, (0, 1)))
        for q in [16, 17, 19, 23, 24, 48]:
            for value in [0, 0xff, 0x7f]:
                cases.append(Case('alias_byte', (16, q, value), initial, (0, 1)))
    names = sorted({case.name for case in cases})

    code = HELPERS
    for name in names:
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
        run([CC, '-O' + opt, '-shared', '-fPIC', str(generated), str(native_path), '-o', str(path)])
        libraries.append(ctypes.CDLL(str(path)))

    probe_input = ''.join(f'{case.name} {case.args[0]} {case.args[1]} {case.args[2]} {case.memory.hex()}\n' for case in cases)
    (root / 'probe-input.txt').write_text(probe_input)
    result = run([PROBE, str(native_path)], input=probe_input).splitlines()
    if len(result) != len(cases):
        raise AssertionError('IR probe returned the wrong number of cases')

    failures = []
    for case, ir in zip(cases, result):
        name = case.name
        a, b, c = case.args
        label, before, after, memory, call_count = ir.split()
        assert label == name
        width = 32 if name in ['logical32_from_signed', 'arithmetic32_from_unsigned'] else 64
        # Flag fixtures return a byte; emitted C may use uint8_t rather than
        # the original zero-extending assembly's 64-bit ABI return container.
        if re.search(r'_(?:c|o|z|s|p|pf|sahf_pf|cf|sf|of|zf)$', name):
            width = 8
        mask = (1 << width) - 1
        observed = [execute(lib, case, width, native) for lib in [native] + libraries]
        expected = observed[0]
        ir_result = (int(after) & mask, bytes.fromhex(memory), int(call_count))
        if any(value != expected for value in observed[1:] + [ir_result]) or (int(before) & mask) != expected[0]:
            failures.append(f'{name}({a:#x},{b:#x},{c}): native/C0/C2={[value[0] for value in observed]}, '
                            f'IR={before}/{after}; calls={[value[2] for value in observed]}/{call_count}; initial={case.memory.hex()} native={expected[1].hex()} '
                            f'C0={observed[1][1].hex()} C2={observed[2][1].hex()} IR={memory}')
    if failures:
        raise AssertionError('\n'.join(failures[:25]) + f'\n{len(failures)} failing cases; artifacts: {root}')

    # Execute emitted C separately with UBSan, including memory accesses,
    # loop exits, and zero counts that must never evaluate width-sized shifts.
    runner = root / 'ubsan.c'
    runner.write_text(r'''#include "generated.c"
int main(void) {
    uint64_t data[16] = {0};
    data[2] = 3;
    if (xchg_address(&data[2]) != 3 || data[2] != (uintptr_t)&data[2]) return 1;
    data[2] = 10;
    if (alias_snapshot(&data[2], &data[2], 7) != 17 || data[2] != 7) return 2;
    data[2] = 0x1234;
    if (alias_byte(&data[2], (unsigned char*)&data[2] + 1, 0xff) != (0x1234 ^ 0xff34)) return 3;
    if (void_index(&data[2], 1, 9) != 0 || data[3] != 9) return 4;
    data[2] = 10;
    if (loop_alias(&data[2], &data[3], 4) != 46 || data[6] != 14) return 5;
    if (loop_pair(0, 2, 3) != 1 || loop_pair(3, 2, 3) != (8 ^ 13)) return 6;
    if (loop_sum(0, 7) != 7 || loop_sum(4, 7) != 13) return 7;
    if (loop_early(4, 2, 7) != 8 || branch_phi(3, 7, 1) != (10 ^ 0x55)) return 8;
    return shrd_zero(1,2,0) != 1 || shld_zero(1,2,64) != 1;
}
''')
    exe = root / 'ubsan'
    run([CC, '-O0', '-fsanitize=undefined', '-fno-sanitize-recover=undefined',
         str(runner), str(native_path), '-o', str(exe)])
    run([str(exe)])
    print(f'OK: {len(cases)} cases across {len(names)} functions; native, SSA, cleaned SSA; '
          f'C -O0/-O2 and full memory comparison; UBSan shifts/control-flow/memory. BMI mask={bmi}')


if __name__ == '__main__':
    # Retain failures for inspection; remove successful run artifacts.
    directory = tempfile.mkdtemp(prefix='ember-x64-pipeline-')
    try:
        main(directory)
    except subprocess.CalledProcessError as error:
        pathlib.Path(directory, 'failed-command.stdout').write_text(error.stdout or '')
        pathlib.Path(directory, 'failed-command.stderr').write_text(error.stderr or '')
        print((error.stdout or '')[-1000:], (error.stderr or '')[-6000:], f'Artifacts: {directory}', file=sys.stderr)
        raise
    else:
        import shutil
        shutil.rmtree(directory)
