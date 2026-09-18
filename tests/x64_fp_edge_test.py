"""Execute floating arithmetic, flag consumers, and conversions against x86."""
import ctypes
import math
from pathlib import Path
import random
import struct
import subprocess
import sys
import tempfile


def run(args):
    result = subprocess.run(list(map(str, args)), capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, (args, result.stdout, result.stderr)
    return result.stdout


def main():
    spelunk, compiler = sys.argv[1:]
    # Retain failing generated C, assembly and executable inputs for diagnosis.
    folder = Path(tempfile.mkdtemp(prefix='spelunk-fp-edges-'))
    print(f'Floating-point edge fixtures: {folder}', flush=True)
    assembly, signatures, compares, conversions = ['.text'], {}, [], []
    arithmetic, int_conversions = [], []

    def function(name, body, signature):
        assembly.extend([f'.globl {name}', f'.type {name}, @function', f'{name}:',
                         *body, f'.size {name}, .-{name}'])
        signatures[name] = signature

    conditions = ['b', 'ae', 'e', 'ne', 'be', 'a', 'p', 'np',
                  's', 'ns', 'o', 'no', 'l', 'ge', 'le', 'g']
    for suffix, ctype, pytype in [('ss', 'float', ctypes.c_float),
                                ('sd', 'double', ctypes.c_double)]:
        for operation in ['sub_self', 'div_self', 'add_zero', 'mul_zero']:
            name = f'arithmetic_{suffix}_{operation}'
            op, operand = operation.split('_')
            body = [] if operand == 'self' else ['pxor %xmm1, %xmm1']
            source = '%xmm0' if operand == 'self' else '%xmm1'
            function(name, body + [f'{op}{suffix} {source}, %xmm0', 'ret'], f'{ctype}|{ctype}|x')
            arithmetic.append((name, pytype))
        for memory in [False, True]:
            for width in [32, 64]:
                name = f'from_integer_{suffix}_{int(memory)}_{width}'
                source = '(%rdi)' if memory else ('%edi' if width == 32 else '%rdi')
                # Unsigned annotations cannot change the instruction's signed
                # interpretation. Register cases also exercise ignored high bits.
                arg = f'const uint{width}_t*' if memory else 'uint64_t'
                function(name, [f'cvtsi2{suffix} {source}, %xmm0', 'ret'], f'{ctype}|{arg}|x')
                int_conversions.append((name, pytype, memory, width))
        for ordered in [False, True]:
            mnemonic = ('comi' if ordered else 'ucomi') + suffix
            for condition in conditions:
                for mode in ['set', 'cmov', 'branch']:
                    name = f'{mnemonic}_{mode}_{condition}'
                    # Seed SF/OF before the comparison to catch missing clears.
                    body = ['mov $0x7fffffff, %eax', 'add $1, %eax',
                            f'{mnemonic} %xmm1, %xmm0']
                    if mode == 'set':
                        body += [f'set{condition} %al', 'movzbl %al, %eax', 'ret']
                    elif mode == 'cmov':
                        body += ['mov $0, %eax', 'mov $1, %edx', f'cmov{condition} %edx, %eax', 'ret']
                    else:
                        body += [f'j{condition} .L{name}', 'mov $0, %eax', 'ret',
                                 f'.L{name}:', 'mov $1, %eax', 'ret']
                    function(name, body, f'int|{ctype}|a|{ctype}|b')
                    compares.append((name, pytype, condition))
            # The flags describe the old operands even after an XMM write.
            name = f'{mnemonic}_saved_parity'
            function(name, [f'{mnemonic} %xmm1, %xmm0', 'pxor %xmm0, %xmm0',
                            'pxor %xmm1, %xmm1', 'setp %al', 'movzbl %al, %eax', 'ret'],
                     f'int|{ctype}|a|{ctype}|b')
            compares.append((name, pytype, 'p'))
        for memory in [False, True]:
            for width in [32, 64, '32z']:
                name = f'convert_{suffix}_{int(memory)}_{width}'
                source = '(%rdi)' if memory else '%xmm0'
                dest = '%rax' if width == 64 else '%eax'
                ret = 'uint64_t' if width == '32z' else f'int{width}_t'
                arg = f'const {ctype}*' if memory else ctype
                function(name, [f'cvtt{suffix}2si {source}, {dest}', 'ret'], f'{ret}|{arg}|x')
                conversions.append((name, suffix, pytype, memory, width))
    assembly.append('.section .note.GNU-stack,"",@progbits')
    (folder / 'native.S').write_text('\n'.join(assembly) + '\n')
    native = folder / 'native.so'
    run([compiler, '-shared', '-fPIC', folder / 'native.S', '-o', native])
    addresses = {line.split()[2]: int(line.split()[0], 16)
                 for line in run(['nm', '-D', '--defined-only', native]).splitlines()}
    annotations = folder / 'signatures.anns'
    annotations.write_text(''.join(f'sig {addresses[name]:#x} {sig}\n'
                                   for name, sig in signatures.items()))
    exported = folder / 'exported.c'
    exported.write_text('\n'.join(run([spelunk, '--no-cache', '--emit-c', '--annotations',
                                       annotations, '-s', name, native]) for name in signatures))
    libs = [ctypes.CDLL(str(native))]
    for opt in ['0', '2']:
        target = folder / f'exported-O{opt}.so'
        run([compiler, '-std=c11', '-Werror', '-O' + opt, '-shared', '-fPIC', exported, '-o', target])
        libs.append(ctypes.CDLL(str(target)))

    values = [-math.inf, -100.5, -1.0, -0.0, 0.0, 1.0, 100.5, math.inf, math.nan]
    def same_float(a, b, pytype):
        if math.isnan(a) and math.isnan(b):
            return True
        fmt = '<f' if pytype == ctypes.c_float else '<d'
        return struct.pack(fmt, a) == struct.pack(fmt, b)

    for name, pytype in arithmetic:
        functions = [getattr(lib, name) for lib in libs]
        for fn in functions:
            fn.argtypes, fn.restype = [pytype], pytype
        for x in values + [2.0, 1e-30, -1e-30, 1e30, -1e30]:
            results = [fn(x) for fn in functions]
            assert all(same_float(results[0], value, pytype) for value in results[1:]), (name, x, results)
        if name.endswith('div_self'):
            assert all(fn(2.0) == 1.0 for fn in functions), name

    integer_rng = random.Random(20260919)
    for name, pytype, memory, width in int_conversions:
        functions = [getattr(lib, name) for lib in libs]
        storage = ctypes.c_uint32 if width == 32 else ctypes.c_uint64
        for fn in functions:
            fn.argtypes = [ctypes.POINTER(storage) if memory else ctypes.c_uint64]
            fn.restype = pytype
        inputs = [0, 1, -1, -2, -(1 << (width - 1)), (1 << (width - 1)) - 1,
                  (1 << (width - 1)), (1 << width) - 1]
        inputs += [integer_rng.getrandbits(64) for _ in range(200)]
        for x in inputs:
            value = storage(x)
            arg = ctypes.byref(value) if memory else x
            results = [fn(arg) for fn in functions]
            assert all(same_float(results[0], result, pytype) for result in results[1:]), (name, x, results)
            if x == -1:
                assert results == [-1.0] * len(functions), (name, results)

    for name, pytype, condition in compares:
        functions = [getattr(lib, name) for lib in libs]
        for fn in functions:
            fn.argtypes, fn.restype = [pytype, pytype], ctypes.c_int
        for a in values:
            for b in values:
                unordered = math.isnan(a) or math.isnan(b)
                cf, zf = unordered or a < b, unordered or a == b
                expected = dict(b=cf, ae=not cf, e=zf, ne=not zf, be=cf or zf,
                                a=not cf and not zf, p=unordered, np=not unordered,
                                s=False, ns=True, o=False, no=True, l=False, ge=True,
                                le=zf, g=not zf)[condition]
                results = [fn(a, b) for fn in functions]
                assert all(value == expected for value in results), (name, a, b, expected, results)

    rng = random.Random(20260918)
    patterns = {}
    for suffix, bits, fmt in [('ss', 32, 'f'), ('sd', 64, 'd')]:
        pack = lambda x: int.from_bytes(struct.pack('<' + fmt, x), 'little')
        seeds = values + [-3e9, 3e9, -1.75, 1.75, -2147483648.75, 2147483647.75]
        data = {pack(x) for x in seeds}
        for boundary in [2**31, 2**63]:
            for sign in [-1, 1]:
                center = pack(float(sign * boundary))
                data.update(center + offset for offset in range(-3, 4))
        data.update([1, (1 << (bits - 1)) | 1])  # signed subnormals
        data.update([0x7fc12345, 0x7f812345, 0xffc12345] if bits == 32 else
                    [0x7ff8123456789abc, 0x7ff0123456789abc, 0xfff8123456789abc])
        data.update(rng.getrandbits(bits) for _ in range(200))
        patterns[suffix] = sorted(data)

    sanitizer = ['#include <fenv.h>']
    for suffix, raw in patterns.items():
        bits = 32 if suffix == 'ss' else 64
        sanitizer.append(f'static const uint{bits}_t bits_{suffix}[] = {{' +
                         ','.join(hex(x) for x in raw) + '};')
    checks = []
    for name, suffix, pytype, memory, width in conversions:
        functions = [getattr(lib, name) for lib in libs]
        restype = ctypes.c_uint64 if width == '32z' else (
            ctypes.c_int64 if width == 64 else ctypes.c_int32)
        for fn in functions:
            fn.argtypes = [ctypes.POINTER(pytype) if memory else pytype]
            fn.restype = restype
        expected_bits = []
        for bits in patterns[suffix]:
            size = 4 if suffix == 'ss' else 8
            scalar = pytype.from_buffer_copy(bits.to_bytes(size, 'little'))
            x = scalar.value
            nbits = 64 if width == 64 else 32
            minimum = -(1 << (nbits - 1))
            truncated = int(x) if math.isfinite(x) else minimum
            expected = truncated if minimum <= truncated < -minimum else minimum
            if width == '32z':
                expected &= 0xffffffff
            results = [fn(ctypes.byref(scalar) if memory else scalar) for fn in functions]
            assert results == [expected] * len(functions), (name, hex(bits), x, expected, results)
            expected_bits.append(expected & 0xffffffffffffffff)
        sanitizer.append(f'static const uint64_t expected_{name}[] = {{' +
                         ','.join(f'UINT64_C({x})' for x in expected_bits) + '};')
        ctype = 'float' if suffix == 'ss' else 'double'
        argument = '&x' if memory else 'x'
        checks.append(f'''for (size_t i = 0; i < {len(expected_bits)}; ++i) {{
            {ctype} x; memcpy(&x, &bits_{suffix}[i], sizeof(x));
            if ((uint64_t){name}({argument}) != expected_{name}[i]) abort();
        }}''')
    sanitizer.append('int main(void) {\nconst int modes[] = {FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO};\n'
                     'for (size_t mode = 0; mode < 4; ++mode) { if (fesetround(modes[mode])) return 1;\n' +
                     '\n'.join(checks) + '\n} return 0; }\n')
    checked = folder / 'checked.c'
    checked.write_text(exported.read_text() + '\n' + '\n'.join(sanitizer))
    target = folder / 'checked'
    run([compiler, '-std=c11', '-Werror', '-O1', '-fsanitize=undefined,float-cast-overflow',
         '-fno-sanitize-recover=all', checked, '-lm', '-o', target])
    run([target])
    print('Floating arithmetic, flags and 32/64-bit conversions match native execution; UBSan checks pass')


if __name__ == '__main__':
    main()
