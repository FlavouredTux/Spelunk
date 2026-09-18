"""Compare CMPSS exports with native masks, upper lanes, and scalar memory reads."""
import ctypes
from pathlib import Path
import random
import struct
import subprocess
import sys
import tempfile


def run(args):
    result = subprocess.run(list(map(str, args)), capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, (args, result.stdout, result.stderr)
    return result.stdout


def main():
    spelunk, compiler = sys.argv[1:]
    with tempfile.TemporaryDirectory(prefix='spelunk-cmpss-') as temp:
        folder = Path(temp)
        fixtures = Path(__file__).parent / 'fixtures'
        main_source = folder / 'fp-main.c'
        main_source.write_text(run([spelunk, '--no-cache', '--emit-c', fixtures / 'fp_scalar.prebuilt']))
        for opt in ['0', '2']:
            main_binary = folder / f'fp-main-O{opt}'
            run([compiler, '-std=c11', '-Werror', '-O' + opt, main_source, '-lm', '-o', main_binary])
            for argc in [1, 2, 9, 10, 11, 32, 100]:
                argv = ['fixture'] + ['arg'] * (argc - 1)
                expected = subprocess.run(argv, executable=str(fixtures / 'fp_scalar.prebuilt'),
                                          capture_output=True, timeout=10)
                actual = subprocess.run(argv, executable=str(main_binary), capture_output=True, timeout=10)
                assert (actual.returncode, actual.stdout, actual.stderr) == (
                    expected.returncode, expected.stdout, expected.stderr), ('fp_scalar main', opt, argc)
        assembly = ['.text']
        names = []
        for predicate in range(8):
            for mode in ['register', 'memory', 'add', 'move', 'load']:
                name = f'compare_{predicate}_{mode}'
                names.append(name)
                before = {'add': 'addss %xmm1, %xmm0',
                          'move': 'movss %xmm1, %xmm0',
                          'load': 'movss (%rsi), %xmm0'}.get(mode, '')
                assembly.extend([
                    f'.globl {name}', f'.type {name}, @function', f'{name}:',
                    'movdqu (%rsi), %xmm0',
                    '' if mode == 'memory' else 'movdqu (%rdx), %xmm1', before,
                    f'cmpss ${predicate}, ' + ('(%rdx)' if mode == 'memory' else '%xmm1') + ', %xmm0',
                    'movdqu %xmm0, (%rdi)', 'ret', f'.size {name}, .-{name}',
                ])
        assembly.append('.section .note.GNU-stack,"",@progbits')
        source = folder / 'compare.S'
        source.write_text('\n'.join(assembly) + '\n')
        native = folder / 'native.so'
        run([compiler, '-shared', '-fPIC', source, '-o', native])
        addresses = {line.split()[2]: int(line.split()[0], 16)
                     for line in run(['nm', '-D', '--defined-only', native]).splitlines()}
        annotations = folder / 'compare.anns'
        annotations.write_text(''.join(
            f'sig {addresses[name]:#x} void|void*|dst|const void*|left|const void*|right\n'
            for name in names))
        exported = folder / 'exported.c'
        exported.write_text('\n'.join(run([
            spelunk, '--no-cache', '--emit-c', '--annotations', annotations, '-s', name, native])
            for name in names))
        libs = [ctypes.CDLL(str(native))]
        for opt in ['0', '2']:
            target = folder / f'exported-O{opt}.so'
            run([compiler, '-std=c11', '-Werror', '-O' + opt, '-shared', '-fPIC',
                 exported, '-o', target])
            libs.append(ctypes.CDLL(str(target)))
        # Include infinities, signed zero, quiet/signaling NaNs, and subnormals.
        bits = [0, 0x80000000, 0x3f800000, 0xbf800000, 0x7f800000,
                0xff800000, 0x7fc12345, 0x7f812345, 1, 0x80000001]
        rng = random.Random(20260918)
        pairs = [(a, b) for a in bits for b in bits]
        pairs += [(rng.getrandbits(32), rng.getrandbits(32)) for _ in range(100)]
        for name in names:
            functions = [getattr(lib, name) for lib in libs]
            for fn in functions:
                fn.argtypes = [ctypes.c_void_p] * 3
                fn.restype = None
            for a, b in pairs:
                left = struct.pack('<I', a) + rng.randbytes(12)
                right = struct.pack('<I', b) + rng.randbytes(12)
                left_buf = ctypes.create_string_buffer(left)
                right_buf = ctypes.create_string_buffer(right)
                outputs = []
                for fn in functions:
                    dest = ctypes.create_string_buffer(b'\xa5' * 32)
                    fn(ctypes.byref(dest, 3), left_buf, right_buf)
                    outputs.append(dest.raw)
                assert outputs[0] == outputs[1] == outputs[2], (name, hex(a), hex(b), outputs)
                upper = bytes(12) if name.endswith('_load') else left[4:]
                assert outputs[0][7:19] == upper, (name, 'incorrect upper lanes')
                assert outputs[0][:3] == b'\xa5' * 3 and outputs[0][19:32] == b'\xa5' * 13
                assert left_buf.raw[:16] == left and right_buf.raw[:16] == right
        print('All eight CMPSS predicates match native masks and upper lanes at -O0/-O2')


if __name__ == '__main__':
    main()
