"""Compare SSE2 shuffle exports with native instructions and lane permutations."""
import ctypes
from pathlib import Path
import random
import subprocess
import sys
import tempfile


def run(args):
    result = subprocess.run(list(map(str, args)), text=True,
                            capture_output=True, timeout=30)
    if result.returncode:
        raise RuntimeError(f'{result.args}:\n{result.stderr}')
    return result.stdout


def permute(data, mnemonic, control):
    width = 4 if mnemonic == 'pshufd' else 2
    lanes = [data[i:i + width] for i in range(0, 16, width)]
    start = 4 if mnemonic == 'pshufhw' else 0
    result = lanes[:]
    for lane in range(4):
        result[start + lane] = lanes[start + ((control >> (2 * lane)) & 3)]
    return b''.join(result)


def main():
    spelunk, compiler = sys.argv[1:]
    with tempfile.TemporaryDirectory(prefix='spelunk-shuffles-') as temp:
        folder = Path(temp)
        assembly = ['.text']
        cases = []
        for mnemonic in ('pshufd', 'pshuflw', 'pshufhw'):
            for memory in (False, True):
                for control in (0, 1, 27, 85, 128, 196, 231, 255):
                    name = f'{mnemonic}_{int(memory)}_{control}'
                    cases.append((name, mnemonic, control))
                    assembly += [f'.globl {name}', f'.type {name}, @function',
                                 f'{name}:', 'pxor %xmm0, %xmm0']
                    if not memory:
                        assembly += ['movdqu (%rsi), %xmm1']
                    source = '(%rsi)' if memory else '%xmm1'
                    assembly += [f'{mnemonic} ${control}, {source}, %xmm0',
                                 'movdqu %xmm0, (%rdi)', 'ret',
                                 f'.size {name}, .-{name}']
        assembly.append('.section .note.GNU-stack,"",@progbits')
        native_source = folder / 'native.S'
        native_source.write_text('\n'.join(assembly) + '\n')
        native = folder / 'native.so'
        run([compiler, '-shared', '-fPIC', native_source, '-o', native])
        addresses = {line.split()[2]: line.split()[0]
                     for line in run(['nm', '-D', '--defined-only', native]).splitlines()}
        annotations = folder / 'signatures.ann'
        annotations.write_text(''.join(f'sig {addresses[name]} void|void*|dst|const void*|src\n'
                                       for name, _, _ in cases))
        names = folder / 'names.txt'
        names.write_text('\n'.join(name for name, _, _ in cases) + '\n')
        exported_source = folder / 'exported.c'
        exported_source.write_text(run([spelunk, '--no-cache', '--emit-c', '--annotations',
                                        annotations, '--symbols', names, native]))
        libraries = [ctypes.CDLL(str(native))]
        for optimization in ('0', '2'):
            exported = folder / f'exported-O{optimization}.so'
            run([compiler, '-std=c11', '-Werror', '-O' + optimization, '-shared', '-fPIC',
                 exported_source, '-o', exported])
            libraries.append(ctypes.CDLL(str(exported)))
        rng = random.Random(20260919)
        inputs = [bytes(range(16)), bytes(16), bytes([255] * 16)]
        inputs += [rng.randbytes(16) for _ in range(32)]
        for name, mnemonic, control in cases:
            for lib in libraries:
                function = getattr(lib, name)
                function.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
                function.restype = None
                for data in inputs:
                    source = ctypes.create_string_buffer(data)
                    destination = (ctypes.c_ubyte * 32)(*([0xa5] * 32))
                    function(ctypes.byref(destination, 3), source)
                    expected = bytes([0xa5] * 3) + permute(data, mnemonic, control) + bytes([0xa5] * 13)
                    if bytes(destination) != expected or source.raw != data + b'\0':
                        raise AssertionError((name, data.hex(), bytes(destination).hex(), expected.hex()))
        print(f'{len(cases)} shuffle functions match native instructions and lane permutations')


if __name__ == '__main__':
    main()
