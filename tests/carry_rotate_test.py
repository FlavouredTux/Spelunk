"""Compare rotate-through-carry results and carry flags with native x86."""
import ctypes
from pathlib import Path
import random
import subprocess
import sys
import tempfile


def run(args):
    result = subprocess.run(list(map(str, args)), capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError(f'{result.args}\n{result.stderr}')
    return result.stdout


def main():
    spelunk, cc = sys.argv[1:]
    with tempfile.TemporaryDirectory(prefix='spelunk-carry-') as tmp:
        root = Path(tmp)
        functions = []
        assembly = ['.text']
        for width, register in [(8, 'al'), (16, 'ax'), (32, 'eax'), (64, 'rax')]:
            for direction in ('rcl', 'rcr'):
                name = f'check_{direction}_{width}'
                functions.append(name)
                assembly += [f'.globl {name}', f'.type {name}, @function', f'{name}:',
                             'mov %rsi, %rax', 'mov %rcx, %r8', 'mov %edx, %ecx',
                             'bt $0, %r8', f'{direction} %cl, %{register}', 'setc %dl',
                             'mov %rax, (%rdi)', 'movzbl %dl, %edx', 'mov %rdx, 8(%rdi)',
                             'ret', f'.size {name}, .-{name}']
        assembly += ['.section .note.GNU-stack,"",@progbits']
        source = root / 'native.S'
        source.write_text('\n'.join(assembly))
        native = root / 'native.so'
        run([cc, '-shared', '-fPIC', source, '-o', native])
        addresses = {line.split()[2]: line.split()[0] for line in run(['nm', '-D', '--defined-only', native]).splitlines()}
        annotations = root / 'signatures.ann'
        annotations.write_text(''.join(f'sig {addresses[name]} void|void*|out|uint64_t|value|uint64_t|count|uint64_t|carry\n'
                                       for name in functions))
        exported = root / 'exported.c'
        exported.write_text('\n'.join(run([spelunk, '--no-cache', '--emit-c', '--annotations', annotations,
                                          '-s', name, native]) for name in functions))
        libraries = [ctypes.CDLL(str(native))]
        for opt in ('0', '2'):
            target = root / f'exported-{opt}.so'
            run([cc, '-std=c11', '-Werror', '-shared', '-fPIC', '-O' + opt, exported, '-o', target])
            libraries.append(ctypes.CDLL(str(target)))
        rng = random.Random(20260919)
        values = [0, 1, 127, 128, 255, 65535, 1 << 31, 1 << 63, (1 << 64) - 1]
        values += [rng.getrandbits(64) for _ in range(50)]
        for name in functions:
            for value in values:
                for count in (0, 1, 2, 8, 9, 16, 17, 31, 32, 33, 63, 64, 65, 255):
                    for carry in (0, 1):
                        results = []
                        for library in libraries:
                            fn = getattr(library, name)
                            fn.argtypes = [ctypes.c_void_p] + [ctypes.c_uint64] * 3
                            fn.restype = None
                            output = (ctypes.c_uint64 * 2)()
                            fn(output, value, count, carry)
                            results.append(tuple(output))
                        if results[0] != results[1] or results[0] != results[2]:
                            raise AssertionError((name, value, count, carry, results))
        print('Carry rotates and CF match native x86 at all four operand widths')


if __name__ == '__main__':
    main()
