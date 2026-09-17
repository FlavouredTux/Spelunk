"""Execute exported SIMD copies and wide division against native machine code."""
import ctypes
from pathlib import Path
import random
import re
import subprocess
import sys
import tempfile


def run(args):
    return subprocess.run(list(map(str, args)), check=True, text=True,
                          capture_output=True, timeout=30).stdout


def main():
    spelunk, compiler = sys.argv[1:]
    source = Path(__file__).parent / 'support/export_regressions.S'
    with tempfile.TemporaryDirectory(prefix='spelunk-export-regressions-') as temp:
        folder = Path(temp)
        binary = folder / 'native.so'
        run([compiler, '-shared', '-fPIC', source, '-o', binary])
        names = ['export_copy', 'export_quotient', 'export_remainder', 'export_choose', 'export_choose_call']
        annotations = folder / 'signatures.anns'
        addresses = {}
        for line in run(['nm', '-D', '--defined-only', binary]).splitlines():
            address, _, name = line.split()
            addresses[name] = int(address, 16)
        annotations.write_text(
            f'sig {addresses["export_copy"]:#x} void|void*|dst|const void*|src\n' +
            ''.join(f'sig {addresses[name]:#x} uint64_t|uint64_t|hi|uint64_t|lo|uint64_t|divisor\n'
                    for name in names[1:3]) +
            f'sig {addresses["export_choose"]:#x} uint64_t|void*|record|uint64_t|indirect\n' +
            f'sig {addresses["export_choose_call"]:#x} uint64_t|void*|record|uint64_t|indirect|void*|callback\n')
        exported = folder / 'exported.c'
        exported.write_text('\n'.join(run([spelunk, '--no-cache', '--emit-c',
                                          '--annotations', annotations, '-s', name, binary])
                                      for name in names))
        text = exported.read_text()
        assert 'unresolved' not in text and '#error' not in text, text
        scratch = run([spelunk, '--no-cache', '--emit-c', '-s', 'export_scratch', binary])
        assert re.search(r'^void export_scratch\(', scratch, re.M), scratch
        assert 'xmm0_' not in scratch, scratch
        stale = run([spelunk, '--no-cache', '--emit-c', '-s', 'export_stale', binary])
        assert 'unresolved register read' not in stale and 'rcx_' not in stale, stale
        for name, body in [('scratch', scratch), ('stale', stale)]:
            checked = folder / (name + '.c')
            checked.write_text(body)
            run([compiler, '-std=c11', '-Werror', '-fsyntax-only', checked])
        libs = [ctypes.CDLL(str(binary))]
        for opt in ['0', '2']:
            target = folder / f'exported-O{opt}.so'
            run([compiler, '-std=c11', '-Werror', '-O' + opt, '-shared', '-fPIC',
                 exported, '-o', target])
            libs.append(ctypes.CDLL(str(target)))
        rng = random.Random(20260917)
        for lib in libs:
            lib.export_copy.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
            lib.export_copy.restype = None
            lib.export_choose.argtypes = [ctypes.c_void_p, ctypes.c_uint64]
            lib.export_choose.restype = ctypes.c_uint64
            lib.export_choose_call.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p]
            lib.export_choose_call.restype = ctypes.c_uint64
            for name in names[1:3]:
                fn = getattr(lib, name)
                fn.argtypes = [ctypes.c_uint64] * 3
                fn.restype = ctypes.c_uint64
        for _ in range(100):
            payload = rng.randbytes(48)
            offset = rng.randrange(1, 16)
            for lib in libs:
                src = (ctypes.c_ubyte * 48).from_buffer_copy(payload)
                dst = (ctypes.c_ubyte * 48)(*([0xa5] * 48))
                lib.export_copy(ctypes.byref(dst, offset), ctypes.byref(src, offset))
                expected = bytearray([0xa5] * 48)
                expected[offset:offset+16] = payload[offset:offset+16]
                assert bytes(dst) == expected
                assert bytes(src) == payload
            divisor = rng.randrange(1, 1 << 64)
            hi, lo = rng.randrange(divisor), rng.getrandbits(64)
            quotient, remainder = divmod((hi << 64) | lo, divisor)
            for lib in libs:
                assert lib.export_quotient(hi, lo, divisor) == quotient
                assert lib.export_remainder(hi, lo, divisor) == remainder
                external = ctypes.c_uint64(lo)
                record = (ctypes.c_uint64 * 2)(ctypes.addressof(external), hi)
                assert lib.export_choose(record, 0) == hi
                assert lib.export_choose(record, 1) == lo
                calls = []
                @ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_void_p, ctypes.c_uint64)
                def callback(ptr, length):
                    calls.append((ptr, length))
                    return ctypes.c_uint64.from_address(ptr).value ^ length
                record = (ctypes.c_uint64 * 3)(ctypes.addressof(external), 7, hi)
                assert lib.export_choose_call(record, 0, callback) == hi ^ 3
                assert lib.export_choose_call(record, 1, callback) == lo ^ 7
                assert calls == [(ctypes.addressof(record) + 16, 3), (ctypes.addressof(external), 7)]


if __name__ == '__main__':
    main()
