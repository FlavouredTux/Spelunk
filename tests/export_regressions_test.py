"""Execute exported SIMD copies and wide division against native machine code."""
import ctypes
import math
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
        fixtures = Path(__file__).parent / 'fixtures'
        # Scalar SSE functions must agree with their native source, including
        # NaNs and signed zeros where fmin/fmax differ from x86 min/max.
        scalar_names = ['max_d', 'clamp_f']
        scalar_text = '\n'.join(run([spelunk, '--no-cache', '--emit-c', '-s', name,
                                     fixtures / 'fp_scalar.prebuilt']) for name in scalar_names)
        scalar_source = folder / 'scalar.c'
        scalar_source.write_text(scalar_text)
        native_scalar = folder / 'native-scalar.so'
        run([compiler, '-O2', '-shared', '-fPIC', fixtures / 'fp_scalar.c', '-lm', '-o', native_scalar])
        scalar_libs = [ctypes.CDLL(str(native_scalar))]
        for opt in ['0', '2']:
            target = folder / f'scalar-O{opt}.so'
            run([compiler, '-std=c11', '-Werror', '-O' + opt, '-shared', '-fPIC', scalar_source, '-o', target])
            scalar_libs.append(ctypes.CDLL(str(target)))
        for lib in scalar_libs:
            lib.max_d.argtypes = [ctypes.c_double] * 2
            lib.max_d.restype = ctypes.c_double
            lib.clamp_f.argtypes = [ctypes.c_float] * 3
            lib.clamp_f.restype = ctypes.c_float
        values = [-math.inf, -100.5, -0.0, 0.0, 1.25, 100.5, math.inf, math.nan]
        def same_float(got, expected):
            return (math.isnan(got) and math.isnan(expected)) or (
                got == expected and (got != 0 or math.copysign(1, got) == math.copysign(1, expected)))
        for a in values:
            for b in values:
                expected = scalar_libs[0].max_d(a, b)
                for lib in scalar_libs[1:]:
                    assert same_float(lib.max_d(a, b), expected), ('max_d', a, b)
                for c in values:
                    expected = scalar_libs[0].clamp_f(a, b, c)
                    for lib in scalar_libs[1:]:
                        assert same_float(lib.clamp_f(a, b, c), expected), ('clamp_f', a, b, c)
        clear_source = folder / 'clear.c'
        clear_source.write_text(run([spelunk, '--no-cache', '--emit-c', '-s', 'sse_memclr',
                                     fixtures / 'decoder_misc.prebuilt']) + '\nuint8_t big_dst[4096];\n')
        clear_lib = folder / 'clear.so'
        run([compiler, '-std=c11', '-Werror', '-O2', '-shared', '-fPIC', clear_source, '-o', clear_lib])
        clear = ctypes.CDLL(str(clear_lib))
        data = (ctypes.c_ubyte * 4096).in_dll(clear, 'big_dst')
        for i in range(4096):
            data[i] = 0xa5
        clear.sse_memclr()
        assert bytes(data) == bytes(4096)
        printf_source = folder / 'printf.c'
        printf_source.write_text(run([spelunk, '--no-cache', '--emit-c',
                                      fixtures / 'printf_noise.prebuilt']) + '\nuint8_t g_count[4];\n')
        printf_binary = folder / 'printf'
        run([compiler, '-std=c11', '-Werror', '-O2', printf_source, '-o', printf_binary])
        for argv in [['fixture'], ['fixture', 'hello'], ['fixture', 'hello', 'world']]:
            expected = subprocess.run(argv, executable=str(fixtures / 'printf_noise.prebuilt'), capture_output=True)
            actual = subprocess.run(argv, executable=str(printf_binary), capture_output=True)
            assert (actual.returncode, actual.stdout, actual.stderr) == (expected.returncode, expected.stdout, expected.stderr)
        binary = folder / 'native.so'
        run([compiler, '-shared', '-fPIC', source, '-o', binary])
        names = ['export_copy', 'export_quotient', 'export_remainder', 'export_choose', 'export_choose_call']
        annotations = folder / 'signatures.anns'
        addresses = {}
        for line in run(['nm', '-D', '--defined-only', binary]).splitlines():
            address, _, name = line.split()
            addresses[name] = int(address, 16)
        for name, reason in [('export_x87_copy', 'unresolved intrinsic'),
                             ('export_undecoded', 'undecoded control-flow target')]:
            result = subprocess.run([spelunk, '--no-cache', '--emit-c', '-s', name, str(binary)],
                                    capture_output=True, text=True, timeout=30)
            assert result.returncode == 1 and not result.stdout, (name, result)
            assert 'is incomplete:' in result.stderr and reason in result.stderr, (name, result.stderr)
        pseudo = run([spelunk, '--no-cache', '-p', '-s', 'export_x87_copy', binary])
        assert 'x64.fld' in pseudo and 'x64.fstp' in pseudo, pseudo
        printf_plt = int(re.search(r'([0-9a-f]+) <vprintf@plt>:',
                                  run(['objdump', '-d', binary]))[1], 16)
        va_annotations = folder / 'va.anns'
        va_annotations.write_text(
            f'sig {addresses["export_vprintf"]:#x} int|void*|ap\n'
            f'sig {printf_plt:#x} int|const char*|format|void*|ap\n')
        va_export = folder / 'va-export.c'
        va_export.write_text(run([spelunk, '--no-cache', '--emit-c', '--annotations',
                                  va_annotations, '-s', 'export_vprintf', binary]))
        va_driver = folder / 'va-driver.c'
        va_driver.write_text('''#include <stdarg.h>
extern int export_vprintf(void *);
static int invoke(int unused, ...) {
    va_list ap;
    va_start(ap, unused);
    int result = export_vprintf(ap);
    va_end(ap);
    return result;
}
int main(void) { return invoke(0, 42) == 3 ? 0 : 1; }
''')
        for opt in ['0', '2']:
            va_binary = folder / f'va-O{opt}'
            run([compiler, '-std=c11', '-Werror', '-O' + opt, va_export, va_driver, '-o', va_binary])
            assert run([va_binary]) == '42\n'
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
