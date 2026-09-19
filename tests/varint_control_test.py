"""Native/exported loop exits agree, including non-returning error paths."""
import ctypes
from pathlib import Path
import random
import subprocess
import sys
import tempfile

exe, cc = sys.argv[1:]
support = Path(__file__).parent / 'support'


def run(args):
    result = subprocess.run(list(map(str, args)), capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise AssertionError((args, result.stdout, result.stderr))
    return result.stdout


class Stream(ctypes.Structure):
    _fields_ = [('data', ctypes.c_void_p), ('left', ctypes.c_size_t)]


with tempfile.TemporaryDirectory(prefix='spelunk-varint-control-') as directory:
    root = Path(directory)
    cases = [b'', b'\0', b'\x7f', b'\x80\x01', b'\xff\x7f', b'\xac\x02',
             b'\x80', b'\xff' * 9 + b'\x01', b'\x80' * 10, b'\xff' * 10]
    rng = random.Random(20260919)
    cases += [bytes(rng.randrange(256) for _ in range(rng.randrange(14))) for _ in range(200)]
    for _ in range(200):
        value = rng.getrandbits(64)
        encoded = bytearray()
        while value >= 128:
            encoded.append((value & 127) | 128)
            value >>= 7
        encoded.append(value)
        cases.append(bytes(encoded))
    for opt in ('0', '2'):
        native = root / f'native{opt}.so'
        driver = support / 'varint_control_driver.c'
        # Keep an actual loop so the test exercises loop-exit reconstruction,
        # rather than Clang's completely unrolled ten-byte decoder.
        run([cc, '-O' + opt, '-fno-unroll-loops', '-g', '-shared', '-fPIC', '-Wl,-Bsymbolic',
             support / 'varint_control.c', support / 'varint_control.S', driver, '-o', native])
        address = next(line.split()[0] for line in run(['nm', '--defined-only', native]).splitlines()
                       if line.split()[-1] == 'decode_induction')
        annotation = root / 'signatures.ann'
        annotation.write_text(f'sig {address} void|uint64_t*|output|ByteStream*|stream\n')
        sources = []
        for name in ('control_read_byte', 'decode_control', 'decode_induction'):
            path = root / f'{name}.c'
            path.write_text(run([exe, '--no-cache', '--annotations', annotation, '--emit-c', '-s', name, native]))
            sources.append(path)
        pseudo = run([exe, '--no-cache', '-p', '-s', 'decode_control', native])
        assert 'goto bb_' not in pseudo, pseudo
        bounded = run([exe, '--no-cache', '--annotations', annotation, '-p', '-s', 'decode_induction', native])
        assert '0x3f' not in bounded and '<<' in bounded and 'goto bb_' not in bounded, bounded
        for export_opt in ('0', '2'):
            exported = root / f'export{opt}-{export_opt}.so'
            run([cc, '-std=c11', '-Werror', '-O' + export_opt, '-shared', '-fPIC', '-Wl,-Bsymbolic',
                 *sources, driver, '-o', exported])
            libs = [ctypes.CDLL(str(path)) for path in (native, exported)]
            for lib in libs:
                lib.invoke_control.argtypes = [ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(Stream)]
                lib.invoke_control.restype = ctypes.c_int
                lib.invoke_function.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(Stream)]
                lib.invoke_function.restype = ctypes.c_int
            for data in cases:
                results = []
                for lib in libs:
                    buffer = ctypes.create_string_buffer(data)
                    stream = Stream(ctypes.addressof(buffer), len(data))
                    value = ctypes.c_uint64(0x123456789abcdef)
                    status = lib.invoke_control(ctypes.byref(value), ctypes.byref(stream))
                    results.append((status, value.value, stream.left, stream.data - ctypes.addressof(buffer)))
                assert results[0] == results[1], (opt, export_opt, data, results)
                for lib in libs:
                    buffer = ctypes.create_string_buffer(data)
                    stream = Stream(ctypes.addressof(buffer), len(data))
                    value = ctypes.c_uint64(0x123456789abcdef)
                    status = lib.invoke_function(ctypes.cast(lib.decode_induction, ctypes.c_void_p),
                                                 ctypes.byref(value), ctypes.byref(stream))
                    got = (status, value.value, stream.left, stream.data - ctypes.addressof(buffer))
                    assert got == results[0], ('induction', opt, export_opt, data, got, results[0])
