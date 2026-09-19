"""Varint loop state and implicit x86 shift-count semantics survive emission."""
import ctypes
from pathlib import Path
import subprocess
import re
import random
import sys
import tempfile

exe, cc = sys.argv[1:]
source = Path(__file__).parent / 'support/varint.c'


def run(args):
    result = subprocess.run(list(map(str, args)), capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise AssertionError((args, result.stdout, result.stderr))
    return result.stdout


class Stream(ctypes.Structure):
    _fields_ = [('data', ctypes.c_void_p), ('left', ctypes.c_size_t)]


with tempfile.TemporaryDirectory(prefix='spelunk-varint-') as directory:
    root = Path(directory)
    exceptions = root / 'exceptions.so'
    run([cc, '-O2', '-shared', '-fPIC', source.with_name('varint_exceptions.cpp'), '-lstdc++', '-o', exceptions])
    name = next(line.split()[-1] for line in run(['nm', '--defined-only', exceptions]).splitlines()
                if 'checkSize' in line)
    pseudo = run([exe, '--no-cache', '-p', '-s', name, exceptions])
    assert 'unsigned long long* a1' in pseudo and 'wire::Stream* a2' in pseudo, pseudo
    allocations = re.findall(r'__cxa_allocate_exception\(([^)\n]*)\)', pseudo)
    assert len(allocations) == 2 and all(',' not in args for args in allocations), pseudo
    assert pseudo.count('__cxa_throw(') in (1, 2), pseudo
    if pseudo.count('__cxa_throw(') == 1:
        assert 'goto bb_' in pseudo, pseudo
    assert pseudo.count('"read past end"') == 1, pseudo
    assert pseudo.count('"larger than maximum size"') == 1, pseudo
    compiler_flags = [] if 'clang' in run([cc, '--version']).lower() else ['-fno-ipa-cp', '-fno-ipa-ra']
    for opt in ('0', '2'):
        binary = root / f'native{opt}.so'
        run([cc, '-O' + opt, '-g', '-shared', '-fPIC', '-Wl,-Bsymbolic-functions', *compiler_flags, source, '-o', binary])
        if opt == '2':
            nodebug = root / 'nodebug.so'
            run([cc, '-O2', '-shared', '-fPIC', '-Wl,-Bsymbolic-functions', *compiler_flags, source, '-o', nodebug])
            wrapper = run([exe, '--no-cache', '-p', '-s', 'read_byte', nodebug])
            assert 'read_bytes(a1, a2, 1)' in wrapper, wrapper
        generated = []
        for name in ('read_bytes', 'read_byte', 'decode_varint', 'shift_value'):
            path = root / (name + '.c')
            path.write_text(run([exe, '--no-cache', '--emit-c', '-s', name, binary]))
            generated.append(path)
        pseudo = run([exe, '--no-cache', '-p', '-s', 'shift_value', binary])
        assert '?' not in pseudo, pseudo
        for export_opt in ('0', '2'):
            output = root / f'export{opt}-{export_opt}.so'
            run([cc, '-std=c11', '-Werror', '-O' + export_opt, '-shared', '-fPIC', *generated, '-o', output])
            libs = [ctypes.CDLL(str(path)) for path in (binary, output)]
            for lib in libs:
                lib.decode_varint.argtypes = [ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(Stream)]
                lib.shift_value.argtypes = [ctypes.c_uint64, ctypes.c_uint]
                lib.shift_value.restype = ctypes.c_uint64
            cases = [b'', b'\0', b'\x7f', b'\x80\x01', b'\xff\x7f', b'\xac\x02',
                     b'\x80', b'\xff' * 9 + b'\x01', b'\x80' * 10, b'\xff' * 10,
                     b'\x80' * 8 + b'\x01']
            rng = random.Random(20260919)
            cases.extend(bytes(rng.randrange(256) for _ in range(rng.randrange(13))) for _ in range(100))
            for _ in range(100):
                number = rng.getrandbits(64)
                encoded = bytearray()
                while number >= 128:
                    encoded.append((number & 127) | 128)
                    number >>= 7
                encoded.append(number)
                cases.append(bytes(encoded))
            for data in cases:
                results = []
                for lib in libs:
                    storage = ctypes.create_string_buffer(data)
                    stream = Stream(ctypes.addressof(storage), len(data))
                    value = ctypes.c_uint64(0x123456789)
                    status = lib.decode_varint(ctypes.byref(value), ctypes.byref(stream))
                    results.append((status, value.value, stream.left, stream.data - ctypes.addressof(storage)))
                assert results[0] == results[1], (opt, export_opt, data, results)
            for value in (0, 1, 0x7f, 0x8000000000000001, 0xffffffffffffffff):
                for count in (0, 1, 7, 31, 32, 63, 64, 65, 127, 255):
                    results = [lib.shift_value(value, count) for lib in libs]
                    assert results[0] == results[1], (value, count, results)
