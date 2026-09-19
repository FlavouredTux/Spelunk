"""Stale virtual arguments and push-rax reservations are presentation noise."""
import ctypes
from pathlib import Path
import re
import subprocess
import sys
import tempfile

exe, cc = sys.argv[1:]
source = Path(__file__).parent / 'support/x64_call_frame.S'


def run(args):
    result = subprocess.run(list(map(str, args)), text=True, capture_output=True, timeout=30)
    if result.returncode:
        raise AssertionError((args, result.stderr))
    return result.stdout


with tempfile.TemporaryDirectory(prefix='spelunk-call-frame-') as tmp:
    root = Path(tmp)
    native = root / 'native.so'
    run([cc, '-shared', '-fPIC', '-Wl,-Bsymbolic-functions', source, '-o', native])
    for name, arguments in [('virtual_stale', 'a2'), ('virtual_duplicate', 'a2, a2'),
                            ('virtual_prepared_before_branch', 'a2, a2'),
                            ('virtual_other_argument', 'a2, 7')]:
        pseudo = run([exe, '--no-cache', '-p', '-s', name, native])
        assert f'vfn_3({arguments})' in pseudo, (name, pseudo)
        if name == 'virtual_stale':
            assert 'inferred ABI args' in pseudo, pseudo

    pseudo = run([exe, '--no-cache', '-p', '-s', 'reserve_marker', native])
    assert not re.search(r'\brax\b', pseudo), pseudo
    assert 'local_8[8]' not in pseudo, pseudo
    # A strict export cannot assume the callee only reads the four-byte
    # subobject. Leave the uninitialized padding visible and reject it.
    rejected = subprocess.run([exe, '--no-cache', '--emit-c', '-s', 'reserve_marker', str(native)],
                              text=True, capture_output=True, timeout=30)
    assert rejected.returncode == 1 and not rejected.stdout, rejected
    for name in ('read_entry_push', 'partial_overwrite', 'escape_uninitialized', 'segment_store_is_not_frame'):
        pseudo = run([exe, '--no-cache', '-p', '-s', name, native])
        assert re.search(r'\brax\b', pseudo), (name, pseudo)

    generated = []
    for name in ('capture_word', 'reserve_full_word', 'pushed_value'):
        path = root / (name + '.c')
        path.write_text(run([exe, '--no-cache', '--emit-c', '-s', name, native]))
        generated.append(path)
    for opt in ('0', '2'):
        exported = root / f'export{opt}.so'
        run([cc, '-std=c11', '-Werror', '-shared', '-fPIC', '-O' + opt, *generated, '-o', exported])
        libs = [ctypes.CDLL(str(path)) for path in (native, exported)]
        for name in ('reserve_full_word', 'pushed_value'):
            for lib in libs:
                getattr(lib, name).argtypes = [ctypes.c_uint64 if name == 'reserve_full_word' else ctypes.c_uint32]
                getattr(lib, name).restype = ctypes.c_uint64
            values = [0, 1, 127, 0x80000000, 0xffffffff]
            if name == 'reserve_full_word':
                values += [0x8000000000000000, 0xffffffffffffffff]
            for value in values:
                results = [getattr(lib, name)(value) for lib in libs]
                assert results == [value, value], (name, opt, value, results)
