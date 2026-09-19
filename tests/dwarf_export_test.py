"""Check recovered record fields and callback typedefs through C export."""
import ctypes
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile


def run(args):
    result = subprocess.run(list(map(str, args)), text=True, capture_output=True, timeout=30)
    if result.returncode:
        raise RuntimeError(f'{result.args}\n{result.stderr}')
    return result.stdout


def main():
    spelunk, cc = sys.argv[1:]
    repo = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location('samples', repo / 'scripts/pseudocode_samples.py')
    samples = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(samples)
    with tempfile.TemporaryDirectory(prefix='spelunk-dwarf-export-') as tmp:
        root = Path(tmp)
        for version in ('4', '5'):
            for opt in ('0', '2'):
                folder = root / f'dwarf{version}-O{opt}'
                folder.mkdir()
                for sample, source, names in (
                    ('callback', repo / 'tests/fixtures/indirect_trace.c', ('plus7', 'minus3', 'call_fp', 'call_zero', 'main')),
                    ('record', repo / 'tests/support/pseudocode_samples/records.c', ('update_counter',)),
                    ('member', repo / 'tests/fixtures/indirect_tail.c', ('via_member',)),
                ):
                    native = folder / f'{sample}.so'
                    if sample == 'callback':
                        generated = folder / 'callbacks.c'
                        generated.write_text(source.read_text() + '\ntypedef int (*zero_op)(void);\n'
                                             'int call_zero(zero_op fn) { return fn() + 3; }\n')
                        source = generated
                    run([cc, '-shared', '-fPIC', '-Wl,-Bsymbolic', '-gdwarf-' + version, '-O' + opt, source, '-o', native])
                    sources = []
                    for name in names:
                        text = run([spelunk, '--no-cache', '--emit-c', '-s', name, native])
                        exported = folder / f'{name}.c'
                        exported.write_text(text)
                        sources.append(exported)
                    if sample == 'callback':
                        if 'typedef int (*op_t)(int);' not in (folder / 'call_fp.c').read_text():
                            raise AssertionError('callback typedef was not recovered')
                    elif sample == 'record':
                        pseudo = run([spelunk, '--no-cache', '-p', '-s', 'update_counter', native])
                        for member in ('value', 'limit', 'flags', 'updates'):
                            if f'counter->{member}' not in pseudo:
                                raise AssertionError(pseudo)
                        address = next(line.split()[0] for line in run(['nm', '-D', '--defined-only', native]).splitlines()
                                       if line.split()[-1] == 'update_counter')
                        annotation = folder / 'record.ann'
                        annotation.write_text(f'sig {address} uint32_t|struct Counter*|counter|uint32_t|amount\n')
                        tagged = folder / 'record-tagged.c'
                        tagged.write_text(run([spelunk, '--no-cache', '--emit-c', '--annotations', annotation,
                                               '-s', 'update_counter', native]))
                    for export_opt in ('0', '2'):
                        exported = folder / f'{sample}-export-{export_opt}.so'
                        run([cc, '-std=c11', '-Werror', '-shared', '-fPIC', '-O' + export_opt, *sources, '-o', exported])
                        if sample == 'record':
                            samples.compare('records', 'update_counter', native, exported, 42, 0)
                            tagged_lib = folder / f'tagged-{export_opt}.so'
                            run([cc, '-std=c11', '-Werror', '-shared', '-fPIC', '-O' + export_opt, tagged, '-o', tagged_lib])
                            samples.compare('records', 'update_counter', native, tagged_lib, 42, 0)
                            continue
                        libraries = [ctypes.CDLL(str(path)) for path in (native, exported)]
                        if sample == 'member':
                            if 'int (*)(int)' not in sources[0].read_text():
                                raise AssertionError('member callback prototype was not recovered')
                            callback = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int)(lambda value: value + 19)
                            handler = (ctypes.c_void_p * 2)(ctypes.cast(callback, ctypes.c_void_p), None)
                            for lib in libraries:
                                lib.via_member.argtypes = [ctypes.c_void_p, ctypes.c_int]
                                lib.via_member.restype = ctypes.c_int
                                for value in (-1000, -1, 0, 1, 1000):
                                    if lib.via_member(handler, value) != value + 19:
                                        raise AssertionError(('member', value))
                            continue
                        if 'int (*)(void)' not in (folder / 'call_zero.c').read_text():
                            raise AssertionError('zero-argument callback prototype was not recovered')
                        zero = ctypes.CFUNCTYPE(ctypes.c_int)(lambda: 19)
                        for lib in libraries:
                            lib.call_zero.argtypes, lib.call_zero.restype = [ctypes.c_void_p], ctypes.c_int
                            if lib.call_zero(ctypes.cast(zero, ctypes.c_void_p)) != 22:
                                raise AssertionError('zero-argument callback result')
                            lib.call_fp.argtypes, lib.call_fp.restype = [ctypes.c_void_p, ctypes.c_int], ctypes.c_int
                            lib.main.argtypes, lib.main.restype = [ctypes.c_int, ctypes.c_void_p], ctypes.c_int
                        for value in (-1000, -8, -1, 0, 1, 7, 1000):
                            for name in ('plus7', 'minus3'):
                                callback = ctypes.cast(getattr(libraries[0], name), ctypes.c_void_p)
                                results = [lib.call_fp(callback, value) for lib in libraries]
                                if results[0] != results[1]:
                                    raise AssertionError((name, value, results))
                            if libraries[0].main(value, None) != libraries[1].main(value, None):
                                raise AssertionError(('main', value))
        print('DWARF v4/v5 record layouts and callbacks round-trip at -O0/-O2')


if __name__ == '__main__':
    main()
