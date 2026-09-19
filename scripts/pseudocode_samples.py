#!/usr/bin/env python3
"""Build small native binaries and compare exported C against their behavior."""
import argparse
import ctypes
import json
from pathlib import Path
import random
import subprocess
import sys


SAMPLES = {
    'branches': ('classify', 'int32_t|int32_t|value|int32_t|mode'),
    'loops': ('accumulate', 'uint32_t|uint32_t|limit|uint32_t|seed'),
    'records': ('update_counter', 'uint32_t|void*|counter|uint32_t|amount'),
    'division': ('divide_pair', 'int32_t|int32_t|numerator|int32_t|denominator'),
}


def run(args):
    return subprocess.run(list(map(str, args)), check=True, text=True,
                          capture_output=True, timeout=30).stdout


def compare(sample, name, native, exported, seed, random_cases):
    libraries = [ctypes.CDLL(str(path)) for path in (native, exported)]
    functions = [getattr(lib, name) for lib in libraries]
    rng = random.Random(seed)
    if sample == 'records':
        for fn in functions:
            fn.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
            fn.restype = ctypes.c_uint32
        cases = [(v, limit, flags, updates, amount)
                 for v in (0, 9, 10, 11, 0xffffffff)
                 for limit in (0, 10, 0xffffffff)
                 for flags in (0, 1, 2, 3)
                 for updates in (0, 0xffffffff)
                 for amount in (0, 1, 10, 0xffffffff)]
        for case in cases:
            results = []
            for fn in functions:
                # Sentinels catch writes beyond the four-field record.
                storage = (ctypes.c_uint32 * 6)(0xa5a5a5a5, *case[:4], 0x5a5a5a5a)
                value = fn(ctypes.byref(storage, 4), case[4])
                results.append((value, bytes(storage)))
            if results[0] != results[1]:
                raise AssertionError(f'{name}{case}: {results!r}')
        for fn in functions:
            if fn(None, 1) != 0:
                raise AssertionError('null record must return zero')
        return len(cases) + 1
    signed = sample in ('branches', 'division')
    scalar = ctypes.c_int32 if signed else ctypes.c_uint32
    for fn in functions:
        fn.argtypes, fn.restype = [scalar, scalar], scalar
    if sample == 'division':
        values = (-2147483648, -100, -7, -1, 0, 1, 7, 100, 2147483647)
        cases = [(x, y) for x in values for y in values]
        cases += [(rng.randint(-2147483648, 2147483647),
                   rng.randint(-2147483648, 2147483647)) for _ in range(random_cases)]
    elif signed:
        cases = [(x, mode) for x in (-2147483648, -101, -100, -1, 0, 1, 99, 100, 101, 2147483647)
                 for mode in (-1, 0, 1, 2, 3, 4, 2147483647)]
        cases += [(rng.randint(-200, 200), rng.randint(-2, 5)) for _ in range(random_cases)]
    else:
        cases = [(limit, seed) for limit in (0, 1, 2, 3, 4, 9, 32, 100)
                 for seed in (0, 1, 999, 1000, 1001, 0xffffffff)]
        cases += [(rng.randrange(100), rng.getrandbits(32)) for _ in range(random_cases)]
    for case in cases:
        expected, actual = [fn(*case) for fn in functions]
        if expected != actual:
            raise AssertionError(f'{name}{case}: expected {expected}, got {actual}')
    return len(cases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    root = Path(__file__).resolve().parents[1]
    parser.add_argument('--spelunk', type=Path, default=root / 'build/cli/spelunk')
    parser.add_argument('--cc', default='cc')
    parser.add_argument('--optimizations', nargs='+', choices=('0', '1', '2', '3', 's'),
                        default=('0', '2'))
    parser.add_argument('--seed', type=int, default=20260919)
    parser.add_argument('--random-cases', type=int, default=300)
    parser.add_argument('--output', type=Path, default=root / 'build/pseudocode-samples')
    parser.add_argument('--compare', nargs=4, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.random_cases < 0:
        parser.error('--random-cases must be nonnegative')
    if args.compare:
        sample, name, native, exported = args.compare
        print(compare(sample, name, Path(native), Path(exported), args.seed, args.random_cases))
        return 0
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    report = []
    for sample, (name, signature) in SAMPLES.items():
        for optimization in args.optimizations:
            folder = output / f'{sample}-O{optimization}'
            folder.mkdir(exist_ok=True)
            native = folder / 'native.so'
            run([args.cc, '-std=c11', '-g', '-O' + optimization, '-shared', '-fPIC',
                 root / 'tests/support/pseudocode_samples' / (sample + '.c'), '-o', native])
            address = next(line.split()[0] for line in run(['nm', '-D', '--defined-only', native]).splitlines()
                           if line.split()[-1] == name)
            annotations = folder / 'signatures.ann'
            annotations.write_text(f'sig {address} {signature}\n')
            common = [args.spelunk.resolve(), '--no-cache', '--annotations', annotations, '-s', name]
            row = {'sample': sample, 'native_optimization': optimization,
                   'compiler': args.cc, 'seed': args.seed,
                   'random_cases': args.random_cases, 'checks': []}
            try:
                (folder / 'pseudo.c').write_text(run([*common, '-p', native]))
                source = folder / 'exported.c'
                source.write_text(run([*common, '--emit-c', native]))
                for opt in ('0', '2'):
                    exported = folder / f'exported-O{opt}.so'
                    run([args.cc, '-std=c11', '-Werror', '-O' + opt, '-shared', '-fPIC', source, '-o', exported])
                    # A bad export can crash or loop forever. Keep its execution
                    # in a disposable process with the same timeout as tools.
                    count = int(run([sys.executable, Path(__file__).resolve(),
                                     '--seed', args.seed, '--random-cases', args.random_cases,
                                     '--compare', sample, name, native, exported]))
                    row['checks'].append({'export_optimization': opt, 'cases': count})
                row['status'] = 'passed'
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired, AssertionError) as error:
                row['status'] = 'failed'
                row['error'] = str(error) + '\n' + (getattr(error, 'stderr', '') or '')
            report.append(row)
            (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
            print(f'{sample}-O{optimization}: {row["status"]}', flush=True)
    print(f'Binaries, pseudo-C, exports and results: {output}')
    return int(any(row['status'] != 'passed' for row in report))


if __name__ == '__main__':
    raise SystemExit(main())
