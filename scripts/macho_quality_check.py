#!/usr/bin/env python3
"""Audit function discovery and emitted-C diagnostics on copied Intel Mach-O files.

Original inputs are never modified. Stripping retains dynamic exports and
runtime metadata; reference coverage is measured against defined text symbols.
Compiler diagnostics can require SDK/type declarations and are not a semantic
correctness score. Use the semantic execution tests for that guarantee.
"""
import argparse
from collections import Counter
from dataclasses import asdict
import hashlib
import json
import pathlib
import random
import re
import struct
import subprocess
import time

from check_pseudocode import check_source


def run(command, timeout=30):
    result = subprocess.run([str(x) for x in command], text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or f'Command exited {result.returncode}')
    return result.stdout


def x64_slice(data):
    magic = struct.unpack_from('>I', data)[0]
    if magic in (0xcafebabe, 0xcafebabf):
        count = struct.unpack_from('>I', data, 4)[0]
        stride = 32 if magic == 0xcafebabf else 20
        for i in range(count):
            offset = 8 + stride * i
            cpu = struct.unpack_from('>I', data, offset)[0]
            start, size = struct.unpack_from('>QQ' if stride == 32 else '>II', data, offset + 8)
            if cpu == 0x1000007:
                return x64_slice(data[start:start + size])
        raise ValueError('No x86-64 slice')
    if struct.unpack_from('<II', data) != (0xfeedfacf, 0x1000007):
        raise ValueError('Expected a 64-bit Intel Mach-O')
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binaries', nargs='+', type=pathlib.Path)
    parser.add_argument('--output', required=True, type=pathlib.Path)
    parser.add_argument('--ember', default='ember')
    parser.add_argument('--strip', default='llvm-strip')
    parser.add_argument('--nm', default='llvm-nm')
    parser.add_argument('--compiler', default='clang')
    parser.add_argument('--preamble', type=pathlib.Path)
    parser.add_argument('--sample', type=int, default=24)
    parser.add_argument('--seed', type=int, default=20260911)
    parser.add_argument('--timeout', type=int, default=30)
    args = parser.parse_args()
    if args.sample < 0 or args.timeout <= 0:
        parser.error('sample must be nonnegative and timeout must be positive')
    args.output.mkdir(parents=True, exist_ok=True)
    preamble = args.preamble.read_text() if args.preamble else '#include <stdint.h>\n#include <stdbool.h>\n#include <stddef.h>\n'
    summary = []
    for index, path in enumerate(args.binaries):
        raw = path.read_bytes()
        folder = args.output / f'{index}-{path.stem}'
        folder.mkdir(parents=True, exist_ok=True)
        original, stripped = folder / 'original.dylib', folder / 'stripped.dylib'
        original.write_bytes(x64_slice(raw))
        run([args.strip, '-s', '-o', stripped, original], args.timeout)
        symbols = {int(m[1], 16): m[2] for line in run([args.nm, '--defined-only', original]).splitlines()
                   if (m := re.match(r'^([0-9a-fA-F]+) [tT] (.+)$', line))}
        inventories = {}
        for label, binary in [('original', original), ('stripped', stripped)]:
            output = run([args.ember, '--no-cache', '--functions', '--json', binary], args.timeout)
            (folder / f'{label}-functions.json').write_text(output)
            inventories[label] = {int(row['addr'], 16): row for row in json.loads(output)}
        before, after = inventories['original'], inventories['stripped']
        candidates = sorted(address for address in symbols.keys() & before.keys()
                            if 24 <= int(before[address]['size'], 16) <= 1024)
        chosen = random.Random(args.seed).sample(candidates, min(args.sample, len(candidates)))
        samples = []
        for address in chosen:
            for label, binary in [('original', original), ('stripped', stripped)]:
                row = {'address': hex(address), 'name': symbols[address], 'variant': label,
                       'discovered': address in inventories[label]}
                start = time.monotonic()
                destination = folder / f'{label}-{address:x}.c'
                try:
                    if not row['discovered']:
                        raise RuntimeError('Function entry was not enumerated; no nearest-symbol fallback attempted')
                    output = run([args.ember, '--no-cache', '-p', '-s', hex(address), binary], args.timeout)
                    destination.write_text(output)
                    diagnostics = check_source(output, filename=str(destination),
                                               compiler=args.compiler, preamble=preamble)
                    row.update(output=str(destination), diagnostics=[asdict(d) for d in diagnostics])
                except (RuntimeError, subprocess.TimeoutExpired) as error:
                    row['error'] = str(error)
                row['seconds'] = round(time.monotonic() - start, 4)
                samples.append(row)
        lost = sorted(symbols.keys() - after.keys())
        result = {'input': str(path.resolve()), 'input_sha256': hashlib.sha256(raw).hexdigest(),
                  'reference_text_entries': len(symbols), 'retained_text_entries': len(symbols.keys() & after.keys()),
                  'missing_text_entries': [{'address': hex(x), 'name': symbols[x]} for x in lost],
                  'original_entries': len(before), 'stripped_entries': len(after),
                  'extra_entries_after_stripping': len(after.keys() - before.keys()), 'samples': samples}
        (folder / 'report.json').write_text(json.dumps(result, indent=2))
        counts = Counter(d['message'] for s in samples for d in s.get('diagnostics', []))
        result['diagnostic_counts'] = dict(counts)
        summary.append(result)
        print(f'{path.name}: {result["retained_text_entries"]}/{len(symbols)} reference entries retained; '
              f'{sum("error" not in s for s in samples)}/{len(samples)} samples produced output; '
              f'{sum(not s.get("diagnostics") and "error" not in s for s in samples)} compiled with supplied declarations')
    (args.output / 'summary.json').write_text(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
