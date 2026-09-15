#!/usr/bin/env python3
"""Check emitted C with Clang; supply API/type declarations via --preamble.

Diagnostics describe compilation gaps, not proofs of incorrect machine-code
semantics. Intentional pseudo-C extensions and unknown SDK types can require
additional declarations before a function can be checked as C.
"""
import argparse
from dataclasses import asdict, dataclass
import json
import pathlib
import re
import subprocess


@dataclass(frozen=True)
class Diagnostic:
    file: str
    line: int
    column: int
    severity: str
    message: str


def check_source(source, *, compiler='clang', filename='pseudo.c', preamble=''):
    translation_unit = preamble + '\n#line 1 ' + json.dumps(str(filename)) + '\n' + source
    command = [compiler, '-x', 'c', '-std=c11', '-fsyntax-only', '-fno-color-diagnostics',
               '-ferror-limit=0', '-Werror=implicit-function-declaration',
               '-Werror=incompatible-pointer-types', '-Werror=return-type',
               '-Werror=unreachable-code-aggressive', '-']
    result = subprocess.run(command, input=translation_unit, text=True, capture_output=True, timeout=30)
    diagnostics = []
    tokens = re.finditer(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*[\s\S]*?\*/|//[^\n]*', source)
    markers = ('STRUCTURER_FAIL', 'unresolved expression materialization', 'unresolved SSA merge',
               'stray call.args', 'unresolved register read', 'unresolved record type',
               'unresolved intrinsic', 'unresolved string operation',
               'unresolved call signature')
    for token in tokens:
        if not token[0].startswith(('/*', '//')):
            continue
        for marker in markers:
            if marker in token[0]:
                line = source.count('\n', 0, token.start()) + 1
                column = token.start() - source.rfind('\n', 0, token.start())
                diagnostics.append(Diagnostic(str(filename), line, column, 'error',
                                              'incomplete decompiler output: ' + marker))
    for line in result.stderr.splitlines():
        match = re.match(r'^(.*):(\d+):(\d+): (fatal error|error|warning): (.*)$', line)
        if match:
            diagnostics.append(Diagnostic(match[1], int(match[2]), int(match[3]), match[4], match[5]))
    if result.returncode and not diagnostics:
        raise RuntimeError(result.stderr.strip() or 'Compiler failed without diagnostics')
    return diagnostics


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('files', nargs='+', type=pathlib.Path)
    parser.add_argument('--compiler', default='clang')
    parser.add_argument('--preamble', type=pathlib.Path, help='Header text containing known API and type declarations')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args()
    preamble = args.preamble.read_text() if args.preamble else '#include <stdint.h>\n#include <stdbool.h>\n'
    diagnostics = [d for path in args.files for d in check_source(
        path.read_text(), compiler=args.compiler, filename=str(path), preamble=preamble)]
    if args.json:
        print(json.dumps([asdict(d) for d in diagnostics], indent=2))
    else:
        for d in diagnostics:
            print(f'{d.file}:{d.line}:{d.column}: {d.severity}: {d.message}')
        if not diagnostics:
            print(f'{len(args.files)} file(s) passed the C output checks')
    return int(any(d.severity != 'warning' for d in diagnostics))


if __name__ == '__main__':
    raise SystemExit(main())
