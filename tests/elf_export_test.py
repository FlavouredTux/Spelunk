"""Check that `--emit-c` produces a compilable, self-contained C export.

The Mach-O export test executes a handful of hand-picked functions. This one
goes the other way: every ELF fixture in the tree, checked for nothing more
than "clang accepts it, with no unresolved markers left in the text". That is
cheap enough to run over the whole corpus and catches the declaration gaps -
a record type nothing declares, an intrinsic nothing defines, a register read
with no reaching definition - that only show up on unfamiliar input.

Fixtures whose export is still incomplete are listed in KNOWN_GAPS with the
reason. The list is checked in both directions, so closing a gap fails the
test until the entry is removed.
"""
import argparse
import pathlib
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'scripts'))
from check_pseudocode import check_source

# fixture -> what is still missing from its export.
KNOWN_GAPS = {}


def main(args):
    fixtures = sorted(pathlib.Path(args.fixtures).glob('*.prebuilt'))
    assert fixtures, f'no fixtures under {args.fixtures}'
    clean, failed = [], {}
    for fixture in fixtures:
        emitted = subprocess.run([args.spelunk, '--no-cache', '--emit-c', str(fixture)],
                                 capture_output=True, text=True, timeout=120)
        name = fixture.stem
        if emitted.returncode != 0:
            assert emitted.returncode == 1, (name, 'unexpected exit', emitted.returncode, emitted.stderr)
            if 'C export for ' in emitted.stderr and 'is incomplete:' in emitted.stderr:
                assert not emitted.stdout, (name, 'incomplete export leaked partial C')
                failed[name] = [emitted.stderr.strip()]
            else:
                raise AssertionError((name, 'unexpected export failure', emitted.stderr))
            continue
        diagnostics = check_source(emitted.stdout, compiler=args.clang,
                                   filename=name + '.c')
        if diagnostics:
            failed[name] = [d.message for d in diagnostics]
        else:
            clean.append(name)

    regressed = {n: d for n, d in failed.items() if n not in KNOWN_GAPS}
    assert not regressed, 'export no longer compiles: ' + repr(regressed)
    fixed = [n for n in KNOWN_GAPS if n in clean]
    assert not fixed, 'these fixtures now export cleanly, drop them from KNOWN_GAPS: ' + repr(fixed)
    stale = [n for n in KNOWN_GAPS if n not in failed and n not in clean]
    assert not stale, 'KNOWN_GAPS names a fixture with no export: ' + repr(stale)

    print(f'{len(clean)} of {len(clean) + len(failed)} ELF fixtures export '
          f'self-contained C that clang accepts; {len(failed)} known gaps')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--spelunk', required=True)
    parser.add_argument('--clang', required=True)
    parser.add_argument('--fixtures', required=True)
    main(parser.parse_args())
