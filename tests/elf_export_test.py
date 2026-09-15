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
KNOWN_GAPS = {
    'fp_scalar': 'scalar doubles flow into vector intrinsic operands (_mm_max_sd)',
    'dbg_target_ofp': 'omit-frame-pointer target reads rax with no reaching definition',
    'indirect_tail': 'xmm0 is read at entry with no reaching definition',
    'indirect_trace': 'op_t is a function-pointer typedef debug info gives by name only',
    'decoder_misc': 'REP CMPS/SCAS/LODS and sized global arrays are not modelled',
    'dbg_exec_parent': 'a string pointer loaded from memory is passed to %s as uint64_t',
    'printf_noise': 'a string pointer loaded from memory is passed to %s as uint64_t',
}


def main(args):
    fixtures = sorted(pathlib.Path(args.fixtures).glob('*.prebuilt'))
    assert fixtures, f'no fixtures under {args.fixtures}'
    clean, failed = [], {}
    for fixture in fixtures:
        emitted = subprocess.run([args.ember, '--no-cache', '--emit-c', str(fixture)],
                                 capture_output=True, text=True, timeout=120)
        if emitted.returncode != 0:
            continue  # not a decompilable image (raw blobs, debugger payloads)
        name = fixture.stem
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
    parser.add_argument('--ember', required=True)
    parser.add_argument('--clang', required=True)
    parser.add_argument('--fixtures', required=True)
    main(parser.parse_args())
