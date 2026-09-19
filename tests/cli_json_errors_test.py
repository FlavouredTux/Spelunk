"""Diagnostics stay machine-readable without changing command output/status."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


exe, fixture = sys.argv[1:]


def invoke(args, failure=True, timing=False):
    env = dict(os.environ, SPELUNK_TIMING='1' if timing else '0')
    result = subprocess.run([exe, *map(str, args)], capture_output=True,
                            text=True, env=env, timeout=30)
    assert (result.returncode != 0) == failure, result
    records = [json.loads(line) for line in result.stderr.splitlines()]
    assert all(set(record) == {'type', 'kind', 'message'} for record in records), records
    errors = [record for record in records if record['type'] == 'error']
    assert bool(errors) == failure, records
    return result, records


for args in (['--json', '--bad-option'], ['--bad-option', '--json'],
             ['--json'], ['--json', '--limit', 'bad', fixture]):
    result, records = invoke(args)
    assert records[-1]['kind'] == 'invalid-format', records
    assert not result.stdout

with tempfile.TemporaryDirectory(prefix='spelunk-json-errors-') as tmp:
    missing = Path(tmp) / 'missing"\\\nü🐧.bin'
    result, records = invoke(['--json', '--functions', missing])
    assert records[-1]['kind'] == 'io', records
    assert str(missing) in records[-1]['message'], records
    malformed = Path(tmp) / 'malformed'
    malformed.write_bytes(b'not a binary')
    invoke(['--json', '--functions', malformed])
    invalid_name = os.fsencode(tmp) + b'/missing-\xff'
    raw = subprocess.run([os.fsencode(exe), b'--json', b'--functions', invalid_name],
                         capture_output=True, timeout=30)
    assert raw.returncode != 0
    assert json.loads(raw.stderr)['type'] == 'error', raw.stderr

invoke(['--json', '--no-cache', '-p', '-s', 'missing_symbol', fixture])
invoke(['--json', '--no-cache', '--state-map', '0xINVALID', fixture])
result, records = invoke(['--json', '--no-cache', '--functions', fixture], failure=False, timing=True)
json.loads(result.stdout)
assert records, 'timing diagnostics were not exercised'

# A value spelled --json must not select JSON diagnostics.
plain = subprocess.run([exe, '-s', '--json', '--bad-option'], capture_output=True, text=True)
assert plain.returncode != 0 and plain.stderr.startswith('spelunk:'), plain
plain = subprocess.run([exe, '--bad-option'], capture_output=True, text=True)
assert plain.returncode != 0 and 'unknown flag' in plain.stderr
