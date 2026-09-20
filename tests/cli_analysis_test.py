"""Scoped disassembly, boundary warnings, callee completeness and string labels."""
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

exe, cc = sys.argv[1:]
source = Path(__file__).parent / 'support/cli_analysis.S'


def invoke(args, status=0):
    result = subprocess.run([exe, *map(str, args)], text=True, capture_output=True, timeout=20)
    assert result.returncode == status, (args, result)
    return result


with tempfile.TemporaryDirectory(prefix='spelunk-cli-analysis-') as directory:
    binary = Path(directory) / 'fixture.so'
    subprocess.run([cc, '-shared', '-fPIC', '-Wl,-Bsymbolic', source, '-o', binary],
                   check=True, capture_output=True, timeout=30)
    functions = json.loads(invoke(['--functions', '--json', binary]).stdout)
    by_name = {row['name']: (int(row['addr'], 16), int(row['size'], 16)) for row in functions}

    disasm = invoke(['-d', '-s', 'scoped_function', binary])
    assert re.match(r'^; spelunk-build: \S+ \S+\n', disasm.stdout), disasm.stdout
    assert 'xrefs from:' not in disasm.stdout, disasm.stdout
    assert f'({by_name["scoped_function"][1]} bytes)' in disasm.stdout, disasm.stdout

    report = json.loads(invoke(['--callees', 'callees_complete', '--json', binary]).stdout)
    assert set(report['build']) == {'version', 'revision'} and report['build']['revision'], report
    edges = {(int(row['va'], 16), row['kind']) for row in report['callees']}
    assert report['extent_complete'] is True, report
    assert (by_name['reachable_call'][0], 'direct') in edges, report
    assert (by_name['landing_call'][0], 'direct_extent') in edges, report
    assert len(report['unresolved_indirect_sites']) == 1, report
    plain = invoke(['--callees', 'callees_complete', binary]).stdout
    assert plain.startswith('# spelunk-build: ') and 'direct_extent' in plain and 'indirect_unresolved' in plain, plain

    start = by_name['scoped_function'][0]
    # push rbp is one byte; start+1 is a valid boundary. start+2 lands in
    # the following three-byte mov rbp,rsp.
    middle = invoke(['--disasm-at', hex(start + 2), '--count', '2', binary])
    assert 'not an instruction boundary' in middle.stderr, middle
    assert 'decoding starts mid-instruction' in middle.stdout, middle.stdout
    exact = invoke(['--disasm-at', hex(start), '--count', '2', binary])
    assert 'not an instruction boundary' not in exact.stderr, exact
    assert 'verified instruction boundary' in exact.stderr and exact.stdout.startswith('; spelunk-build: '), exact
    json_middle = invoke(['--json', '--disasm-at', hex(start + 2), '--count', '2', binary])
    diagnostics = [json.loads(line) for line in json_middle.stderr.splitlines()]
    assert any('not an instruction boundary' in row['message'] for row in diagnostics), diagnostics
    assert set(json.loads(json_middle.stdout)['build']) == {'version', 'revision'}

    strings = invoke(['--disasm-at', 'string_ref', '--count', '2', binary]).stdout
    assert '"varint decode read past end"' in strings, strings
    assert 'misleading_string_owner+' not in strings, strings
