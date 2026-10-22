"""Function-view JSON records, partial batches, and enforced CLI deadlines."""
import json
import fcntl
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time


exe, cc = sys.argv[1:]
repo = Path(__file__).resolve().parents[1]
fixture = repo / 'tests/fixtures/return_value.prebuilt'


def run(args, status=0):
    result = subprocess.run([exe, *map(str, args)], text=True, capture_output=True, timeout=15)
    assert result.returncode == status, (args, result)
    return result


def records(result):
    parsed = [json.loads(line) for line in result.stdout.splitlines()]
    for row in parsed:
        assert set(row) == {'schema_version', 'build', 'type', 'symbol', 'address', 'name',
                            'view', 'status', 'output', 'error'}, row
        assert row['schema_version'] == 1 and row['type'] == 'function', row
        assert set(row['build']) == {'version', 'revision'} and row['build']['revision'], row
        if row['status'] == 'ok':
            assert row['error'] is None and isinstance(row['output'], str), row
            assert int(row['address'], 16) > 0 and row['name'], row
        else:
            assert row['status'] == 'error' and row['output'] is None, row
            assert set(row['error']) == {'kind', 'message'} and row['error']['message'], row
    for line in result.stderr.splitlines():
        assert json.loads(line)['type'] in ('diagnostic', 'error'), line
    return parsed


with tempfile.TemporaryDirectory(prefix='spelunk-cli-batch-') as tmp:
    root = Path(tmp)
    manifest = root / 'symbols.txt'
    missing = 'missing"\\🐧'
    names = ['add32', missing, 'compound']
    manifest.write_text('\n'.join(names) + '\n')
    for flag, view in [('-d', 'disasm'), ('-c', 'cfg'), ('--cfg-pseudo', 'cfg-pseudo'),
                       ('-i', 'ir'), ('--ssa', 'ssa'), ('-O', 'opt'),
                       ('--struct', 'struct'), ('-p', 'pseudo'), ('--emit-c', 'emit-c')]:
        args = ['--no-cache', flag, '--symbols', manifest, fixture]
        rows = records(run(['--json', *args], status=1))
        assert [row['symbol'] for row in rows] == names, rows
        assert [row['status'] for row in rows] == ['ok', 'error', 'ok'], rows
        assert all(row['view'] == view for row in rows), rows
        assert rows[1]['address'] is None and rows[1]['name'] is None, rows
        assert rows[1]['error']['kind'] == 'resolve-failed', rows
        for row in (rows[0], rows[2]):
            plain = run(['--no-cache', flag, '-s', row['symbol'], fixture])
            plain_body = plain.stdout.split('\n', 1)[1]
            assert 'spelunk-build:' in plain.stdout.splitlines()[0], plain.stdout
            assert row['output'] == plain_body, (flag, row, plain.stdout)
            single = records(run(['--json', '--no-cache', flag, '-s', row['symbol'], fixture]))
            assert single == [row], (flag, row, single)

    native = root / 'exports.so'
    subprocess.run([cc, '-shared', '-fPIC', str(repo / 'tests/support/export_regressions.S'),
                    '-o', str(native)], check=True, capture_output=True, timeout=30)
    manifest.write_text('export_copy\nexport_rdtsc\nexport_undecoded\nexport_quotient\n')
    for json_mode in (False, True):
        args = ['--no-cache', '--emit-c', '--symbols', manifest, native]
        result = run((['--json'] if json_mode else []) + args, status=1)
        if json_mode:
            rows = records(result)
            assert [r['status'] for r in rows] == ['ok', 'error', 'error', 'ok'], rows
            assert all(r['address'] is not None for r in rows), rows
            assert 'unresolved intrinsic' in rows[1]['error']['message'], rows
            assert 'undecoded control-flow target' in rows[2]['error']['message'], rows
        else:
            assert '// spelunk-symbol: export_quotient' in result.stdout, result

    for contents in ('', 'add32\nadd32\n', 'has whitespace\n'):
        manifest.write_text(contents)
        result = run(['--json', '-p', '--symbols', manifest, fixture], status=1)
        assert not result.stdout and json.loads(result.stderr.splitlines()[-1])['type'] == 'error'

    # Consume one result, then stop draining stdout. The bounded pipe forces
    # the command to remain active until its deadline, after real output.
    many_source = root / 'many.S'
    many_source.write_text('.text\n' + '\n'.join(
        f'.globl batch_{i}\n.type batch_{i}, @function\nbatch_{i}:\n'
        f'movl ${i}, %eax\nret\n.size batch_{i}, .-batch_{i}\n'
        for i in range(128)) + '.section .note.GNU-stack,"",@progbits\n')
    many_binary = root / 'many.so'
    subprocess.run([cc, '-shared', '-fPIC', str(many_source), '-o', str(many_binary)],
                   check=True, capture_output=True, timeout=30)
    manifest.write_text(''.join(f'batch_{i}\n' for i in range(128)))
    read_fd, write_fd = os.pipe()
    fcntl.fcntl(write_fd, fcntl.F_SETPIPE_SZ, 4096)
    child = subprocess.Popen([exe, '--json', '--no-cache', '--timeout', '2s', '-i',
                              '--symbols', str(manifest), str(many_binary)],
                             stdout=write_fd, stderr=subprocess.PIPE)
    os.close(write_fd)
    try:
        with os.fdopen(read_fd, 'rb') as stream:
            first = json.loads(stream.readline())
            assert first['symbol'] == 'batch_0' and first['status'] == 'ok', first
            assert child.poll() is None, 'results were not delivered while the command was active'
            assert child.wait(timeout=5) == 124
            tail = stream.read()
            complete = tail[:tail.rfind(b'\n') + 1]
            remaining = [json.loads(line) for line in complete.splitlines()]
            assert all(row['status'] == 'ok' for row in remaining), remaining
        assert json.loads(child.stderr.read().splitlines()[-1])['kind'] == 'timeout'
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()
        child.stderr.close()

    for duration in ('', '0', '-1s', 'nan', 'inf', '0.5ms', '1e300s', '25h', '2seconds'):
        result = run(['--json', '--timeout', duration, '-p', fixture], status=1)
        assert not result.stdout and json.loads(result.stderr)['kind'] == 'invalid-format', result
    # Normal completion must cancel the watchdog, not wait out its budget.
    for duration in ('10', '10000ms', '10.5s', '1m', '24h'):
        start = time.monotonic()
        records(run(['--json', '--timeout', duration, '-p', '-s', 'add32', fixture]))
        assert time.monotonic() - start < 5, duration

    # Opening a FIFO without a writer blocks deterministically. No huge
    # binaries or race-prone assumptions about how fast analysis runs.
    fifo = root / 'blocked-symbols'
    os.mkfifo(fifo)
    for json_mode in (False, True):
        start = time.monotonic()
        result = run((['--json'] if json_mode else []) +
                     ['--timeout', '150ms', '-p', '--symbols', fifo, fixture], status=124)
        assert 0.1 <= time.monotonic() - start < 5, result
        assert not result.stdout, result
        if json_mode:
            assert json.loads(result.stderr.splitlines()[-1])['kind'] == 'timeout', result
        else:
            assert 'spelunk: timeout:' in result.stderr, result

    # Neither a stalled diagnostic consumer nor a blocked final stdout flush
    # can outlive the deadline. These pipes are deliberately never drained.
    for blocked_stream in ('stdout', 'stderr'):
        read_fd, write_fd = os.pipe()
        child = None
        try:
            os.set_blocking(write_fd, False)
            try:
                while True:
                    os.write(write_fd, b'x' * 4096)
            except BlockingIOError:
                pass
            os.set_blocking(write_fd, True)
            args = ['--functions', str(fixture)] if blocked_stream == 'stdout' else [
                '-p', '--symbols', str(fifo), str(fixture)]
            child = subprocess.Popen([exe, '--json', '--no-cache', '--timeout', '150ms', *args],
                stdout=write_fd if blocked_stream == 'stdout' else subprocess.DEVNULL,
                stderr=write_fd if blocked_stream == 'stderr' else subprocess.DEVNULL)
            assert child.wait(timeout=5) == 124
        finally:
            if child is not None and child.poll() is None:
                child.kill()
                child.wait()
            os.close(write_fd)
            os.close(read_fd)
