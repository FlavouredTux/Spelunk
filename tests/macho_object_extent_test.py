"""Mach-O object functions use compact-unwind extents or fail explicitly."""
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

exe, clang = sys.argv[1:]


def run(args, status=0):
    result = subprocess.run(list(map(str, args)), text=True, capture_output=True, timeout=30)
    assert result.returncode == status, (args, result)
    return result


def compact_extents(path):
    data = path.read_bytes()
    assert struct.unpack_from('<I', data)[0] == 0xfeedfacf
    result = {}
    cursor = 32
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        command, size = struct.unpack_from('<II', data, cursor)
        if command == 0x19:
            count = struct.unpack_from('<I', data, cursor + 64)[0]
            section = cursor + 72
            for _ in range(count):
                sectname = data[section:section + 16].split(b'\0')[0]
                length, offset = struct.unpack_from('<QI', data, section + 40)[0], struct.unpack_from('<I', data, section + 48)[0]
                if sectname == b'__compact_unwind':
                    payload = data[offset:offset + length]
                    for item in range(0, len(payload), 32):
                        start, extent = struct.unpack_from('<QI', payload, item)
                        if extent:
                            result[start] = extent
                section += 80
        cursor += size
    return result


with tempfile.TemporaryDirectory(prefix='spelunk-macho-object-') as directory:
    root = Path(directory)
    source = root / 'fixture.c'
    source.write_text('''
extern void sink(void*);
__attribute__((noinline)) int object_extent_target(int x) {
    volatile char bytes[256];
    for (int i = 0; i < 256; ++i) bytes[i] = (char)(x + i);
    sink((void*)bytes);
    return bytes[(x + 1) & 255];
}
''')
    obj = root / 'fixture.o'
    run([clang, '--target=x86_64-apple-macos10.15', '-Os', '-c', source, '-o', obj])
    expected = compact_extents(obj)
    assert expected, 'compiler emitted no compact unwind records'
    functions = json.loads(run([exe, '--no-cache', '--functions', '--json', obj]).stdout)
    target = next(row for row in functions if row['name'] == 'object_extent_target')
    address, extent = int(target['addr'], 16), int(target['size'], 16)
    assert expected[address] == extent and extent > 12, (expected, target)
    assert not any(row['kind'] == 'sub' and address < int(row['addr'], 16) < address + extent
                   for row in functions), functions
    disasm = run([exe, '--no-cache', '-d', '-s', 'object_extent_target', obj]).stdout
    assert f'({extent} bytes)' in disasm and '1024 bytes' not in disasm, disasm[:300]

    unsupported = root / 'unsupported.o'
    run([clang, '--target=x86_64-apple-macos10.15', '-Os', '-fno-unwind-tables',
         '-fno-asynchronous-unwind-tables', '-c', source, '-o', unsupported])
    failed = run([exe, '--no-cache', '--json', '--functions', unsupported], status=1)
    assert not failed.stdout
    error = json.loads(failed.stderr.splitlines()[-1])
    assert error['kind'] == 'unsupported' and 'reliable extent metadata' in error['message'], error
    failed = run([exe, '--no-cache', '--json', '-d', '-s', 'object_extent_target', unsupported], status=1)
    row = json.loads(failed.stdout)
    assert row['status'] == 'error' and row['error']['kind'] == 'resolve-failed', row
    diagnostics = [json.loads(line) for line in failed.stderr.splitlines()]
    assert any('no reliable function extent' in item['message'] for item in diagnostics), diagnostics
