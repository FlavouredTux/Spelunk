#!/usr/bin/env python3
"""Isolated end-to-end tests for whole PPC translation-unit recovery."""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tempfile


def executable(path: pathlib.Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: ppc_decompile_unit_test.py SCRIPT")
    script = pathlib.Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory() as directory:
        root = pathlib.Path(directory)
        project = root / "project"
        source = project / "src" / "unit.c"
        target = project / "build" / "target.o"
        base = project / "build" / "base.o"
        source.parent.mkdir(parents=True)
        target.parent.mkdir(parents=True)
        target.write_bytes(b"target")
        base.write_bytes(b"base")
        original = """\
#include <common.h>

typedef struct Work { int value; } Work;
static int shared_value;

void first(void) { shared_value = 1; }
int second(int value) { return value + shared_value; }
"""
        source.write_text(original, encoding="utf-8")
        (project / "objdiff.json").write_text(json.dumps({"units": [{
            "name": "main/unit",
            "target_path": "build/target.o",
            "base_path": "build/base.o",
            "metadata": {"source_path": "src/unit.c"},
        }]}), encoding="utf-8")

        objdiff = root / "objdiff-cli"
        executable(objdiff, """#!/usr/bin/env python3
import json
print(json.dumps({"left": {"symbols": [
  {"name": "first", "kind": "SYMBOL_FUNCTION", "size": "16"},
  {"name": "second", "kind": "SYMBOL_FUNCTION", "address": "16", "size": "24"}
]}, "right": {"symbols": [
  {"name": "first", "kind": "SYMBOL_FUNCTION", "size": "16"},
  {"name": "second", "kind": "SYMBOL_FUNCTION", "address": "16", "size": "24"},
  {"name": "third", "kind": "SYMBOL_FUNCTION", "address": "40", "size": "8"}
]}}))
""")
        ember = root / "ember"
        executable(ember, """#!/usr/bin/env python3
import pathlib, sys
manifest = pathlib.Path(sys.argv[sys.argv.index('--symbols') + 1])
for name in manifest.read_text().splitlines():
    print(f'// ember-symbol: {name}')
    print('typedef union PpcState {')
    print('  struct { uint32_t word_0; };')
    print('} PpcState;')
    if name == 'first':
        print('void first(void) { PpcState* state = 0; state->word_0 = 1; }')
    elif name == 'second':
        print('int second(int value) { return value + 1; }')
    else:
        print('void third(void) {}')
""")
        output = root / "recovered.c"
        command = [
            sys.executable, str(script), "--project", str(project),
            "--unit", "main/unit", "--objdiff", str(objdiff),
            "--ember", str(ember), "--output", str(output), "--strict",
            "--batch-size", "2",
        ]
        result = subprocess.run(command, text=True, capture_output=True, check=False)
        assert result.returncode == 0, result.stderr
        text = output.read_text(encoding="utf-8")
        assert text.index("void first") < text.index("int second")
        assert text.index("int second") < text.index("void third")
        assert "#include <common.h>" in text
        assert "typedef struct Work" in text
        assert "static int shared_value" in text
        assert "PpcState_first" in text
        assert "PpcState_second" in text
        assert "shared_value = 1" not in text
        assert source.read_text(encoding="utf-8") == original
        assert "recovered 3/3 function(s)" in result.stderr
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
