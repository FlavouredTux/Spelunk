#!/usr/bin/env python3
"""Exercise batch PPC views and code/data round-trip verification."""

from __future__ import annotations

import pathlib
import struct
import subprocess
import sys
import tempfile


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise AssertionError(
            f"command failed ({result.returncode}): {' '.join(command)}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}")
    return result


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: ppc_workflow_cli_test.py SPELUNK PPC_DOL")
    spelunk = pathlib.Path(sys.argv[1])
    fixture = pathlib.Path(sys.argv[2])

    with tempfile.TemporaryDirectory() as directory:
        temp = pathlib.Path(directory)
        manifest = temp / "symbols.txt"
        manifest.write_text(
            "# comments and blank lines are accepted\n"
            "scalar_entry\n\n"
            "0x80003140\n"
            "0x80003160\n",
            encoding="utf-8",
        )
        batch = run([
            str(spelunk), "-q", "-p", "--symbols", str(manifest), str(fixture)
        ])
        markers = [line for line in batch.stdout.splitlines()
                   if line.startswith("// spelunk-symbol: ")]
        assert markers == [
            "// spelunk-symbol: scalar_entry",
            "// spelunk-symbol: 0x80003140",
            "// spelunk-symbol: 0x80003160",
        ]

        # A conventional headers/include path automatically sees its sibling
        # decomp directory, and f32 aliases retain their scalar FP ABI role.
        include = temp / "headers" / "include"
        decomp = temp / "headers" / "decomp"
        include.mkdir(parents=True)
        decomp.mkdir(parents=True)
        (decomp / "extra.h").write_text(
            "typedef float f32;\n", encoding="utf-8")
        (include / "fixture.h").write_text(
            "#include \"extra.h\"\n"
            "typedef struct UnitWork { int value; } UnitWork;\n"
            "#define DECOMP_STATIC(expr)\n"
            "DECOMP_STATIC(UnitWork unit_work)\n"
            "void scalar_entry(UnitWork * state, f32 scale);\n",
            encoding="utf-8",
        )
        imported = run([
            str(spelunk), "--verbose", "--headers", str(include),
            "-p", "-s", "scalar_entry", str(fixture),
        ])
        assert "parse diagnostic" not in imported.stderr
        assert "void scalar_entry(UnitWork * state, float scale)" in imported.stdout
        assert "typedef union UnitWork" in imported.stdout

        data = run([
            str(spelunk), "-q", "--decompile-data", "0x80004000",
            "--type", "uint32_t[2]", "--verify-roundtrip", str(fixture),
        ])
        assert "uint32_t data_80004000[2]" in data.stdout
        assert "round-trip verified: 1 object(s), 0x8 bytes" in data.stderr

        # Replace the fixture's data section with a tiny event script:
        # SET(LW(1)); END_SCRIPT(). The DOL layout stays otherwise intact.
        event_dol = temp / "event.dol"
        image = bytearray(fixture.read_bytes())
        data_offset = struct.unpack_from(">I", image, 0x1C)[0]
        set_word = (1 << 16) | 50
        lw_one = (-29_999_999) & 0xFFFFFFFF
        end_script = 1
        event = struct.pack(">III", set_word, lw_one, end_script)
        image[data_offset:] = event
        struct.pack_into(">I", image, 0xAC, len(event))
        event_dol.write_bytes(image)
        decoded = run([
            str(spelunk), "-q", "--evt-script", "0x80004000",
            "--verify-roundtrip", str(event_dol),
        ])
        assert "SET(LW(1))" in decoded.stdout
        assert "END_SCRIPT()" in decoded.stdout
        assert "round-trip verified: 12 event bytes" in decoded.stderr

        # A non-script address fails validation before anything reaches
        # stdout: no partial EVT_BEGIN body may trail the error line.
        raw = subprocess.run(
            [str(spelunk), "-q", "--evt-script", "0x80004000", str(fixture)],
            capture_output=True, text=True, check=False)
        assert raw.returncode != 0
        assert "invalid opcode/count" in raw.stderr
        assert "EVT_BEGIN" not in raw.stdout

        # --json has no evt-script form; the downgrade is announced on
        # stderr instead of silently emitting plain text.
        raw = subprocess.run(
            [str(spelunk), "-q", "--evt-script", "0x80004000", "--json",
             str(fixture)],
            capture_output=True, text=True, check=False)
        assert raw.returncode != 0
        assert "--evt-script has no --json output" in raw.stderr

        decoded_json = run([
            str(spelunk), "-q", "--evt-script", "0x80004000",
            "--verify-roundtrip", "--json", str(event_dol),
        ])
        assert "--evt-script has no --json output" in decoded_json.stderr
        assert "SET(LW(1))" in decoded_json.stdout
        assert "round-trip verified: 12 event bytes" in decoded_json.stderr

        # Conflicting view flags: one stderr line names every requested
        # selector plus the dispatch-order winner, then the run proceeds
        # (no hard fail - scripts keep working).
        batch = run([
            str(spelunk), "-q", "--strings", "--functions", str(fixture),
        ])
        assert ("multiple view flags requested (--strings, --functions); "
                "running --strings only") in batch.stderr
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
