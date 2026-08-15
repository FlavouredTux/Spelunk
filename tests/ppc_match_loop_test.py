#!/usr/bin/env python3
"""Unit and isolated workflow tests for the CodeWarrior match loop."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import shlex
import sys
import tempfile


def load_module(path: pathlib.Path):
    spec = importlib.util.spec_from_file_location("ppc_match_loop", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_executable(path: pathlib.Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: ppc_match_loop_test.py SCRIPT")
    matcher = load_module(pathlib.Path(sys.argv[1]))

    with tempfile.TemporaryDirectory() as directory_text:
        root = pathlib.Path(directory_text)
        project = root / "project"
        source_path = project / "src" / "sample.c"
        target_path = project / "build" / "target.o"
        base_path = project / "build" / "base.o"
        source_path.parent.mkdir(parents=True)
        target_path.parent.mkdir(parents=True)
        source = """\
int target_fn(int lhs, int rhs) {
    int first;
    int second;
    return lhs < rhs;
}
"""
        source_path.write_text(source, encoding="utf-8")
        target_path.write_bytes(b"target-object")
        base_path.write_bytes(b"base-object")
        (project / "objdiff.json").write_text(
            json.dumps(
                {
                    "units": [
                        {
                            "name": "main/sample",
                            "target_path": "build/target.o",
                            "base_path": "build/base.o",
                            "metadata": {"source_path": "src/sample.c"},
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        spec_path = root / "variants.json"
        spec_path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "choices": [
                        {
                            "name": "comparison-shape",
                            "category": "condition",
                            "find": "lhs < rhs",
                            "alternatives": [
                                {"name": "swapped", "text": "rhs > lhs"},
                                {"name": "negated", "text": "!(lhs >= rhs)"},
                            ],
                        },
                        {
                            "name": "local-order",
                            "category": "declarations",
                            "find": "    int first;\n    int second;",
                            "alternatives": [
                                {
                                    "name": "reversed",
                                    "text": "    int second;\n    int first;",
                                }
                            ],
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )

        unit = matcher.load_project_unit(project, "main/sample")
        assert unit.source == source_path.resolve()
        choices = matcher.load_choices(spec_path, source)
        candidates = matcher.expand_candidates(source, choices, 16)
        assert len(candidates) == 6
        assert any("rhs > lhs" in candidate.source for candidate in candidates)
        assert any("int second;\n    int first;" in candidate.source for candidate in candidates)
        try:
            matcher.expand_candidates(source, choices, 5)
        except matcher.MatchError as error:
            assert "above --max-candidates" in str(error)
        else:
            raise AssertionError("candidate limit was not enforced")

        overlapping_path = root / "overlap.json"
        overlapping_path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "choices": [
                        {"name": "outer", "find": "lhs < rhs", "alternatives": ["rhs > lhs"]},
                        {
                            "name": "inner",
                            "find": "lhs",
                            "occurrence": 2,
                            "alternatives": ["left"],
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )
        try:
            matcher.load_choices(overlapping_path, source)
        except matcher.MatchError as error:
            assert "overlap" in str(error)
        else:
            raise AssertionError("overlapping choices were not rejected")

        compiler = root / "fake_compiler.py"
        write_executable(
            compiler,
            """#!/usr/bin/env python3
import pathlib
import sys
source, output = map(pathlib.Path, sys.argv[1:3])
output.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
""",
        )
        objdiff = root / "objdiff-cli"
        write_executable(
            objdiff,
            """#!/usr/bin/env python3
import json
import pathlib
import sys
args = sys.argv[1:]
if args[:2] == ["diff", "--help"]:
    print("--output --format")
    raise SystemExit(0)
candidate_path = pathlib.Path(args[args.index("-2") + 1])
output = pathlib.Path(args[args.index("-o") + 1])
candidate = candidate_path.read_text(encoding="utf-8")
fuzzy = 100.0 if "rhs > lhs" in candidate and "int second;\\n    int first;" in candidate else 91.25
symbol = args[-1]
entry = {"name": symbol, "size": "20", "match_percent": fuzzy, "instructions": []}
report = {"left": {"symbols": [entry]}, "right": {"symbols": [entry]}}
output.write_text(json.dumps(report), encoding="utf-8")
""",
        )
        output = root / "results"
        compile_command = " ".join(
            [
                shlex.quote(sys.executable),
                shlex.quote(str(compiler)),
                "{source}",
                "{object}",
            ]
        )
        argv = [
            "--project",
            str(project),
            "--unit",
            "main/sample",
            "--symbol",
            "target_fn",
            "--spec",
            str(spec_path),
            "--output-dir",
            str(output),
            "--objdiff",
            str(objdiff),
            "--compile-command",
            compile_command,
            "--jobs",
            "2",
            "--fail-unmatched",
            "--quiet",
        ]
        assert matcher.main(argv) == 0
        report = json.loads((output / "results.json").read_text(encoding="utf-8"))
        assert report["candidate_count"] == 6
        assert report["scored_count"] == 6
        assert report["best_exact"] is True
        best = (output / "best.c").read_text(encoding="utf-8")
        assert "rhs > lhs" in best
        assert "int second;\n    int first;" in best
        assert "#line" not in best
        assert (output / "best.o").is_file()
        assert (output / "best.objdiff.json").is_file()
        assert not list((output / "candidates").glob("*/objdiff-report.json"))
        assert "function match: 100.000000%" in (output / "summary.txt").read_text(encoding="utf-8")

        # An identical rerun reuses candidate reports instead of recompiling.
        assert matcher.main(argv) == 0
        cached = json.loads((output / "results.json").read_text(encoding="utf-8"))
        assert all(result["cached"] for result in cached["results"])

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
