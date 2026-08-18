#!/usr/bin/env python3
"""Recover every function in an objdiff unit as one project-aware C source file."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from typing import Any, Sequence


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from ppc_match_loop import (  # noqa: E402
    MatchError,
    ProjectUnit,
    _code_mask,
    function_source_span,
    infer_compile_argv,
    load_project_unit,
    materialize_compile_argv,
)


class UnitError(RuntimeError):
    """A focused, user-facing translation-unit recovery error."""


@dataclass(frozen=True)
class FunctionSymbol:
    name: str
    address: int
    size: int


_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_BATCH_MARKER = re.compile(r"^// ember-symbol: (\S+)\s*$")
_SYNTHETIC_TYPE = re.compile(r"\b(?:PpcGlobalState|PpcObject|PpcState)\d*\b")


def _parse_number(value: Any) -> int:
    if value is None:
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise UnitError(f"unexpected numeric value in objdiff output: {value!r}")


def _run(
    argv: Sequence[str], cwd: pathlib.Path, timeout: float
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            list(argv), cwd=cwd, text=True, capture_output=True,
            timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise UnitError(f"command timed out after {timeout:g}s: {argv[0]}") from error
    except OSError as error:
        raise UnitError(f"could not execute {argv[0]}: {error}") from error


def _tool(explicit: pathlib.Path | None, project: pathlib.Path, name: str) -> pathlib.Path:
    if explicit is not None:
        path = explicit.expanduser().resolve()
        if not path.is_file():
            raise UnitError(f"{name} executable does not exist: {path}")
        return path
    project_tool = project / "build" / "tools" / name
    if project_tool.is_file():
        return project_tool.resolve()
    found = shutil.which(name)
    if found:
        return pathlib.Path(found).resolve()
    option = "--objdiff" if name == "objdiff-cli" else f"--{name}"
    raise UnitError(f"could not find {name}; pass {option}")


def load_function_symbols(
    objdiff: pathlib.Path, project: pathlib.Path, unit_name: str, timeout: float
) -> list[FunctionSymbol]:
    result = _run(
        [str(objdiff), "diff", "-p", str(project), "-u", unit_name,
         "-o", "-", "--format", "json"],
        project,
        timeout,
    )
    if result.returncode != 0:
        detail = result.stderr.strip().splitlines()
        raise UnitError(detail[-1] if detail else "objdiff could not inspect the unit")
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise UnitError(f"objdiff returned invalid JSON: {error}") from error

    # Project conventions differ on which side is called target/base. An
    # incomplete decomp object can contain only a prefix of the retail
    # functions, so select the richer table rather than guessing by label.
    sides = [report.get("left"), report.get("right")]
    candidate_sides: list[list[dict[str, Any]]] = []
    for side in sides:
        if not isinstance(side, dict) or not isinstance(side.get("symbols"), list):
            continue
        candidates = [
            item for item in side["symbols"]
            if isinstance(item, dict) and item.get("kind") == "SYMBOL_FUNCTION"
        ]
        if candidates:
            candidate_sides.append(candidates)
    raw_symbols = max(candidate_sides, key=len, default=[])
    if not raw_symbols:
        raise UnitError(f"objdiff unit {unit_name} contains no function symbols")

    functions: list[FunctionSymbol] = []
    seen: set[str] = set()
    for item in raw_symbols:
        name = item.get("name")
        if not isinstance(name, str) or not _IDENT.fullmatch(name) or name in seen:
            continue
        seen.add(name)
        functions.append(FunctionSymbol(
            name=name,
            address=_parse_number(item.get("address")),
            size=_parse_number(item.get("size")),
        ))
    if not functions:
        raise UnitError(f"objdiff unit {unit_name} has no C-compatible function names")
    return functions


def split_batch_output(text: str) -> dict[str, str]:
    outputs: dict[str, list[str]] = {}
    current: str | None = None
    for line in text.splitlines(keepends=True):
        marker = _BATCH_MARKER.match(line.rstrip("\r\n"))
        if marker is not None:
            current = marker.group(1)
            outputs.setdefault(current, [])
            continue
        if current is not None:
            outputs[current].append(line)
    return {name: "".join(lines).strip() + "\n" for name, lines in outputs.items()}


def _skip_space_and_comments(source: str, offset: int) -> int:
    while offset < len(source):
        if source[offset].isspace():
            offset += 1
        elif source.startswith("//", offset):
            newline = source.find("\n", offset + 2)
            offset = len(source) if newline < 0 else newline + 1
        elif source.startswith("/*", offset):
            end = source.find("*/", offset + 2)
            offset = len(source) if end < 0 else end + 2
        else:
            break
    return offset


def _matching_paren(source: str, opening: int) -> int | None:
    depth = 0
    quote: str | None = None
    escaped = False
    offset = opening
    while offset < len(source):
        char = source[offset]
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif char in "\"'":
            quote = char
        elif source.startswith("//", offset):
            newline = source.find("\n", offset + 2)
            offset = len(source) if newline < 0 else newline
        elif source.startswith("/*", offset):
            end = source.find("*/", offset + 2)
            offset = len(source) if end < 0 else end + 1
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return offset
        offset += 1
    return None


def source_preamble(source: str, names: set[str]) -> str:
    """Keep declarations/data preceding the first recovered function body."""
    earliest = len(source)
    for name in names:
        for match in re.finditer(rf"\b{re.escape(name)}\s*\(", source):
            opening = source.find("(", match.start())
            closing = _matching_paren(source, opening)
            if closing is None:
                continue
            after = _skip_space_and_comments(source, closing + 1)
            if after < len(source) and source[after] == "{":
                line_start = source.rfind("\n", 0, match.start()) + 1
                earliest = min(earliest, line_start)
                break
    if earliest == len(source):
        includes = [line for line in source.splitlines() if line.lstrip().startswith("#include")]
        return "\n".join(includes) + ("\n" if includes else "")
    return source[:earliest].rstrip() + "\n"


def isolate_synthetic_types(text: str, function_name: str) -> str:
    suffix = re.sub(r"[^A-Za-z0-9_]", "_", function_name)
    names = sorted(set(_SYNTHETIC_TYPE.findall(text)), key=len, reverse=True)
    for name in names:
        text = re.sub(rf"\b{re.escape(name)}\b", f"{name}_{suffix}", text)
    return text


def preserve_source_entry_statements(
    generated: str, original: str, function_name: str
) -> str:
    span = function_source_span(original, function_name)
    if not span:
        return generated
    source_body = original[span[0]:span[1]]
    statements = re.findall(
        r"(?m)^[ \t]*(\(void\)\s+[A-Za-z_][A-Za-z0-9_]*\s*;)[ \t]*$",
        source_body,
    )
    statements = [statement for statement in statements if statement not in generated]
    if not statements:
        return generated
    definition = re.search(
        rf"\b{re.escape(function_name)}\s*\([^;{{}}]*\)\s*\{{", generated
    )
    if not definition:
        return generated
    insertion = "\n" + "\n".join(f"  {statement}" for statement in statements)
    return generated[:definition.end()] + insertion + generated[definition.end():]


def render_unit(
    unit: ProjectUnit,
    functions: Sequence[FunctionSymbol],
    outputs: dict[str, str],
    command: Sequence[str],
) -> tuple[str, list[str]]:
    original = unit.source.read_text(encoding="utf-8", errors="replace")
    names = {function.name for function in functions}
    preamble = source_preamble(original, names)
    missing = [function.name for function in functions if function.name not in outputs]

    lines = [
        "/* Recovered by Ember from the retail object.",
        f" * objdiff unit: {unit.name}",
        f" * original source: {unit.source}",
        " * The original file was not modified.",
        " */",
        "",
        preamble.rstrip(),
        "",
    ]
    for function in functions:
        body = outputs.get(function.name)
        if body is None:
            lines.append(f"/* Missing recovery for {function.name}. */\n")
            continue
        body = isolate_synthetic_types(body, function.name).strip()
        body = preserve_source_entry_statements(body, original, function.name)
        lines.extend((
            f"/* {function.name}: object offset 0x{function.address:x}, "
            f"size 0x{function.size:x} */",
            body,
            "",
        ))
    mask = _code_mask(preamble)
    brace_balance = sum(
        1 if char == "{" else -1 if char == "}" else 0
        for char, is_code in zip(preamble, mask) if is_code
    )
    if brace_balance > 0:
        lines.extend("}" for _ in range(brace_balance))
        lines.append("")
    lines.extend((
        "/* Recovery command:",
        " * " + " ".join(command),
        " */",
        "",
    ))
    return "\n".join(lines), missing


def _atomic_write(path: pathlib.Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".tmp.{os.getpid()}")
    temporary.write_text(text, encoding="utf-8")
    temporary.replace(path)


def _count_diff_items(value: Any) -> int:
    if isinstance(value, dict):
        return (1 if "diff_kind" in value else 0) + sum(
            _count_diff_items(item) for item in value.values()
        )
    if isinstance(value, list):
        return sum(_count_diff_items(item) for item in value)
    return 0


def _summarize_objdiff(report: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    left = report.get("left") if isinstance(report.get("left"), dict) else {}
    right = report.get("right") if isinstance(report.get("right"), dict) else {}
    left_symbols = left.get("symbols") if isinstance(left.get("symbols"), list) else []
    right_symbols = right.get("symbols") if isinstance(right.get("symbols"), list) else []
    right_by_name = {
        item.get("name"): item for item in right_symbols
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    functions: list[dict[str, Any]] = []
    data: list[dict[str, Any]] = []
    for item in left_symbols:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            continue
        name = item["name"]
        candidate = right_by_name.get(name)
        target_symbol = item.get("target_symbol")
        if isinstance(target_symbol, (int, str)):
            target_index = _parse_number(target_symbol)
            if 0 <= target_index < len(right_symbols) and isinstance(
                right_symbols[target_index], dict
            ):
                candidate = right_symbols[target_index]
        kind = item.get("kind")
        target_size = _parse_number(item.get("size"))
        candidate_size = _parse_number(candidate.get("size")) if isinstance(candidate, dict) else 0
        if kind == "SYMBOL_FUNCTION":
            match = float(item.get("match_percent", 0.0))
            functions.append({
                "name": name,
                "match_percent": match,
                "exact": candidate is not None and match >= 100.0 and target_size == candidate_size,
                "target_size": target_size,
                "candidate_size": candidate_size,
                "diff_items": _count_diff_items(item.get("instructions", [])),
            })
        elif kind == "SYMBOL_OBJECT" and not name.startswith("["):
            differences = _count_diff_items(item.get("data_diff", []))
            match = float(item.get("match_percent", 0.0))
            data.append({
                "name": name,
                "match_percent": match,
                "exact": candidate is not None and target_size == candidate_size and match >= 100.0,
                "target_size": target_size,
                "candidate_size": candidate_size,
                "diff_items": differences,
            })
    return functions, data


def _write_verification(
    directory: pathlib.Path,
    report: dict[str, Any],
    functions: Sequence[dict[str, Any]],
    data: Sequence[dict[str, Any]],
    project: pathlib.Path,
    unit: ProjectUnit,
) -> None:
    exact_functions = sum(bool(item["exact"]) for item in functions)
    exact_data = sum(bool(item["exact"]) for item in data)
    report["functions"] = list(functions)
    report["data"] = list(data)
    report["function_count"] = len(functions)
    report["exact_function_count"] = exact_functions
    report["data_count"] = len(data)
    report["exact_data_count"] = exact_data
    report["exact"] = (
        bool(functions or data) and exact_functions == len(functions) and exact_data == len(data)
    )
    _atomic_write(
        directory / "verification.json",
        json.dumps(report, indent=2, sort_keys=True) + "\n",
    )

    nonmatching_functions = sorted(
        (item for item in functions if not item["exact"]),
        key=lambda item: (float(item["match_percent"]), item["name"]),
        reverse=True,
    )
    nonmatching_data = [item for item in data if not item["exact"]]
    queue = {
        "schema": 1,
        "project": str(project),
        "unit": unit.name,
        "functions": [
            {
                "symbol": item["name"],
                "match_percent": item["match_percent"],
                "command": [
                    "ember-match", "--project", str(project), "--unit", unit.name,
                    "--symbol", item["name"], "--auto", "--output-dir",
                    str(directory / "matches" / item["name"]),
                ],
            }
            for item in nonmatching_functions if _IDENT.fullmatch(item["name"])
        ],
        "data": nonmatching_data,
    }
    _atomic_write(directory / "matcher-queue.json", json.dumps(queue, indent=2) + "\n")
    _atomic_write(
        directory / "matcher-symbols.txt",
        "".join(f"{item['name']}\n" for item in nonmatching_functions),
    )

    lines = [
        f"CodeWarrior unit verification: {unit.name}",
        f"compile: {'passed' if report.get('compile_ok') else 'failed'}",
        f"objdiff: {'passed' if report.get('objdiff_ok') else 'failed'}",
        f"functions exact: {exact_functions}/{len(functions)}",
        f"data exact: {exact_data}/{len(data)}",
        f"whole object exact: {'yes' if report['exact'] else 'no'}",
    ]
    for item in nonmatching_functions[:20]:
        lines.append(f"  {item['name']}: {item['match_percent']:.6f}%")
    _atomic_write(directory / "verification.txt", "\n".join(lines) + "\n")


def verify_unit(
    *,
    project: pathlib.Path,
    unit: ProjectUnit,
    source: pathlib.Path,
    directory: pathlib.Path,
    objdiff: pathlib.Path,
    ninja: str,
    compile_command: str | None,
    timeout: float,
) -> tuple[bool, bool]:
    marker = directory / ".ember-unit-verification.json"
    identity = {
        "schema": 1,
        "project": str(project),
        "unit": unit.name,
        "source": str(source),
    }
    if directory.exists() and any(directory.iterdir()) and not marker.is_file():
        raise UnitError(f"refusing non-empty unmarked verification directory: {directory}")
    directory.mkdir(parents=True, exist_ok=True)
    if marker.is_file() and json.loads(marker.read_text(encoding="utf-8")) != identity:
        raise UnitError(f"verification directory belongs to another run: {directory}")
    _atomic_write(marker, json.dumps(identity, indent=2) + "\n")

    if compile_command:
        template = shlex.split(compile_command)
        if not any("{source}" in token for token in template):
            raise UnitError("--compile-command must contain {source}")
        if not any("{object}" in token or "{object_dir}" in token for token in template):
            raise UnitError("--compile-command must contain {object} or {object_dir}")
    else:
        template = infer_compile_argv(ninja, project, unit)
    compile_source = directory / unit.source.name
    _atomic_write(compile_source, source.read_text(encoding="utf-8"))
    candidate_object = directory / f"{unit.source.stem}.o"
    compile_argv = materialize_compile_argv(
        template, project, unit.source, compile_source, candidate_object
    )
    compile_result = _run(compile_argv, project, timeout)
    _atomic_write(
        directory / "compile.log", compile_result.stdout + compile_result.stderr
    )
    diagnostic_text = compile_result.stdout + compile_result.stderr
    diagnostics = [
        line.strip() for line in diagnostic_text.splitlines()
        if "error" in line.lower() or "warning" in line.lower()
    ]
    verification: dict[str, Any] = {
        "schema": 1,
        "project": str(project),
        "unit": unit.name,
        "source": str(source),
        "compile_source": str(compile_source),
        "candidate_object": str(candidate_object),
        "compile_command": compile_argv,
        "compile_returncode": compile_result.returncode,
        "compile_ok": compile_result.returncode == 0 and candidate_object.is_file(),
        "compile_diagnostics": diagnostics,
        "objdiff_ok": False,
    }
    if not verification["compile_ok"]:
        gaps = sorted(set(
            match.group(1)
            for line in diagnostics
            for match in [re.search(
                r"(?:unknown type name|undeclared identifier|not declared).*?['\"`]([^'\"`]+)",
                line,
            )]
            if match
        ))
        verification["header_or_annotation_gaps"] = gaps
        _write_verification(directory, verification, [], [], project, unit)
        return False, False

    diff_path = directory / "objdiff.json"
    objdiff_argv = [
        str(objdiff), "--no-color", "diff", "-1", str(unit.target_object),
        "-2", str(candidate_object), "-o", str(diff_path), "--format", "json",
    ]
    diff_result = _run(objdiff_argv, project, timeout)
    _atomic_write(directory / "objdiff.log", diff_result.stdout + diff_result.stderr)
    verification["objdiff_command"] = objdiff_argv
    verification["objdiff_returncode"] = diff_result.returncode
    verification["objdiff_ok"] = diff_result.returncode == 0 and diff_path.is_file()
    if not verification["objdiff_ok"]:
        _write_verification(directory, verification, [], [], project, unit)
        return False, False
    try:
        diff_report = json.loads(diff_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise UnitError(f"could not read objdiff verification: {error}") from error
    functions, data = _summarize_objdiff(diff_report)
    _write_verification(directory, verification, functions, data, project, unit)
    return True, bool(verification.get("exact"))


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=pathlib.Path, required=True,
                        help="DTK/objdiff project directory")
    parser.add_argument("--unit", required=True, help="unit name from objdiff.json")
    parser.add_argument("--version", default="EU0")
    parser.add_argument("--output", type=pathlib.Path,
                        help="write the recovered source here (default: stdout)")
    parser.add_argument("--source", type=pathlib.Path,
                        help="override metadata.source_path")
    parser.add_argument("--ember", type=pathlib.Path)
    parser.add_argument("--objdiff", type=pathlib.Path)
    parser.add_argument("--headers", type=pathlib.Path, action="append", default=[])
    parser.add_argument("--header-arg", action="append", default=[])
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--batch-size", type=int, default=24,
                        help="functions per Ember process (default: 24)")
    parser.add_argument("--verify", action="store_true",
                        help="compile the recovered unit and produce whole-object objdiff feedback")
    parser.add_argument("--verify-dir", type=pathlib.Path,
                        help="verification artifacts (default: OUTPUT.verify)")
    parser.add_argument("--ninja", default="ninja")
    parser.add_argument(
        "--compile-command",
        help="override compiler command with {source}, {object}, {object_dir}, and {project}",
    )
    parser.add_argument("--fail-unmatched", action="store_true",
                        help="with --verify, return 1 unless every function/data object is exact")
    parser.add_argument("--strict", action="store_true",
                        help="fail if Ember cannot recover any object function")
    parser.add_argument("--quiet", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_args(argv or sys.argv[1:])
    try:
        project = arguments.project.expanduser().resolve()
        unit = load_project_unit(project, arguments.unit, arguments.source)
        objdiff = _tool(arguments.objdiff, project, "objdiff-cli")
        ember = _tool(arguments.ember, project, "ember")
        functions = load_function_symbols(
            objdiff, project, arguments.unit, arguments.timeout
        )
        if arguments.batch_size < 1:
            raise UnitError("--batch-size must be at least 1")
        command = [
            str(ember), "--dtk", str(project), "--version", arguments.version,
            "-q", "-p", "--symbols", "<generated-manifest>",
        ]
        for header in arguments.headers:
            command.extend(("--headers", str(header.expanduser().resolve())))
        for header_arg in arguments.header_arg:
            command.extend(("--header-arg", header_arg))
        outputs: dict[str, str] = {}
        batch_failures: dict[str, str] = {}
        with tempfile.TemporaryDirectory(prefix="ember-unit-") as directory:
            temporary = pathlib.Path(directory)
            batch_number = 0

            def recover_batch(batch: Sequence[FunctionSymbol]) -> None:
                nonlocal batch_number
                manifest = temporary / f"symbols-{batch_number:04d}.txt"
                batch_number += 1
                manifest.write_text(
                    "".join(f"{function.name}\n" for function in batch),
                    encoding="utf-8",
                )
                actual_command = list(command)
                actual_command[actual_command.index("<generated-manifest>")] = str(manifest)
                result = _run(actual_command, project, arguments.timeout)
                if result.returncode != 0:
                    # Some large functions expose shared-batch state bugs even
                    # though they decompile correctly alone. Bisect a failed
                    # batch so one bad grouping cannot hide the rest of a unit.
                    if len(batch) > 1:
                        middle = len(batch) // 2
                        recover_batch(batch[:middle])
                        recover_batch(batch[middle:])
                        return
                    detail = result.stderr.strip().splitlines()
                    suffix = detail[-1] if detail else f"exit {result.returncode}"
                    batch_failures[batch[0].name] = suffix
                    return
                outputs.update(split_batch_output(result.stdout))

            for start in range(0, len(functions), arguments.batch_size):
                recover_batch(functions[start:start + arguments.batch_size])
        rendered, missing = render_unit(unit, functions, outputs, command)
        if arguments.strict and missing:
            details = [
                f"{name} ({batch_failures[name]})" if name in batch_failures else name
                for name in missing[:8]
            ]
            raise UnitError(
                f"{len(missing)} function(s) were not recovered: {', '.join(details)}"
            )
        output_path = arguments.output.expanduser().resolve() if arguments.output else None
        if output_path is None:
            sys.stdout.write(rendered)
        else:
            _atomic_write(output_path, rendered)
        if not arguments.quiet:
            destination = str(output_path) if output_path else "stdout"
            print(
                f"ember-unit: recovered {len(functions) - len(missing)}/{len(functions)} "
                f"function(s) from {arguments.unit} -> {destination}",
                file=sys.stderr,
            )
        if arguments.verify:
            if output_path is None:
                raise UnitError("--verify requires --output")
            verify_dir = (
                arguments.verify_dir.expanduser().resolve()
                if arguments.verify_dir
                else output_path.with_name(output_path.name + ".verify")
            )
            completed, exact = verify_unit(
                project=project,
                unit=unit,
                source=output_path,
                directory=verify_dir,
                objdiff=objdiff,
                ninja=arguments.ninja,
                compile_command=arguments.compile_command,
                timeout=arguments.timeout,
            )
            if not arguments.quiet:
                print(
                    f"ember-unit: verification {'complete' if completed else 'failed'}; "
                    f"exact={'yes' if exact else 'no'} -> {verify_dir}",
                    file=sys.stderr,
                )
            if not completed or (arguments.fail_unmatched and not exact):
                return 1
        return 0 if not missing else 1
    except (MatchError, UnitError, OSError, ValueError) as error:
        print(f"ember-unit: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
