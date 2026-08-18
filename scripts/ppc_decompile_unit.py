#!/usr/bin/env python3
"""Recover every function in an objdiff unit as one project-aware C source file."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from typing import Any, Sequence


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from ppc_match_loop import MatchError, ProjectUnit, load_project_unit  # noqa: E402


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


def _run(argv: Sequence[str], cwd: pathlib.Path, timeout: float) -> subprocess.CompletedProcess[str]:
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
        lines.extend((
            f"/* {function.name}: object offset 0x{function.address:x}, size 0x{function.size:x} */",
            body,
            "",
        ))
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
        if arguments.output is None:
            sys.stdout.write(rendered)
        else:
            _atomic_write(arguments.output.expanduser().resolve(), rendered)
        if not arguments.quiet:
            destination = str(arguments.output) if arguments.output else "stdout"
            print(
                f"ember-unit: recovered {len(functions) - len(missing)}/{len(functions)} "
                f"function(s) from {arguments.unit} -> {destination}",
                file=sys.stderr,
            )
        return 0 if not missing else 1
    except (MatchError, UnitError, OSError, ValueError) as error:
        print(f"ember-unit: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
