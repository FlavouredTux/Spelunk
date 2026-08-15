#!/usr/bin/env python3
"""Search controlled source variants with CodeWarrior and objdiff.

The matcher never edits the input source or decompilation project.  It expands
an explicit set of source alternatives, compiles every candidate in an
isolated directory, asks objdiff for a machine-readable report, and preserves
the highest-scoring source/object pair with a reproducible JSON report.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import hashlib
import itertools
import json
import math
import os
import pathlib
import shlex
import shutil
import subprocess
import sys
import time
from typing import Any, Sequence


class MatchError(RuntimeError):
    """A user-actionable matching workflow error."""


@dataclasses.dataclass(frozen=True)
class Alternative:
    name: str
    text: str


@dataclasses.dataclass(frozen=True)
class Choice:
    name: str
    category: str
    start: int
    end: int
    alternatives: tuple[Alternative, ...]


@dataclasses.dataclass(frozen=True)
class Candidate:
    candidate_id: str
    source: str
    selections: tuple[tuple[str, str], ...]
    changed_choices: int


@dataclasses.dataclass(frozen=True)
class ProjectUnit:
    name: str
    target_object: pathlib.Path
    base_object: pathlib.Path
    source: pathlib.Path


def _read_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise MatchError(f"cannot read {path}: {error}") from error
    if not isinstance(value, dict):
        raise MatchError(f"{path}: expected a JSON object")
    return value


def _atomic_write(path: pathlib.Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    temporary.write_text(text, encoding="utf-8")
    os.replace(temporary, path)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
    except OSError as error:
        raise MatchError(f"cannot hash {path}: {error}") from error
    return digest.hexdigest()


def _command_artifacts(argv: Sequence[str], cwd: pathlib.Path) -> dict[str, str]:
    artifacts: dict[str, str] = {}
    for token in argv:
        if "{" in token or token.startswith("-"):
            continue
        path = pathlib.Path(token)
        if not path.is_absolute():
            path = cwd / path
        if not path.is_file():
            continue
        resolved = path.resolve()
        if os.access(resolved, os.X_OK) or resolved.suffix.lower() in {".exe", ".py"}:
            artifacts[str(resolved)] = _sha256_file(resolved)
    return artifacts


def _resolve_project_path(project: pathlib.Path, value: str, label: str) -> pathlib.Path:
    path = pathlib.Path(value)
    if not path.is_absolute():
        path = project / path
    path = path.resolve()
    if not path.is_file():
        raise MatchError(f"{label} does not exist: {path}")
    return path


def load_project_unit(
    project: pathlib.Path,
    unit_name: str,
    source_override: pathlib.Path | None = None,
    target_override: pathlib.Path | None = None,
    base_override: pathlib.Path | None = None,
) -> ProjectUnit:
    config_path = next(
        (
            project / name
            for name in ("objdiff.json", "objdiff.yml", "objdiff.yaml")
            if (project / name).is_file()
        ),
        None,
    )
    if config_path is None:
        raise MatchError(f"objdiff project configuration not found in {project}")
    if config_path.suffix != ".json":
        raise MatchError("the matching loop currently requires objdiff.json")
    config = _read_json(config_path)
    units = config.get("units")
    if not isinstance(units, list):
        raise MatchError(f"{config_path}: missing units array")
    unit = next(
        (item for item in units if isinstance(item, dict) and item.get("name") == unit_name),
        None,
    )
    if unit is None:
        raise MatchError(f"objdiff unit not found: {unit_name}")

    target_value = target_override or unit.get("target_path")
    base_value = base_override or unit.get("base_path")
    metadata = unit.get("metadata") if isinstance(unit.get("metadata"), dict) else {}
    source_value = source_override or metadata.get("source_path")
    if target_value is None:
        raise MatchError(f"objdiff unit {unit_name} has no target_path")
    if base_value is None:
        raise MatchError(f"objdiff unit {unit_name} has no base_path")
    if source_value is None:
        raise MatchError(f"objdiff unit {unit_name} has no metadata.source_path; pass --source")

    def resolve(value: pathlib.Path | str, label: str) -> pathlib.Path:
        return _resolve_project_path(project, str(value), label)

    return ProjectUnit(
        name=unit_name,
        target_object=resolve(target_value, "target object"),
        base_object=resolve(base_value, "base object"),
        source=resolve(source_value, "source"),
    )


def _occurrences(text: str, needle: str) -> list[int]:
    positions: list[int] = []
    start = 0
    while True:
        at = text.find(needle, start)
        if at < 0:
            return positions
        positions.append(at)
        start = at + max(1, len(needle))


def _parse_alternative(raw: Any, index: int) -> Alternative:
    if isinstance(raw, str):
        return Alternative(f"alternative-{index}", raw)
    if not isinstance(raw, dict) or not isinstance(raw.get("text"), str):
        raise MatchError("each alternative must be a string or an object with a text string")
    name = raw.get("name", f"alternative-{index}")
    if not isinstance(name, str) or not name:
        raise MatchError("alternative names must be non-empty strings")
    return Alternative(name, raw["text"])


def load_choices(spec_path: pathlib.Path, source: str) -> list[Choice]:
    spec = _read_json(spec_path)
    if spec.get("version") != 1:
        raise MatchError(f"{spec_path}: unsupported or missing version (expected 1)")
    raw_choices = spec.get("choices")
    if not isinstance(raw_choices, list) or not raw_choices:
        raise MatchError(f"{spec_path}: choices must be a non-empty array")

    choices: list[Choice] = []
    names: set[str] = set()
    for raw in raw_choices:
        if not isinstance(raw, dict):
            raise MatchError("each choice must be a JSON object")
        name = raw.get("name")
        find = raw.get("find")
        category = raw.get("category", "expression")
        if not isinstance(name, str) or not name:
            raise MatchError("each choice needs a non-empty name")
        if name in names:
            raise MatchError(f"duplicate choice name: {name}")
        names.add(name)
        if not isinstance(find, str) or not find:
            raise MatchError(f"choice {name}: find must be a non-empty string")
        if not isinstance(category, str) or not category:
            raise MatchError(f"choice {name}: category must be a non-empty string")
        positions = _occurrences(source, find)
        occurrence = raw.get("occurrence")
        if occurrence is None:
            if len(positions) != 1:
                raise MatchError(
                    f"choice {name}: find occurs {len(positions)} times; set a 1-based occurrence"
                )
            start = positions[0]
        else:
            if not isinstance(occurrence, int) or occurrence < 1:
                raise MatchError(f"choice {name}: occurrence must be a positive integer")
            if occurrence > len(positions):
                raise MatchError(
                    f"choice {name}: occurrence {occurrence} exceeds {len(positions)} match(es)"
                )
            start = positions[occurrence - 1]

        raw_alternatives = raw.get("alternatives")
        if not isinstance(raw_alternatives, list) or not raw_alternatives:
            raise MatchError(f"choice {name}: alternatives must be a non-empty array")
        alternatives = [Alternative("original", find)]
        alternatives.extend(
            _parse_alternative(item, i + 1) for i, item in enumerate(raw_alternatives)
        )
        deduplicated: list[Alternative] = []
        seen_text: set[str] = set()
        seen_names: set[str] = set()
        for alternative in alternatives:
            if alternative.text in seen_text:
                continue
            if alternative.name in seen_names:
                raise MatchError(f"choice {name}: duplicate alternative name {alternative.name}")
            seen_text.add(alternative.text)
            seen_names.add(alternative.name)
            deduplicated.append(alternative)
        choices.append(
            Choice(name, category, start, start + len(find), tuple(deduplicated))
        )

    by_start = sorted(choices, key=lambda choice: choice.start)
    for left, right in zip(by_start, by_start[1:]):
        if left.end > right.start:
            raise MatchError(f"choices {left.name} and {right.name} overlap")
    return choices


def expand_candidates(source: str, choices: Sequence[Choice], maximum: int) -> list[Candidate]:
    combination_count = math.prod(len(choice.alternatives) for choice in choices)
    if combination_count > maximum:
        raise MatchError(
            f"spec expands to {combination_count} candidates, above --max-candidates {maximum}"
        )
    candidates: dict[str, Candidate] = {}
    for selected in itertools.product(*(choice.alternatives for choice in choices)):
        transformed = source
        replacements = sorted(zip(choices, selected), key=lambda item: item[0].start, reverse=True)
        for choice, alternative in replacements:
            transformed = transformed[: choice.start] + alternative.text + transformed[choice.end :]
        candidate_id = _sha256_bytes(transformed.encode("utf-8"))[:12]
        selections = tuple(
            (choice.name, alternative.name) for choice, alternative in zip(choices, selected)
        )
        changed = sum(alternative.name != "original" for alternative in selected)
        candidates.setdefault(
            candidate_id, Candidate(candidate_id, transformed, selections, changed)
        )
    return sorted(candidates.values(), key=lambda candidate: candidate.candidate_id)


def _split_command(command: str) -> list[list[str]]:
    tokens = shlex.split(command, posix=True)
    segments: list[list[str]] = [[]]
    for token in tokens:
        if token == "&&":
            segments.append([])
        else:
            segments[-1].append(token)
    return [segment for segment in segments if segment]


def infer_compile_argv(
    ninja: str,
    project: pathlib.Path,
    unit: ProjectUnit,
) -> list[str]:
    try:
        target = str(unit.base_object.relative_to(project))
    except ValueError:
        target = str(unit.base_object)
    process = subprocess.run(
        [ninja, "-C", str(project), "-t", "commands", target],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if process.returncode != 0:
        detail = process.stderr.strip() or process.stdout.strip()
        raise MatchError(f"ninja could not expose the compile command: {detail}")
    source_resolved = unit.source.resolve()
    for line in process.stdout.splitlines():
        for segment in _split_command(line):
            if "-c" not in segment:
                continue
            index = segment.index("-c")
            if index + 1 >= len(segment):
                continue
            source_arg = pathlib.Path(segment[index + 1])
            if not source_arg.is_absolute():
                source_arg = project / source_arg
            if source_arg.resolve() == source_resolved:
                return segment
    raise MatchError(f"could not identify the compiler command for {unit.source}")


def materialize_compile_argv(
    template: Sequence[str],
    project: pathlib.Path,
    original_source: pathlib.Path,
    candidate_source: pathlib.Path,
    candidate_object: pathlib.Path,
) -> list[str]:
    mapping = {
        "project": str(project),
        "source": str(candidate_source),
        "object": str(candidate_object),
        "object_dir": str(candidate_object.parent),
        "original_source": str(original_source),
    }
    if any("{" in token for token in template):
        try:
            return [token.format_map(mapping) for token in template]
        except KeyError as error:
            raise MatchError(f"unknown compile-command placeholder: {error.args[0]}") from error

    argv = list(template)
    try:
        source_index = argv.index("-c") + 1
    except ValueError as error:
        raise MatchError("inferred compiler command has no -c input") from error
    argv[source_index] = str(candidate_source)
    if "-o" not in argv:
        raise MatchError("inferred compiler command has no -o output")
    output_index = argv.index("-o") + 1
    old_output = pathlib.Path(argv[output_index])
    argv[output_index] = str(
        candidate_object if old_output.suffix == ".o" else candidate_object.parent
    )
    return argv


def _tool_path(explicit: pathlib.Path | None, project: pathlib.Path, name: str) -> pathlib.Path:
    if explicit is not None:
        path = explicit.expanduser().resolve()
        if not path.is_file():
            raise MatchError(f"{name} executable does not exist: {path}")
        return path
    project_tool = project / "build" / "tools" / name
    if project_tool.is_file():
        return project_tool.resolve()
    found = shutil.which(name)
    if found:
        return pathlib.Path(found).resolve()
    option = "--objdiff" if name == "objdiff-cli" else f"--{name.replace('_', '-')}"
    raise MatchError(f"could not find {name}; pass {option}")


def _run_process(
    argv: Sequence[str], cwd: pathlib.Path, timeout: float
) -> tuple[int, str, str, float]:
    started = time.monotonic()
    try:
        process = subprocess.run(
            list(argv),
            cwd=cwd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        return process.returncode, process.stdout, process.stderr, time.monotonic() - started
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout.decode() if isinstance(error.stdout, bytes) else (error.stdout or "")
        stderr = error.stderr.decode() if isinstance(error.stderr, bytes) else (error.stderr or "")
        return 124, stdout, stderr + f"\ntimed out after {timeout:g}s", time.monotonic() - started


def _score_report(report: dict[str, Any], symbol: str) -> dict[str, Any]:
    units = report.get("units")
    if not isinstance(units, list) or len(units) != 1 or not isinstance(units[0], dict):
        raise MatchError("objdiff report did not contain exactly one unit")
    functions = units[0].get("functions")
    if not isinstance(functions, list):
        raise MatchError("objdiff report did not contain function results")
    matches = [item for item in functions if isinstance(item, dict) and item.get("name") == symbol]
    if len(matches) != 1:
        raise MatchError(f"objdiff report contains {len(matches)} entries for symbol {symbol}")
    function = matches[0]
    fuzzy = float(function.get("fuzzy_match_percent", 0.0))
    size = int(function.get("size", 0))
    measures = units[0].get("measures") if isinstance(units[0].get("measures"), dict) else {}
    return {
        "match_percent": fuzzy,
        "exact": fuzzy >= 100.0,
        "target_size": size,
        "candidate_size": size,
        "size_delta": 0,
        "diff_items": None,
        "unit_matched_code_percent": float(measures.get("matched_code_percent", 0.0)),
        "unit_fuzzy_match_percent": float(measures.get("fuzzy_match_percent", 0.0)),
    }


def _score_oneshot_diff(report: dict[str, Any], symbol: str) -> dict[str, Any]:
    def find_symbol(side_name: str) -> dict[str, Any]:
        side = report.get(side_name)
        symbols = side.get("symbols") if isinstance(side, dict) else None
        if not isinstance(symbols, list):
            raise MatchError(f"objdiff one-shot report has no {side_name} symbols")
        matches = [
            item for item in symbols if isinstance(item, dict) and item.get("name") == symbol
        ]
        if len(matches) != 1:
            raise MatchError(
                f"objdiff one-shot report contains {len(matches)} {side_name} entries for {symbol}"
            )
        return matches[0]

    target = find_symbol("left")
    candidate = find_symbol("right")
    match = float(target.get("match_percent", 0.0))
    target_size = int(target.get("size", 0))
    candidate_size = int(candidate.get("size", 0))
    instructions = target.get("instructions")
    diff_items = (
        sum(1 for item in instructions if isinstance(item, dict) and "diff_kind" in item)
        if isinstance(instructions, list)
        else 0
    )
    return {
        "match_percent": match,
        "exact": match >= 100.0 and target_size == candidate_size,
        "target_size": target_size,
        "candidate_size": candidate_size,
        "size_delta": candidate_size - target_size,
        "diff_items": diff_items,
        "unit_matched_code_percent": match,
        "unit_fuzzy_match_percent": match,
    }


def objdiff_supports_oneshot(objdiff: pathlib.Path) -> bool:
    try:
        process = subprocess.run(
            [str(objdiff), "diff", "--help"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=10,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return False
    return (
        process.returncode == 0
        and "--output" in process.stdout
        and "--format" in process.stdout
    )


def _candidate_rank(result: dict[str, Any]) -> tuple[float, float, float, int, str]:
    score = result.get("score") if isinstance(result.get("score"), dict) else {}
    return (
        1.0 if score.get("exact") else 0.0,
        float(score.get("match_percent", -1.0)),
        float(score.get("unit_fuzzy_match_percent", -1.0)),
        -int(result.get("changed_choices", 0)),
        str(result.get("candidate_id", "")),
    )


def _prepare_output_directory(output: pathlib.Path, run_identity: dict[str, Any]) -> None:
    marker = output / ".ember-match-run.json"
    if output.exists() and not output.is_dir():
        raise MatchError(f"output path is not a directory: {output}")
    if output.exists() and any(output.iterdir()) and not marker.is_file():
        raise MatchError(f"refusing to use non-empty unmarked output directory: {output}")
    output.mkdir(parents=True, exist_ok=True)
    if marker.is_file():
        previous = _read_json(marker)
        if previous != run_identity:
            raise MatchError(
                f"{output} belongs to a different match run; choose another --output-dir"
            )
    else:
        _atomic_write(marker, json.dumps(run_identity, indent=2, sort_keys=True) + "\n")


def _evaluate_candidate(
    candidate: Candidate,
    *,
    output: pathlib.Path,
    project: pathlib.Path,
    original_source: pathlib.Path,
    target_object: pathlib.Path,
    compile_template: Sequence[str],
    objdiff: pathlib.Path,
    oneshot_objdiff: bool,
    symbol: str,
    timeout: float,
    line_directive: bool,
) -> dict[str, Any]:
    directory = output / "candidates" / candidate.candidate_id
    result_path = directory / "result.json"
    source_path = directory / f"candidate{original_source.suffix}"
    compile_source_path = directory / original_source.name
    object_path = directory / f"{original_source.stem}.o"
    if result_path.is_file():
        cached = _read_json(result_path)
        if cached.get("candidate_id") == candidate.candidate_id:
            cached["cached"] = True
            return cached

    directory.mkdir(parents=True, exist_ok=True)
    source_text = candidate.source
    if line_directive:
        try:
            display_source = original_source.relative_to(project).as_posix()
        except ValueError:
            display_source = original_source.name
        source_text = f'#line 1 "{display_source}"\n' + source_text
    _atomic_write(source_path, candidate.source)
    _atomic_write(compile_source_path, source_text)
    compile_argv = materialize_compile_argv(
        compile_template, project, original_source, compile_source_path, object_path
    )
    compile_rc, compile_stdout, compile_stderr, compile_seconds = _run_process(
        compile_argv, project, timeout
    )
    _atomic_write(directory / "compile.log", compile_stdout + compile_stderr)
    result: dict[str, Any] = {
        "candidate_id": candidate.candidate_id,
        "selections": dict(candidate.selections),
        "changed_choices": candidate.changed_choices,
        "source_sha256": _sha256_bytes(candidate.source.encode("utf-8")),
        "compile_command": compile_argv,
        "compile_returncode": compile_rc,
        "compile_seconds": round(compile_seconds, 6),
        "source_path": str(source_path),
        "compile_source_path": str(compile_source_path),
        "object_path": str(object_path),
        "cached": False,
    }
    if compile_rc != 0 or not object_path.is_file():
        result["error"] = (
            "candidate did not compile" if compile_rc else "compiler produced no object"
        )
        _atomic_write(result_path, json.dumps(result, indent=2, sort_keys=True) + "\n")
        return result

    report_path = directory / "objdiff-report.json"
    if oneshot_objdiff:
        objdiff_argv = [
            str(objdiff),
            "--no-color",
            "diff",
            "-1",
            str(target_object),
            "-2",
            str(object_path),
            "-o",
            str(report_path),
            "--format",
            "json",
            symbol,
        ]
    else:
        objdiff_config = {
            "min_version": "2.0.0-beta.5",
            "build_base": False,
            "build_target": False,
            "units": [
                {
                    "name": "candidate",
                    "target_path": str(target_object),
                    "base_path": str(object_path),
                    "metadata": {"progress_categories": ["match"]},
                }
            ],
        }
        _atomic_write(directory / "objdiff.json", json.dumps(objdiff_config, indent=2) + "\n")
        objdiff_argv = [
            str(objdiff),
            "--no-color",
            "report",
            "generate",
            "-p",
            str(directory),
            "-o",
            str(report_path),
            "-f",
            "json",
        ]
    diff_rc, diff_stdout, diff_stderr, diff_seconds = _run_process(
        objdiff_argv, project, timeout
    )
    _atomic_write(directory / "objdiff.log", diff_stdout + diff_stderr)
    result["objdiff_command"] = objdiff_argv
    result["objdiff_returncode"] = diff_rc
    result["objdiff_seconds"] = round(diff_seconds, 6)
    result["objdiff_report_path"] = str(report_path)
    if diff_rc != 0 or not report_path.is_file():
        result["error"] = "objdiff report failed" if diff_rc else "objdiff produced no report"
    else:
        try:
            report = _read_json(report_path)
            result["score"] = (
                _score_oneshot_diff(report, symbol)
                if oneshot_objdiff
                else _score_report(report, symbol)
            )
        except MatchError as error:
            result["error"] = str(error)
    _atomic_write(result_path, json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def _write_summary(
    output: pathlib.Path,
    symbol: str,
    results: Sequence[dict[str, Any]],
    best: dict[str, Any] | None,
) -> None:
    lines = [f"CodeWarrior match search: {symbol}", f"candidates: {len(results)}"]
    successful = [item for item in results if isinstance(item.get("score"), dict)]
    lines.append(f"compiled and scored: {len(successful)}")
    if best is None:
        lines.append("best: none")
    else:
        score = best["score"]
        lines.extend(
            [
                f"best candidate: {best['candidate_id']}",
                f"function match: {score['match_percent']:.6f}%",
                f"exact: {'yes' if score['exact'] else 'no'}",
                f"changed choices: {best['changed_choices']}",
            ]
        )
        for name, selection in sorted(best["selections"].items()):
            lines.append(f"  {name}: {selection}")
    _atomic_write(output / "summary.txt", "\n".join(lines) + "\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Compile controlled CodeWarrior source variants and rank them with objdiff."
    )
    parser.add_argument(
        "--project", type=pathlib.Path, required=True, help="objdiff project directory"
    )
    parser.add_argument("--unit", required=True, help="unit name from objdiff.json")
    parser.add_argument("--symbol", required=True, help="function symbol to score")
    parser.add_argument("--spec", type=pathlib.Path, required=True, help="version-1 variant JSON")
    parser.add_argument("--output-dir", type=pathlib.Path, required=True)
    parser.add_argument("--source", type=pathlib.Path, help="override metadata.source_path")
    parser.add_argument("--target-object", type=pathlib.Path)
    parser.add_argument("--base-object", type=pathlib.Path)
    parser.add_argument("--objdiff", type=pathlib.Path)
    parser.add_argument("--ninja", default="ninja")
    parser.add_argument(
        "--compile-command",
        help=(
            "explicit command with {source}, {object}, {object_dir}, {project}, "
            "and {original_source}"
        ),
    )
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument(
        "--timeout", type=float, default=120.0, help="seconds per compiler/objdiff process"
    )
    parser.add_argument("--max-candidates", type=int, default=256)
    parser.add_argument("--no-line-directive", action="store_true")
    parser.add_argument(
        "--keep-diffs",
        action="store_true",
        help="retain every full objdiff JSON result instead of only the best",
    )
    parser.add_argument(
        "--fail-unmatched",
        action="store_true",
        help="return 1 unless the best function is exact",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="expand and validate without compiling"
    )
    parser.add_argument("--quiet", action="store_true")
    return parser


def run(arguments: argparse.Namespace) -> int:
    project = arguments.project.expanduser().resolve()
    if not project.is_dir():
        raise MatchError(f"project directory does not exist: {project}")
    if arguments.jobs < 1:
        raise MatchError("--jobs must be at least 1")
    if arguments.timeout <= 0:
        raise MatchError("--timeout must be positive")
    if arguments.max_candidates < 1:
        raise MatchError("--max-candidates must be at least 1")

    source_override = arguments.source.expanduser().resolve() if arguments.source else None
    target_override = (
        arguments.target_object.expanduser().resolve() if arguments.target_object else None
    )
    base_override = arguments.base_object.expanduser().resolve() if arguments.base_object else None
    unit = load_project_unit(
        project, arguments.unit, source_override, target_override, base_override
    )
    try:
        source_text = unit.source.read_text(encoding="utf-8")
    except OSError as error:
        raise MatchError(f"cannot read {unit.source}: {error}") from error
    spec_path = arguments.spec.expanduser().resolve()
    choices = load_choices(spec_path, source_text)
    candidates = expand_candidates(source_text, choices, arguments.max_candidates)
    if not arguments.quiet:
        print(
            f"ember-match: {len(choices)} choice(s), {len(candidates)} unique candidate(s), "
            f"symbol {arguments.symbol}"
        )
    if arguments.dry_run:
        for candidate in candidates:
            print(f"{candidate.candidate_id}\t{dict(candidate.selections)}")
        return 0

    objdiff = _tool_path(arguments.objdiff, project, "objdiff-cli")
    oneshot_objdiff = objdiff_supports_oneshot(objdiff)
    if arguments.compile_command:
        compile_template = shlex.split(arguments.compile_command)
        if not any("{source}" in token for token in compile_template):
            raise MatchError("--compile-command must contain {source}")
        if not any("{object}" in token or "{object_dir}" in token for token in compile_template):
            raise MatchError("--compile-command must contain {object} or {object_dir}")
    else:
        compile_template = infer_compile_argv(arguments.ninja, project, unit)

    output = arguments.output_dir.expanduser().resolve()
    run_identity = {
        "schema": 1,
        "project": str(project),
        "unit": unit.name,
        "symbol": arguments.symbol,
        "source": str(unit.source),
        "source_sha256": _sha256_bytes(source_text.encode("utf-8")),
        "spec": str(spec_path),
        "spec_sha256": _sha256_file(spec_path),
        "target_object": str(unit.target_object),
        "target_sha256": _sha256_file(unit.target_object),
        "compile_template": list(compile_template),
        "compile_artifacts": _command_artifacts(compile_template, project),
        "objdiff": str(objdiff),
        "objdiff_sha256": _sha256_file(objdiff),
        "matcher_sha256": _sha256_file(pathlib.Path(__file__).resolve()),
        "line_directive": not arguments.no_line_directive,
    }
    _prepare_output_directory(output, run_identity)

    evaluate = lambda candidate: _evaluate_candidate(
        candidate,
        output=output,
        project=project,
        original_source=unit.source,
        target_object=unit.target_object,
        compile_template=compile_template,
        objdiff=objdiff,
        oneshot_objdiff=oneshot_objdiff,
        symbol=arguments.symbol,
        timeout=arguments.timeout,
        line_directive=not arguments.no_line_directive,
    )
    results: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=arguments.jobs) as executor:
        future_map = {executor.submit(evaluate, candidate): candidate for candidate in candidates}
        for future in concurrent.futures.as_completed(future_map):
            candidate = future_map[future]
            try:
                result = future.result()
            except Exception as error:  # Preserve other candidates and a useful report.
                result = {
                    "candidate_id": candidate.candidate_id,
                    "selections": dict(candidate.selections),
                    "changed_choices": candidate.changed_choices,
                    "error": f"internal candidate failure: {error}",
                }
            results.append(result)
            if not arguments.quiet:
                if isinstance(result.get("score"), dict):
                    score = result["score"]
                    suffix = " exact" if score["exact"] else ""
                    cached = " cached" if result.get("cached") else ""
                    print(
                        f"ember-match: {candidate.candidate_id} "
                        f"{score['match_percent']:.6f}%{suffix}{cached}"
                    )
                else:
                    print(f"ember-match: {candidate.candidate_id} failed: {result.get('error')}")

    results.sort(key=lambda item: str(item.get("candidate_id", "")))
    scored = [item for item in results if isinstance(item.get("score"), dict)]
    best = max(scored, key=_candidate_rank) if scored else None
    report = {
        "schema": 1,
        "project": str(project),
        "unit": unit.name,
        "symbol": arguments.symbol,
        "candidate_count": len(results),
        "scored_count": len(scored),
        "best_candidate_id": best.get("candidate_id") if best else None,
        "best_exact": bool(best and best["score"]["exact"]),
        "results": sorted(results, key=_candidate_rank, reverse=True),
    }
    _atomic_write(output / "results.json", json.dumps(report, indent=2, sort_keys=True) + "\n")
    _write_summary(output, arguments.symbol, results, best)
    if best is not None:
        shutil.copy2(best["source_path"], output / f"best{unit.source.suffix}")
        shutil.copy2(best["object_path"], output / "best.o")
        best_diff = pathlib.Path(best.get("objdiff_report_path", ""))
        if best_diff.is_file():
            shutil.copy2(best_diff, output / "best.objdiff.json")
        if not arguments.quiet:
            print(
                f"ember-match: best {best['candidate_id']} "
                f"{best['score']['match_percent']:.6f}% -> {output}"
            )
    if not arguments.keep_diffs:
        for result in results:
            report_path = pathlib.Path(result.get("objdiff_report_path", ""))
            if report_path.is_file():
                report_path.unlink()
    if best is None:
        return 1
    if arguments.fail_unmatched and not best["score"]["exact"]:
        return 1
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    try:
        return run(parser.parse_args(argv))
    except MatchError as error:
        print(f"ember-match: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
