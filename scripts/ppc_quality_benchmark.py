#!/usr/bin/env python3
"""Measure pseudo-C quality over a stable PowerPC function corpus."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import subprocess
import sys
import time
from typing import Any, Iterable


SCHEMA_VERSION = 2
LOWER_IS_BETTER = (
    "raw_register_references",
    "versioned_ssa_references",
    "temporary_references",
    "opaque_ppc_intrinsics",
    "generic_parameters",
    "generic_field_references",
    "unresolved_symbol_calls",
    "structurer_failures",
    "constant_condition_artifacts",
    "unresolved_ssa_merges",
    "unresolved_expression_materializations",
    "raw_pointer_literals",
    "self_assignment_artifacts",
    "semantic_expectation_failures",
    "syntax_failures",
)

_RAW_REGISTER = re.compile(r"\b(?:r(?:[0-9]|[12][0-9]|3[01])|f(?:[0-9]|[12][0-9]|3[01]))(?:_[0-9]+)?\b")
_VERSIONED_SSA = re.compile(r"\b(?:r(?:[0-9]|[12][0-9]|3[01])|f(?:[0-9]|[12][0-9]|3[01]))_[0-9]+\b")
_TEMPORARY = re.compile(r"\bt[0-9]+\b")
_OPAQUE_PPC = re.compile(r"\bppc\.[A-Za-z0-9_.]+\s*\(")
_GENERIC_PARAMETER = re.compile(r"\ba[0-9]+\b")
_GENERIC_FIELD = re.compile(r"(?:->|\.)field_[0-9a-fA-F]+\b")
_UNRESOLVED_CALL = re.compile(r"/\*\s*unresolved target\b")
_CONSTANT_CONDITION = re.compile(
    r"\b(?:if|while)\s*\(\s*!?\s*(?:0|1|true|false)\s*\)"
)
_RAW_POINTER = re.compile(r"\bPTR\s*\(\s*0x[0-9a-fA-F]+\s*\)")
_SELF_ASSIGNMENT = re.compile(r"^\s*(.+?)\s+=\s+\1;\s*$", re.MULTILINE)
_BATCH_MARKER = re.compile(r"^// ember-symbol: (\S+)\s*$")
_TIMING = re.compile(
    r"^\[timing\]\s+(.+?):\s+([0-9]+(?:\.[0-9]+)?)\s+ms$"
)


def parse_timings(stderr: str) -> dict[str, float]:
    timings: dict[str, float] = {}
    for line in stderr.splitlines():
        match = _TIMING.match(line.strip())
        if match is None:
            continue
        label = match.group(1).strip()
        timings[label] = round(timings.get(label, 0.0) + float(match.group(2)), 3)
    return timings


def load_manifest(path: pathlib.Path) -> list[str]:
    symbols: list[str] = []
    seen: set[str] = set()
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        symbol = raw.partition("#")[0].strip()
        if not symbol:
            continue
        if any(char.isspace() for char in symbol):
            raise ValueError(f"{path}:{line_number}: symbol must not contain whitespace")
        if symbol in seen:
            raise ValueError(f"{path}:{line_number}: duplicate symbol {symbol!r}")
        seen.add(symbol)
        symbols.append(symbol)
    if not symbols:
        raise ValueError(f"{path}: manifest contains no symbols")
    return symbols


def load_roundtrip_manifest(path: pathlib.Path) -> list[tuple[str, str, str]]:
    cases: list[tuple[str, str, str]] = []
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.partition("#")[0].strip()
        if not line:
            continue
        fields = [field.strip() for field in line.split("\t")]
        if fields[0] == "evt" and len(fields) == 2 and fields[1]:
            cases.append(("evt", fields[1], ""))
        elif fields[0] == "data" and len(fields) == 3 and fields[1] and fields[2]:
            cases.append(("data", fields[1], fields[2]))
        else:
            raise ValueError(
                f"{path}:{line_number}: expected 'evt<TAB>SYMBOL' or "
                "'data<TAB>SYMBOL<TAB>TYPE'")
    if not cases:
        raise ValueError(f"{path}: round-trip manifest contains no cases")
    return cases


def _code_without_line_comments(text: str) -> str:
    return "\n".join(line.partition("//")[0] for line in text.splitlines())


def analyze_pseudo_c(symbol: str, text: str,
                     syntax_failure: str | None = None) -> dict[str, Any]:
    code = _code_without_line_comments(text)
    code_lines = [line for line in code.splitlines() if line.strip()]
    header_index = next((index for index, line in enumerate(code_lines)
                         if "(" in line and line.rstrip().endswith("{")), -1)
    header = code_lines[header_index] if header_index >= 0 else ""
    parameter_text = header.partition("(")[2].rpartition(")")[0]
    body_code = "\n".join(line for index, line in enumerate(code_lines)
                          if index != header_index)
    semantic_expectation_failures = 0
    if symbol == "pluswinMain":
        semantic_expectation_failures += int("PpcNavigationEntry" not in text)
        semantic_expectation_failures += int(
            re.search(r"\.callback\)*\(&", text) is None)
        semantic_expectation_failures += int(
            "OSTicksToMilliseconds(gp->time - pausewin_pluswinWp->openingTime)"
            not in text)
        semantic_expectation_failures += int("->entryIds[" not in text)
        semantic_expectation_failures += int("].originalPos.x" not in text)
        semantic_expectation_failures += int("].flags &= ~0x10" not in text)
        semantic_expectation_failures += int("PpcDataEntry" not in text)
        semantic_expectation_failures += int("__div2i(" in text)
        semantic_expectation_failures += int("carry_add(" in text)
        semantic_expectation_failures += int("word_1b0" in text)
        semantic_expectation_failures += int("word_f8" in text)
        semantic_expectation_failures += int("0x10624dd3" in text)
        semantic_expectation_failures += int("pausewin_pluswinWp +" in text)
    elif symbol == "pluswinBgDispSub":
        semantic_expectation_failures += int("i++)" not in text)
        semantic_expectation_failures += int("i_2++;" not in text)
        semantic_expectation_failures += int("(float)(int32_t)(i - 2)" not in text)
        semantic_expectation_failures += int("(float)(int32_t)(i_2 - 2)" not in text)

    metrics = {
        "lines_of_pseudo_c": len(code_lines),
        "raw_register_references": len(_RAW_REGISTER.findall(code)),
        "versioned_ssa_references": len(_VERSIONED_SSA.findall(code)),
        "temporary_references": len(_TEMPORARY.findall(code)),
        "opaque_ppc_intrinsics": len(_OPAQUE_PPC.findall(code)),
        "generic_parameters": len(_GENERIC_PARAMETER.findall(parameter_text)),
        "generic_field_references": len(_GENERIC_FIELD.findall(code)),
        "unresolved_symbol_calls": len(_UNRESOLVED_CALL.findall(body_code)),
        "structurer_failures": text.count("STRUCTURER_FAIL"),
        "constant_condition_artifacts": len(_CONSTANT_CONDITION.findall(code)),
        "unresolved_ssa_merges": text.count("unresolved SSA merge"),
        "unresolved_expression_materializations": text.count(
            "unresolved expression materialization"),
        "raw_pointer_literals": len(_RAW_POINTER.findall(code)),
        "self_assignment_artifacts": len(_SELF_ASSIGNMENT.findall(code)),
        "semantic_expectation_failures": semantic_expectation_failures,
        "syntax_failures": int(syntax_failure is not None),
    }
    result: dict[str, Any] = {"symbol": symbol, "metrics": metrics}
    if syntax_failure is not None:
        result["syntax_error"] = syntax_failure
    return result


def aggregate(functions: Iterable[dict[str, Any]]) -> dict[str, int]:
    totals = {"functions": 0, "lines_of_pseudo_c": 0, **{key: 0 for key in LOWER_IS_BETTER}}
    for function in functions:
        totals["functions"] += 1
        for key, value in function["metrics"].items():
            totals[key] += int(value)
    return totals


def normalized(totals: dict[str, int]) -> dict[str, float]:
    lines = totals["lines_of_pseudo_c"]
    if lines == 0:
        return {key: 0.0 for key in LOWER_IS_BETTER}
    return {key: round(1000.0 * totals[key] / lines, 3) for key in LOWER_IS_BETTER}


def compare_totals(current: dict[str, int], baseline: dict[str, int]) -> dict[str, Any]:
    deltas = {key: current[key] - int(baseline.get(key, 0)) for key in LOWER_IS_BETTER}
    regressions = [key for key, delta in deltas.items() if delta > 0]
    improvements = [key for key, delta in deltas.items() if delta < 0]
    return {
        "deltas": deltas,
        "regressions": regressions,
        "improvements": improvements,
    }


def run_function(ember: pathlib.Path, dtk: pathlib.Path, version: str,
                 symbol: str, timeout: float,
                 collect_timings: bool = False,
                 headers: list[pathlib.Path] | None = None,
                 header_args: list[str] | None = None,
                 syntax_compiler: str | None = None) -> tuple[dict[str, Any] | None, str | None]:
    command = [str(ember), "--dtk", str(dtk), "--version", version, "-p", "-s", symbol]
    for path in headers or []:
        command.extend(("--headers", str(path)))
    for argument in header_args or []:
        command.extend(("--header-arg", argument))
    environment = None
    if collect_timings:
        environment = os.environ.copy()
        environment["EMBER_TIMING"] = "1"
    started = time.perf_counter()
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=environment,
        )
    except subprocess.TimeoutExpired:
        return None, f"{symbol}: timed out after {timeout:g}s"
    except OSError as error:
        return None, f"{symbol}: could not execute {ember}: {error}"
    if result.returncode != 0:
        detail = result.stderr.strip().splitlines()
        suffix = detail[-1] if detail else f"exit {result.returncode}"
        return None, f"{symbol}: {suffix}"
    syntax_failure = check_syntax(result.stdout, syntax_compiler, timeout)
    function = analyze_pseudo_c(symbol, result.stdout, syntax_failure)
    if collect_timings:
        timings = parse_timings(result.stderr)
        timings["wall"] = round(1000.0 * (time.perf_counter() - started), 3)
        function["timings_ms"] = timings
    return function, None


def check_syntax(text: str, compiler: str | None,
                 timeout: float) -> str | None:
    if compiler is None:
        return None
    source = "#include <stdint.h>\n#include <stddef.h>\n#include <stdbool.h>\n" + text
    try:
        result = subprocess.run(
            [compiler, "-x", "c", "-std=c11", "-fsyntax-only",
             "-Wno-implicit-function-declaration", "-Wno-int-conversion", "-"],
            input=source, capture_output=True, text=True, timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return f"syntax check timed out after {timeout:g}s"
    except OSError as error:
        return f"could not execute syntax compiler {compiler}: {error}"
    if result.returncode == 0:
        return None
    details = [line.strip() for line in result.stderr.splitlines() if line.strip()]
    return details[0] if details else f"syntax compiler exited {result.returncode}"


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
    return {symbol: "".join(lines) for symbol, lines in outputs.items()}


def run_batch(ember: pathlib.Path, dtk: pathlib.Path, version: str,
              manifest: pathlib.Path, symbols: list[str], timeout: float,
              collect_timings: bool = False,
              headers: list[pathlib.Path] | None = None,
              header_args: list[str] | None = None,
              syntax_compiler: str | None = None
              ) -> tuple[list[dict[str, Any]], list[str], dict[str, float]]:
    command = [str(ember), "--dtk", str(dtk), "--version", version,
               "-q", "-p", "--symbols", str(manifest)]
    for path in headers or []:
        command.extend(("--headers", str(path)))
    for argument in header_args or []:
        command.extend(("--header-arg", argument))
    environment = None
    if collect_timings:
        environment = os.environ.copy()
        environment["EMBER_TIMING"] = "1"
    started = time.perf_counter()
    try:
        result = subprocess.run(
            command, check=False, capture_output=True, text=True,
            timeout=timeout, env=environment,
        )
    except subprocess.TimeoutExpired:
        return [], [f"batch timed out after {timeout:g}s"], {}
    except OSError as error:
        return [], [f"could not execute {ember}: {error}"], {}
    if result.returncode != 0:
        details = result.stderr.strip().splitlines()
        suffix = details[-1] if details else f"exit {result.returncode}"
        return [], [f"batch: {suffix}"], {}
    outputs = split_batch_output(result.stdout)
    functions: list[dict[str, Any]] = []
    failures: list[str] = []
    for symbol in symbols:
        text = outputs.get(symbol)
        if text is None:
            failures.append(f"{symbol}: missing from batch output")
            continue
        syntax_failure = check_syntax(text, syntax_compiler, timeout)
        functions.append(analyze_pseudo_c(symbol, text, syntax_failure))
    timings = parse_timings(result.stderr) if collect_timings else {}
    if collect_timings:
        timings["wall"] = round(1000.0 * (time.perf_counter() - started), 3)
    return functions, failures, timings


def run_roundtrip_cases(ember: pathlib.Path, dtk: pathlib.Path, version: str,
                        cases: list[tuple[str, str, str]], timeout: float,
                        headers: list[pathlib.Path] | None = None,
                        header_args: list[str] | None = None
                        ) -> tuple[dict[str, int], list[str]]:
    passed = 0
    failures: list[str] = []
    for kind, symbol, type_name in cases:
        command = [str(ember), "--dtk", str(dtk), "--version", version,
                   "-q", "--verify-roundtrip"]
        for path in headers or []:
            command.extend(("--headers", str(path)))
        for argument in header_args or []:
            command.extend(("--header-arg", argument))
        if kind == "data":
            command.extend(("--decompile-data", symbol, "--type", type_name))
        else:
            command.extend(("--evt-script", symbol))
        try:
            result = subprocess.run(
                command, check=False, capture_output=True, text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            failures.append(f"round-trip {kind} {symbol}: timed out after {timeout:g}s")
            continue
        except OSError as error:
            failures.append(f"round-trip {kind} {symbol}: {error}")
            continue
        if result.returncode == 0 and "round-trip verified:" in result.stderr:
            passed += 1
            continue
        details = [line.strip() for line in result.stderr.splitlines() if line.strip()]
        suffix = details[-1] if details else f"exit {result.returncode}"
        failures.append(f"round-trip {kind} {symbol}: {suffix}")
    return {"requested": len(cases), "passed": passed}, failures


def make_report(ember: pathlib.Path, dtk: pathlib.Path, version: str,
                manifest: pathlib.Path, symbols: list[str], timeout: float,
                collect_timings: bool = False,
                headers: list[pathlib.Path] | None = None,
                header_args: list[str] | None = None,
                syntax_compiler: str | None = None,
                batch: bool = True) -> dict[str, Any]:
    functions: list[dict[str, Any]] = []
    failures: list[str] = []
    batch_timings: dict[str, float] = {}
    if batch:
        functions, failures, batch_timings = run_batch(
            ember, dtk, version, manifest, symbols, timeout, collect_timings,
            headers, header_args, syntax_compiler)
    else:
        for symbol in symbols:
            function, error = run_function(
                ember, dtk, version, symbol, timeout, collect_timings,
                headers, header_args, syntax_compiler)
            if function is not None:
                functions.append(function)
            if error is not None:
                failures.append(error)
    totals = aggregate(functions)
    report = {
        "schema": SCHEMA_VERSION,
        "target": {"version": version, "manifest": manifest.name},
        "requested_functions": len(symbols),
        "functions": functions,
        "failures": failures,
        "totals": totals,
        "per_1000_lines": normalized(totals),
    }
    if collect_timings:
        timing_totals: dict[str, float] = dict(batch_timings)
        if not batch:
            for function in functions:
                for label, elapsed in function.get("timings_ms", {}).items():
                    timing_totals[label] = round(
                        timing_totals.get(label, 0.0) + float(elapsed), 3)
        report["timings_ms"] = timing_totals
    return report


def print_human(report: dict[str, Any]) -> None:
    totals = report["totals"]
    print(f"PPC pseudo-C quality benchmark ({report['target']['version']})")
    print(f"functions: {totals['functions']}/{report['requested_functions']}  "
          f"lines: {totals['lines_of_pseudo_c']}")
    print("metric\tcount\tper_1000_lines\tdelta")
    comparison = report.get("comparison", {})
    deltas = comparison.get("deltas", {})
    for key in LOWER_IS_BETTER:
        delta = deltas.get(key)
        delta_text = "-" if delta is None else f"{delta:+d}"
        print(f"{key}\t{totals[key]}\t{report['per_1000_lines'][key]:.3f}\t{delta_text}")
    if "timings_ms" in report:
        timings = report["timings_ms"]
        preferred = ("wall", "cfg_build", "ir_lift", "ssa_convert", "cleanup",
                     "type_inference", "structurer", "emit", "emit_pseudo")
        ordered = [label for label in preferred if label in timings]
        ordered.extend(sorted(label for label in timings if label not in ordered))
        print("timing\tms")
        for label in ordered:
            print(f"{label}\t{timings[label]:.3f}")
    if "roundtrip" in report:
        result = report["roundtrip"]
        print(f"round-trip: {result['passed']}/{result['requested']} passed")
    for failure in report["failures"]:
        print(f"error: {failure}", file=sys.stderr)


def parse_args(argv: list[str]) -> argparse.Namespace:
    root = pathlib.Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ember", type=pathlib.Path, default=root / "build/cli/ember")
    parser.add_argument("--dtk", type=pathlib.Path, required=True)
    parser.add_argument("--version", default="EU0")
    parser.add_argument("--manifest", type=pathlib.Path,
                        default=root / "benchmarks/spm_eu0_ppc.txt")
    parser.add_argument("--baseline", type=pathlib.Path)
    parser.add_argument("--fail-on-regression", action="store_true")
    parser.add_argument("--timeout", type=float, default=120.0,
                        help="per-function timeout in seconds (default: 120)")
    parser.add_argument("--timings", action="store_true",
                        help="collect wall-clock and Ember pipeline timings")
    parser.add_argument("--headers", action="append", type=pathlib.Path, default=[],
                        help="header path forwarded to Ember; repeatable")
    parser.add_argument("--header-arg", action="append", default=[],
                        help="header parser argument forwarded to Ember; repeatable")
    parser.add_argument("--syntax-check", action="store_true",
                        help="run clang -fsyntax-only on every pseudo-C function")
    parser.add_argument("--compiler", default="clang",
                        help="compiler used by --syntax-check (default: clang)")
    parser.add_argument("--no-batch", action="store_true",
                        help="run one Ember process per symbol (diagnostic compatibility mode)")
    parser.add_argument("--roundtrip-manifest", type=pathlib.Path,
                        help="also verify typed-data/event cases from a TSV manifest")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    if args.fail_on_regression and args.baseline is None:
        parser.error("--fail-on-regression requires --baseline")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        symbols = load_manifest(args.manifest)
        report = make_report(args.ember, args.dtk, args.version, args.manifest,
                             symbols, args.timeout, args.timings,
                             args.headers, args.header_arg,
                             args.compiler if args.syntax_check else None,
                             not args.no_batch)
        if args.roundtrip_manifest is not None:
            roundtrip_cases = load_roundtrip_manifest(args.roundtrip_manifest)
            report["roundtrip"], roundtrip_failures = run_roundtrip_cases(
                args.ember, args.dtk, args.version, roundtrip_cases, args.timeout,
                args.headers, args.header_arg)
            report["failures"].extend(roundtrip_failures)
        if args.baseline is not None:
            baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
            if baseline.get("schema") != SCHEMA_VERSION:
                raise ValueError(f"{args.baseline}: unsupported benchmark schema")
            report["comparison"] = compare_totals(report["totals"], baseline["totals"])
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        print(f"ppc-quality: {error}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print_human(report)

    if report["failures"]:
        return 2
    if args.fail_on_regression and report["comparison"]["regressions"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
