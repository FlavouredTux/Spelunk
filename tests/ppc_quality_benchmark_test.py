#!/usr/bin/env python3
"""Unit tests for the dependency-free PPC quality metric parser."""

from __future__ import annotations

import importlib.util
import pathlib
import sys


def load_module(path: pathlib.Path):
    spec = importlib.util.spec_from_file_location("ppc_quality_benchmark", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: ppc_quality_benchmark_test.py SCRIPT")
    benchmark = load_module(pathlib.Path(sys.argv[1]))
    sample = """\
void func_80100000(double a1, void* a2) {
  float t3 = ppc.fmadds(f1_2, *(float*)(r2 - 4), f3);
  sub_80001234(t3);
  a2->field_10 = (float)f1_2;
  // STRUCTURER_FAIL: dropped block
}
"""
    function = benchmark.analyze_pseudo_c("func_80100000", sample)
    metrics = function["metrics"]
    assert metrics["lines_of_pseudo_c"] == 5
    assert metrics["raw_register_references"] == 4
    assert metrics["versioned_ssa_references"] == 2
    assert metrics["temporary_references"] == 2
    assert metrics["opaque_ppc_intrinsics"] == 1
    assert metrics["generic_parameters"] == 2
    assert metrics["generic_field_references"] == 1
    assert metrics["unresolved_symbol_calls"] == 1
    assert metrics["structurer_failures"] == 1

    totals = benchmark.aggregate([function])
    baseline = dict(totals)
    baseline["opaque_ppc_intrinsics"] = 2
    baseline["generic_parameters"] = 1
    comparison = benchmark.compare_totals(totals, baseline)
    assert comparison["improvements"] == ["opaque_ppc_intrinsics"]
    assert comparison["regressions"] == ["generic_parameters"]

    timings = benchmark.parse_timings("""\
[timing]   cfg_build: 1.250 ms
[timing]   emit: 0.500 ms
[timing]   cfg_build: 0.750 ms
""")
    assert timings == {"cfg_build": 2.0, "emit": 0.5}
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
