#!/usr/bin/env python3
"""Unit tests for the dependency-free PPC quality metric parser."""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import tempfile


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
  sub_80001234(t3); /* unresolved target 0x80001234 */
  a2->field_10 = (float)f1_2;
  // STRUCTURER_FAIL: dropped block
  if (!0) sub_80001234(PTR(0x1234));
  uint32_t value = {0}; /* unresolved SSA merge */
  a2->field_10 = a2->field_10;
}
"""
    function = benchmark.analyze_pseudo_c("func_80100000", sample)
    metrics = function["metrics"]
    assert metrics["lines_of_pseudo_c"] == 8
    assert metrics["raw_register_references"] == 4
    assert metrics["versioned_ssa_references"] == 2
    assert metrics["temporary_references"] == 2
    assert metrics["opaque_ppc_intrinsics"] == 1
    assert metrics["generic_parameters"] == 2
    assert metrics["generic_field_references"] == 3
    assert metrics["unresolved_symbol_calls"] == 1
    assert metrics["structurer_failures"] == 1
    assert metrics["constant_condition_artifacts"] == 1
    assert metrics["unresolved_ssa_merges"] == 1
    assert metrics["unresolved_expression_materializations"] == 0
    assert metrics["raw_pointer_literals"] == 1
    assert metrics["self_assignment_artifacts"] == 1
    assert metrics["semantic_expectation_failures"] == 0
    assert metrics["syntax_failures"] == 0

    pluswin = benchmark.analyze_pseudo_c("pluswinMain", """\
typedef struct PpcNavigationEntry { void (*callback)(void); } PpcNavigationEntry;
typedef struct PpcDataEntry { float float_0; } PpcDataEntry;
void pluswinMain(void) {
  table[i].callback(&table[i]);
  entry = work->entryIds[i];
  x = entries[entry].originalPos.x;
  entries[entry].flags &= ~0x10;
  if (OSTicksToMilliseconds(gp->time - pausewin_pluswinWp->openingTime) <= 500) {}
}
""")
    assert pluswin["metrics"]["semantic_expectation_failures"] == 0
    broken_pluswin = benchmark.analyze_pseudo_c(
        "pluswinMain", "void pluswinMain(void) { __div2i(carry_add(a, b)); }\n")
    assert broken_pluswin["metrics"]["semantic_expectation_failures"] == 9

    split = benchmark.split_batch_output("""\
// spelunk-symbol: first
void first(void) {}\n
// spelunk-symbol: second
void second(void) {}\n
""")
    assert split == {
        "first": "void first(void) {}\n\n",
        "second": "void second(void) {}\n\n",
    }
    with tempfile.TemporaryDirectory() as directory:
        manifest = pathlib.Path(directory) / "roundtrip.tsv"
        manifest.write_text(
            "data\tmapData\tMapData *[468]\n"
            "evt\tlbl_80415e04\n",
            encoding="utf-8",
        )
        assert benchmark.load_roundtrip_manifest(manifest) == [
            ("data", "mapData", "MapData *[468]"),
            ("evt", "lbl_80415e04", ""),
        ]

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
    assert benchmark.check_syntax("void ok(void) {}\n", "clang", 5.0) is None
    assert benchmark.check_syntax("void broken( {\n", "clang", 5.0) is not None
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
