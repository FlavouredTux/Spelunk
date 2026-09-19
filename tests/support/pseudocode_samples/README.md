# Pseudo-C samples

Small C inputs for inspecting decompiler output and checking its behavior:

- `branches.c`: early returns, a switch, absolute value, and signed division.
- `loops.c`: nested loops, `continue`, early exits, and unsigned arithmetic.
- `records.c`: struct fields, conditional stores, null pointers, and counters.
- `division.c`: signed quotient and remainder, including negative divisors.

From the repository root:

```sh
python3 scripts/pseudocode_samples.py
```

The script compiles each source into an ELF shared library at `-O0` and `-O2`.
It saves pseudo-C and C exports, recompiles the exports at both optimization
levels, and compares their results with the native library using boundary
values and deterministic random inputs. The record checks compare the whole
memory buffer, including guard words on both sides.

Results are written to `build/pseudocode-samples/`. Each sample directory
contains `native.so`, `signatures.ann`, `pseudo.c`, `exported.c` when export
succeeds, and the recompiled libraries. `report.json` records failures and
the number of cases checked. Outputs are retained for inspection.

These checks supply function signatures explicitly to test body recovery.
They do not measure automatic signature inference. Only recompiled C exports
are executed; the separate pseudo-C files are for inspection.

CTest runs this as `pseudocode_samples_semantics` on Linux x86-64. It exits
nonzero on a mismatch or failed export. The branch and record samples cover
previous bugs in signed division and merged return values.
