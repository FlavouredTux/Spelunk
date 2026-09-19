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

By default the script compiles each source into an ELF shared library at
`-O0` and `-O2`. It saves pseudo-C and C exports, recompiles the exports at
both optimization levels, and compares their results with the native library using boundary
values and deterministic random inputs. The record checks compare the whole
memory buffer, including guard words on both sides.

For a broader compiler sweep or a reproducible new batch of inputs:

```sh
python3 scripts/pseudocode_samples.py --cc clang --optimizations 0 1 2 3 s \
  --seed 42 --random-cases 1000 --output build/pseudo-clang-42
```

Each execution comparison runs in a separate process with a 30-second timeout.
A crash or hang is recorded as a failure, and the remaining samples still run.

Results are written to `build/pseudocode-samples/`. Each sample directory
contains `native.so`, `signatures.ann`, `pseudo.c`, `exported.c` when export
succeeds, and the recompiled libraries. `report.json` records failures and
the number of cases checked. Outputs are retained for inspection.

These checks supply function signatures explicitly to test body recovery.
They do not measure automatic signature inference. Only recompiled C exports
are executed; the separate pseudo-C files are for inspection.

CTest runs this as `pseudocode_samples_semantics` on Linux x86-64 at `-O0`,
`-O1`, `-O2`, `-O3`, and `-Os`. When Clang is installed,
`pseudocode_samples_clang_semantics` repeats the sweep with Clang. Both tests
fail on a mismatch, crash, timeout, or failed export. The samples cover signed
division, signed-byte returns, switch declarations, partial-register writes,
and assignments on conditional paths into shared return blocks.
