# Making Anchor Bench Hard

Anchor Bench should be a hard evaluation, not a demo. A useful score must
survive models that are already excellent at source-code reasoning and tool
use. The benchmark should therefore test grounded binary understanding under
conditions where confident guessing is expensive.

## Hardness Requirements

1. **Held-out truth**
   - Release only stripped binaries and target addresses.
   - Keep source, debug symbols, PDBs, and canonical names private until after
     scoring.
   - Do not include target names in file paths, strings, section names, or
     manifest IDs.

2. **Anchor dependency**
   - Include call chains where a parent is only nameable after callees are
     named.
   - Report `single-pass` and `cascade` separately.
   - Include an `oracle-anchors` upper-bound split later, where true callee
     names are preloaded to quantify remaining model weakness.

3. **Negative targets**
   - Include compiler/runtime thunks, low-signal wrappers, packed stubs, and
     deliberately ambiguous utility functions.
   - Score abstention as correct for these targets.
   - Penalize high-confidence semantic hallucinations heavily.

4. **Cross-toolchain matrix**
   - Compile the same source under multiple compilers, optimization levels,
     link modes, and symbol stripping strategies.
   - Suggested minimum matrix:
     - GCC/Clang: `-O0`, `-O2`, `-Os`, LTO on/off;
     - MSVC/clang-cl: `/O2`, PDB present for truth, stripped binary for eval;
     - ELF, PE, Mach-O where practical.

5. **No string-only shortcut**
   - Include some functions with useful strings.
   - Include many functions where strings are absent, indirect, shared, or
     misleading.
   - Track tags such as `strings`, `no-strings`, `xref-only`, `callee-only`,
     `rtti`, `indirect-call`, and `negative`.

6. **Budget pressure**
   - Fix per-target or per-round budgets.
   - Report cost, latency, turns, and claims filed.
   - A model that gets a high score by spending 100x more should not silently
     compare equal.

## Difficulty Bands

`smoke`
: Repo-local fixtures that validate harness behavior. Not leaderboard data.

`medium`
: Functions nameable from direct imports, local strings, or obvious arithmetic.

`hard`
: Functions requiring caller/callee context, multiple tool calls, or recovered
  anchors from earlier rounds.

`expert`
: C++ virtual methods, indirect-call-heavy code, state-machine handlers,
  allocator/container internals, or cross-function protocol logic.

`negative`
: Targets where the right behavior is no high-confidence name claim.

## Scoring Policy

Targets may set:

- `canonical`: required semantic name.
- `aliases`: acceptable normalized equivalents.
- `expect: "abstain"`: no high-confidence name should be filed.
- `weight`: default `1`; use `2` or `3` for hard/expert cases.
- `difficulty`: copied into reports for per-band analysis.
- `tags`: copied into reports for slice analysis.

Current v0 scoring:

- correct name: `+1 * weight`;
- missing/disputed name target: `0`;
- wrong name: `-1 * weight`;
- wrong high-confidence name: extra `-0.5 * weight`;
- correct abstention target: `+1 * weight`;
- hallucinated abstention target: `-2 * weight`.

This makes the benchmark hostile to "always guess" agents.

## Suggested Public Result Table

Report at least:

- model and provider;
- Ember commit;
- benchmark manifest version;
- mode: `single-pass`, `cascade`, or future `oracle-anchors`;
- target count and difficulty mix;
- accuracy;
- utility score;
- hallucination count;
- total cost and wall time.

Example:

```text
model                  mode         targets  acc   utility  halluc  cost
x-ai/grok-4.1-fast     single-pass  500      31%   0.18     74      $1.92
x-ai/grok-4.1-fast     cascade      500      46%   0.35     51      $2.44
assistant-sonnet-X        cascade      500      ...   ...      ...     ...
```

## Dataset Construction Plan

1. Build a small private `hard.v0` split from 5-10 OSS projects with debug
   symbols retained separately.
2. Select target functions by graph shape, not by name: leaves, depth-2/3
   parents, high fan-in utilities, virtual methods, and negative thunks.
3. Strip binaries and verify the truth names are not visible through `strings`.
4. Run `single-pass` and `cascade` with the same model and budget.
5. Publish aggregate scores first; publish full manifests only after the split
   is retired.
