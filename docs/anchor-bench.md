# Anchor Bench

Anchor Bench is Ember's benchmark for evaluating reverse-engineering
agents on grounded binary naming tasks.

The benchmark asks an agent to recover semantic names for selected
functions in stripped or partially stripped binaries. The agent can use
Ember tools such as pseudo-C, strings, xrefs, callees, recognition, and
intel claims. The scorer compares final `name` claims against hidden
truth derived from debug symbols, PDBs, source builds, or curated aliases.

The key measurement is not just "can a model name one function?" It is
whether anchors compound:

1. name leaves and functions with imported/runtime anchors;
2. promote high-confidence names;
3. re-render pseudo-C with richer callee/caller names;
4. measure whether later rounds improve accuracy, abstention, and cost.

The initial harness lives in `benchmarks/anchor-bench/`. The checked-in
`seed.v0` manifest is only a smoke test. Public development runs should use
`hard.v1`; production scores should still come from a private split as
described in `benchmarks/anchor-bench/HARD.md`.

```sh
node benchmarks/anchor-bench/run.mjs \
  --manifest benchmarks/anchor-bench/manifests/hard.v1.json \
  --model x-ai/grok-4.1-fast \
  --per-round 3 \
  --max-rounds 2 \
  --budget 0.08
```

Before running `hard.v1`, stage stripped fixture copies:

```sh
node benchmarks/anchor-bench/prepare-hard-v1.mjs
```

Score-only mode:

```sh
node benchmarks/anchor-bench/score.mjs \
  --manifest benchmarks/anchor-bench/manifests/hard.v1.json
```

The static website lives at `benchmarks/anchor-bench/site/index.html`.
It visualizes utility, accuracy, hallucinations, cost, latency, and the
hardness bands that a real held-out split should contain.

## Reported Metrics

- `accuracy`: overall pass rate. Expected abstentions count as correct
  behavior.
- `name_accuracy`: exact normalized match rate on named targets only.
- `points`: strict v0 utility score. Correct is `+1 * weight`;
  missing/disputed is `0`; wrong is `-1 * weight`, with an extra penalty
  for wrong high-confidence claims.
- `utility`: points divided by maximum possible weighted points.
- `hallucinated`: high-confidence names on targets marked `expect: "abstain"`.
- `cost`: reported by the agent run and retained in cascade output.
- `latency`: reported per cascade round.

Hard splits should include negative targets, no-string targets, deep anchor
chains, C++ virtual methods, multiple optimization levels, and private
debug/PDB truth. Future benchmark revisions should add semantic equivalence
judging and calibration curves.
