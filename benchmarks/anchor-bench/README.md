# Anchor Bench

Anchor Bench is a benchmark for tool-using reverse-engineering agents.
It measures whether an agent can recover grounded semantic names for
stripped or partially stripped binary functions, and whether iterative
anchor promotion improves over single-pass naming.

The repo-local fixture manifest is only a smoke test. Public development
scores should use `manifests/hard.v1.json`; production leaderboard scores
should use a held-out hard split; see `HARD.md`.

The benchmark is intentionally simple:

- inputs are binaries plus a manifest of target addresses;
- hidden truth is source/debug-symbol/PDB-derived function names;
- agents interact only through Ember tools;
- outputs are `intel_claim` name claims;
- scoring rewards correct names and abstention, and penalizes confident
  wrong names.

## Modes

`cascade`
: Run `ember-agent cascade` and let high-confidence claims become anchors
  for later rounds.

`single-pass`
: Run one pass of independent workers with no promotion loop. This is the
  baseline that Anchor Cascade should beat on call-heavy binaries.

`oracle-anchors`
: Future mode. Preload selected true callee names to estimate the upper
  bound when anchors are perfect.

## Quick Start

Build Ember and the agent first:

```sh
cmake --build build
cd agent && npm run build && cd ..
node benchmarks/anchor-bench/prepare-hard-v1.mjs
```

Run a tiny one-worker live smoke with OpenRouter:

```sh
node benchmarks/anchor-bench/run.mjs \
  --manifest benchmarks/anchor-bench/manifests/hard.v1.json \
  --model x-ai/grok-4.1-fast \
  --per-round 3 \
  --max-rounds 2 \
  --budget 0.08
```

For single-pass trials, `run.mjs` waits 45 seconds before scoring by default
because fanout workers can finish after the parent command returns. Override
with `--settle-ms` when a model needs more or less time.

Score existing claims without running workers:

```sh
node benchmarks/anchor-bench/score.mjs \
  --manifest benchmarks/anchor-bench/manifests/hard.v1.json
```

Open the static leaderboard site:

```sh
benchmarks/anchor-bench/site/index.html
```

The scripts use `agent/dist/main.js` by default and respect:

- `EMBER_BIN` for the Ember CLI path;
- `XDG_CACHE_HOME` for intel/runs/cache storage;
- `OPENROUTER_API_KEY`, `assistant_API_KEY`, or `~/.config/ember/agent.toml`
  for provider credentials.

`score.mjs` reads Ember's `intel.jsonl` cache directly, so it can score
results even in restricted environments where spawning a nested agent process
is not allowed.

`hard.v1` intentionally points at stripped copies under
`build/anchor-bench/hard-v1/`. Re-run `prepare-hard-v1.mjs` after rebuilding
fixtures so the benchmark does not leak source names through ELF symbols.

Generate report JSON and aggregate leaderboard data:

```sh
node benchmarks/anchor-bench/score.mjs \
  --manifest benchmarks/anchor-bench/manifests/hard.v1.json \
  --model x-ai/grok-4.1-fast \
  --mode cascade \
  --out /tmp/grok-anchor-report.json

node benchmarks/anchor-bench/aggregate.mjs \
  --out /tmp/anchor-leaderboard.json \
  /tmp/grok-anchor-report.json

node benchmarks/anchor-bench/update-site-data.mjs \
  --input /tmp/anchor-leaderboard.json
```

## Manifest Shape

```json
{
  "name": "fixtures.v0",
  "cases": [
    {
      "id": "return_value.gcc-runtime",
      "binary": "build/tests/fixtures/return_value",
      "targets": [
        {
          "address": "0x4010ed",
          "canonical": "__do_global_dtors_aux",
          "aliases": ["do_global_dtors_aux", "global_destructors_aux"],
          "difficulty": "hard",
          "weight": 2
        },
        {
          "address": "0x402000",
          "expect": "abstain",
          "reason": "ambiguous low-signal thunk",
          "difficulty": "negative",
          "weight": 2
        }
      ]
    }
  ]
}
```

Paths are resolved relative to the repository root unless absolute.

## Scoring

For each target:

- exact normalized match against `canonical` or any `aliases`: `+1 * weight`;
- missing claim: `0.0`;
- disputed claim: `0.0`;
- wrong claim: `-1 * weight`;
- wrong high-confidence claim (`confidence >= 0.85`): extra `-0.5 * weight`;
- `expect: "abstain"` with no high-confidence name: `+1 * weight`;
- `expect: "abstain"` with a high-confidence name: `-2 * weight`.

`accuracy` is the overall pass rate, so expected abstentions count as
correct behavior. `name_accuracy` is reported separately for named targets
only. `utility` remains the primary leaderboard sort because it punishes
confident wrong anchors and hallucinated names more heavily than misses.
Normalization lowercases names, removes leading underscores, drops common
compiler suffixes, and compares alphanumeric tokens. The JSON report keeps
the raw prediction so semantic review remains possible.

This is a strict v0 scorer. It is intentionally hostile to "always guess"
agents. Later versions should add semantic equivalence judging, family-level
labels, and calibration curves.

## Dataset Tiers

`fixtures`
: Small repo-local sanity cases. These prove the harness works and catch
  regressions, but are not a meaningful model benchmark.

`oss-stripped`
: Release/debug paired open-source binaries compiled under multiple
  toolchains and optimization levels. Truth comes from unstripped symbols.

`pe-pdb`
: Windows PE binaries where truth comes from PDB names and signatures.

`negative`
: Runtime stubs, obfuscated plumbing, and low-signal functions where the
  correct behavior is a low-confidence note or abstention.
