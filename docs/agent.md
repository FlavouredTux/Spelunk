# Agent harness

`agent/` is a TypeScript multi-agent harness that drives assistant (or
GPT, or any OpenRouter-fronted model) against the ember CLI to do
reverse-engineering work. It is **not** invoked from `ember(1)` — it
ships as a sibling component (`ember-agent`).

The orchestrator is **you** (or whatever LLM session is talking to the
user). The harness only ships single-role *workers*. You decide which
workers to spawn, on which scope, with which budget, then read the
shared intel database to consume their output.

## Components

```
agent/
  src/llm/         Provider adapters: assistant, openai, openrouter
  src/tools/       Typed tool defs that subprocess `ember`
  src/intel/       JSONL claim log + materialized view + disputes
  src/roles/       Role system prompts (mapper/namer/typer/tiebreaker)
  src/worker.ts    Single-role tool-use loop with budget cap
  src/main.ts      CLI: worker | intel | runs
```

## Build

```sh
cd agent
npm install
npm run build
node dist/main.js --help
```

## Configuration

API keys via env vars or `~/.config/ember/agent.toml`:

```toml
[assistant]
key = "sk-ant-..."

[openai]
key = "sk-..."

[openrouter]
key = "sk-or-..."
```

Env vars (`assistant_API_KEY`, `OPENAI_API_KEY`, `OPENROUTER_API_KEY`)
override the toml. Ember binary is auto-discovered (build/cli/ember,
build/ember, $PATH); override with `EMBER_BIN`.

## Roles

| Role        | Default model              | Job |
|-------------|----------------------------|-----|
| namer       | deepseek/deepseek-v4-flash | Propose function names from TEEF + strings + xrefs |
| mapper      | deepseek/deepseek-v4-flash | Tag call-graph clusters by theme |
| typer       | deepseek/deepseek-v4-flash | Infer struct field layouts from access patterns |
| tiebreaker  | deepseek/deepseek-v4-flash | Resolve disputed claims, no agent-bias |

Override with `--model=...`. assistant models route to the assistant
SDK directly (for prompt caching); `vendor/model` style routes through
OpenRouter; bare names route to OpenAI.

## Intel database

Append-only JSONL at `$XDG_CACHE_HOME/ember/<binary-key>/intel.jsonl`.
One line per entry:

```json
{"kind":"claim","id":"...","agent":"namer-r-7f3a","ts":"...","subject":"0x4012a0","predicate":"name","value":"parse_header","evidence":"teef:0.97 whole-exact","confidence":0.97}
{"kind":"retract","id":"...","agent":"tiebreaker-r-9c1","ts":"...","target_id":"...","reason":"verified against decompile"}
```

The materialized view is a fold: per `(subject, predicate)`, drop
retracted claims, then max-confidence wins (recency tiebreak). Two
high-confidence claims from different agents within 0.10 confidence
of each other surface as a **dispute**.

Subject conventions:
- Function: `0x4012a0` (lowercase hex with `0x`)
- String: `string:0x4d3010`
- Struct: `struct:s12`
- Global: `global:0x6b0040`

Predicates: `name`, `type`, `note`, `tag`, `xref`, `signature`.

## CLI

```sh
# Spawn a namer worker on one function, in-process (blocks):
ember-agent worker --role=namer --binary=./target.elf \
  --scope=fn:0x4012a0 --budget=0.20

# Same but detached — returns run-id and exits immediately:
ember-agent worker --role=namer --binary=./target.elf \
  --scope=fn:0x4012a0 --budget=0.20 --detach

# Read intel:
ember-agent intel ./target.elf query    --subject=0x4012a0 --predicate=name
ember-agent intel ./target.elf evidence --subject=0x4012a0
ember-agent intel ./target.elf disputes

# Manual claim (e.g. you, the orchestrator, deciding):
ember-agent intel ./target.elf claim \
  --subject=0x4012a0 --predicate=name --value=parse_header \
  --evidence="manual review" --confidence=0.95 --agent-id=human

# Run management:
ember-agent runs list
ember-agent runs status r-7f3a
ember-agent runs tail   r-7f3a
```

### Fanout

Spawn N detached workers in one shot:

```sh
ember-agent fanout --binary=./target.elf --pick=unnamed \
  --limit=20 --min-size=16 --budget=0.05 --max-turns=12

# --pick=all       every fn ember reports
# --pick=unnamed   only sub_* (skip already-named symbols)
# --pick=list:0x401000,0x401200,...  explicit list
# Returns JSON with run-ids; each worker writes its own events.jsonl.
```

### Anchor Cascade

The TEEF-equivalent for agentic naming. Single-pass swarms treat
each function as an island; the agent looking at `sub_a` sees calls
to `sub_b` and `sub_c` rendered as `sub_b()`/`sub_c()` — opaque,
no anchors to bootstrap from.

Cascade exploits ember's emit-time annotation lookup: re-rendering
pseudo-C after a `promote` is essentially free, so we run the swarm
in rounds with `promote --apply` between them. Each round's agents
see strictly more named neighbors than the prior round's.

```sh
ember-agent cascade --binary=./target.elf \
  --per-round=30 --max-rounds=5 \
  --budget=0.05 --threshold=0.85 \
  --eligibility-ratio=0.5 \
  --model=deepseek/deepseek-v4-flash
```

Eligibility per round: a function is eligible iff
`known_callees / total_callees >= --eligibility-ratio`. PLT thunks
and named symbols count as known; intel claims with confidence ≥
`--threshold` count as known. Leaves (zero callees) are eligible
from round 0.

The loop terminates when a round produces zero new high-confidence
names — every remaining unknown is genuinely too obscured for the
swarm to crack with the current corpus. Round-by-round stats
(eligible / spawned / new_names / cost / elapsed) print to stderr;
the JSON result on stdout has the per-round breakdown plus totals.

Expected behavior on a 7000-fn stripped binary: ~5-10% named in
round 0 (anchored leaves and TEEF-seeded fns), another 15-20% in
round 1, asymptote 50-70% over a few rounds. Bad-faith targets
(libloader-style obfuscated runtime plumbing where naming from
pseudo-C alone is genuinely impossible) terminate after round 0
with the "wasted runs" stat surfaced in the UI.

### Promote

Fold the intel view into a `.ember` script and (optionally) apply it
back to the binary's annotation file so the next `ember -p` shows the
agent-supplied names:

```sh
# Generate the script only (default at <binary>.intel.ember):
ember-agent promote ./target.elf --threshold=0.85

# Generate + apply (writes annotations.db):
ember-agent promote ./target.elf --apply

# Generate + dry-run (shows TSV diff without writing):
ember-agent promote ./target.elf --dry-run
```

Filter rules:
- skip disputed (orchestrator should resolve via tiebreaker first)
- skip below `--threshold` (default 0.85)
- only `name` → `[rename]` and `note` → `[note]` are promotable today.
  `type`/`tag`/`xref` stay agent-internal until ember grows the
  matching script surface.

## Orchestration patterns

**Bulk naming.** Take the output of `ember --recognize` at threshold
0.85, find the gaps (functions where TEEF gave nothing), spawn one
namer per gap with `--detach`. Each namer reads strings + decompile +
caller patterns, files a claim. After they finish, read the intel
view; promote high-confidence claims into the annotations file via
`.ember` script.

**Tiebreaker on disputes.** Two namers disagreeing on the same fn
surfaces as a dispute. Spawn `--role=tiebreaker --scope=disputes`;
the worker reads `intel_disputes`, picks the first, resolves it.

**Map-then-name.** One mapper worker first to tag clusters, then
namer workers on the boundaries of the most interesting clusters.

## Cost guardrails

`--budget=N` (USD) is enforced per-worker. The tally counts:
- assistant: input + output + cache read + cache write at published rates
- OpenAI / OpenRouter: input + output (no cache surfaced)

A worker exits cleanly when `usd >= budget`. There is no global cap
across workers — that's the orchestrator's responsibility.

## What's left

- Daemon mode: long-lived `ember --serve` answering tool calls over a
  socket. Current subprocess-per-call is ~50ms cold + the cache hits
  on subsequent calls. Painful at thousands of calls; fine at hundreds.
- UI panel that surfaces disputes + lets the user resolve them
  manually as a `human` agent-id.
- assistant-direct path verification: `cache_control` is wired but
  hasn't been exercised end-to-end (Max plan ≠ API access). Once a
  user runs the harness with an assistant API key, validate that
  `cache_creation_input_tokens` / `cache_read_input_tokens` show up
  in the tally as expected.
- Retry/backoff on transient 429/5xx from any provider — currently a
  flaky upstream kills the worker.

## Tests

`npm test` runs the suite. Currently covers:
- `intel/log.test.ts` — fold semantics, retraction, dispute detection,
  same-agent self-supersede, value-equal non-dispute, id uniqueness.
- `promote.test.ts` — high-conf rename emission, disputed-skip,
  rename/note section split, value sanitization (`#` and newline).
