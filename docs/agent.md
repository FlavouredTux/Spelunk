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

| Role        | Default model       | Job |
|-------------|---------------------|-----|
| namer       | assistant-sonnet-4-6   | Propose function names from TEEF + strings + xrefs |
| mapper      | assistant-sonnet-4-6   | Tag call-graph clusters by theme |
| typer       | assistant-sonnet-4-6   | Infer struct field layouts from access patterns |
| tiebreaker  | assistant-opus-4-7     | Resolve disputed claims, no agent-bias |

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

- N-API binding for in-process ember calls (current subprocess
  overhead is ~50ms per tool call; fine for a few dozen, painful for
  thousands).
- UI panel that surfaces disputes + lets the user resolve them
  manually as a `human` agent-id.
- Annotations bridge: a `--promote` mode that folds the current
  intel view into `.ember` script form so it can be applied to the
  binary's annotation file.
