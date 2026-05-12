import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

import { Codex, type ModelReasoningEffort, type ThreadEvent } from "@openai/codex-sdk";

import { ROLES } from "./roles/index.js";
import type { WorkerArgs } from "./worker.js";

// Codex SDK-driven worker. Mirrors runassistantCodeWorker but for users on
// a ChatGPT plan (Plus / Team / Business / Enterprise) who want to spend
// that quota instead of an OpenAI API key.
//
//   model = "codex-cli/gpt-5"  → runCodexCliWorker (this file)
//   model = "codex-cli"        → runCodexCliWorker, default model from
//                                ~/.codex/config.toml
//   model = anything else      → runWorker (HTTP-API LLM adapters)
//
// History note: an earlier version of this file shelled out to `codex
// exec --json` directly and parsed JSONL on stdout. The official
// @openai/codex-sdk now exposes a typed Thread/Codex API that does the
// same thing more cleanly - typed events, abortable streams, proper
// usage reporting - so this is now an SDK adapter. Behaviour and model
// prefix unchanged so existing config/dispatch keeps working.
//
// Auth: the Codex CLI persists OAuth tokens at ~/.codex/auth.json. The
// SDK invokes the CLI as a subprocess, which finds them automatically.
// EMBER_CODEX_HOME overrides if you want to point at a different install.
//
// Tool surface: ember already has a CLI (ember --decompile, --xrefs,
// --strings, --refs-to, --recognize) and ember-agent has an `intel claim`
// subcommand. So we let Codex use its built-in shell to drive those -
// every shell call lands in events.jsonl as a tool_ok / tool_err entry,
// every claim is filed via `ember-agent intel claim` writing directly
// to the same intel.jsonl the rest of cascade reads. No MCP bridge
// required - the CLI surface IS the tool surface.

export function isCodexCliModel(model: string | undefined): boolean {
    return (model ?? "").startsWith("codex-cli");
}

function buildPrompt(args: WorkerArgs, system: string, claimsPath: string): string {
    const agentId = args.agentId ?? `${args.role}-${args.runId}`;
    const scope = args.scope.startsWith("fn:")
        ? `Target function: ${args.scope.slice(3)} in ${args.binary}`
        : args.scope.startsWith("dispute:")
            ? `Disputed claim scope: ${args.scope.slice("dispute:".length)} in ${args.binary}`
            : `Scope: ${args.scope} in ${args.binary}`;
    return `${system}

You are running inside Ember's Codex worker. Do not edit repository files.
Use shell commands only for analysis and for writing intel claims.

${scope}
Agent id: ${agentId}

Available shell commands. Copy the exact flag layout - the binary path
and address positions matter:

  ${args.emberBin} -p ${args.binary} -s 0x${args.scope.startsWith("fn:") ? args.scope.slice(3).replace(/^0x/i, "") : "401120"}
      Pseudo-C of one function. Address is passed via \`-s\`. Read this
      FIRST. Use \`-d\` instead of \`-p\` for raw asm only when needed.
  ${args.emberBin} --refs-to 0x401120 ${args.binary}
      Callers of an address. The address is the FLAG value, not a
      positional after the binary. \`--xrefs\` with no arg dumps the
      entire table (slow on big binaries) - prefer --refs-to.
  ${args.emberBin} --callees 0x401120 ${args.binary}
      Direct call targets of the function at the given address (flag
      value, same shape as --refs-to).
  ${args.emberBin} --strings ${args.binary} | grep -iE 'pattern1|pattern2'
      String literals. Note: grep exits non-zero when nothing matches -
      that's expected, not a tool failure. The "no output" itself is
      the answer ("no strings of that flavour reachable").

To file an intel claim, append ONE JSON line to ${claimsPath}:

  echo '{"subject":"0x4012a0","predicate":"name","value":"my_func","evidence":"...","confidence":0.85}' >> ${claimsPath}

The orchestrator drains that file at the end of your turn and ingests
each line through ember-agent's intel db (same validation + id
assignment as the in-process worker.ts loop).

Investigate the target and file at least ONE claim. If you cannot name
with high confidence, file predicate="note" with confidence 0.3-0.6
summarizing what you found and why. Going deeper without filing a
claim wastes the run.`;
}

export async function runCodexCliWorker(args: WorkerArgs): Promise<void> {
    const role = ROLES[args.role];
    if (!role) throw new Error(`unknown role: ${args.role}`);

    // Model syntax:
    //   codex-cli                       → Codex CLI default model (config.toml)
    //   codex-cli/gpt-5.4-mini          → that model, default reasoning effort
    //   codex-cli/gpt-5.4-mini:medium   → model + reasoning effort.
    //                                     Effort: minimal|low|medium|high|xhigh
    const requested = args.model ?? role.defaultModel;
    let cliModel: string | undefined;
    let cliEffort: ModelReasoningEffort | undefined;
    if (requested.startsWith("codex-cli/")) {
        const tail = requested.slice("codex-cli/".length);
        const colon = tail.indexOf(":");
        if (colon >= 0) {
            cliModel = tail.slice(0, colon) || undefined;
            const e = tail.slice(colon + 1) as ModelReasoningEffort;
            if (e === "minimal" || e === "low" || e === "medium" ||
                e === "high"    || e === "xhigh") {
                cliEffort = e;
            }
        } else {
            cliModel = tail || undefined;
        }
    }

    // Auth-home resolution order:
    //   1. WorkerArgs.cliHome - cascade plumbs a per-worker pick from
    //      pickCodexHome() so a multi-account pool round-robins across
    //      a single cascade's workers.
    //   2. EMBER_CODEX_HOME - one-shot env override.
    //   3. ~/.codex - default for the typical single-account case.
    const codexHome = args.cliHome
                   ?? process.env.EMBER_CODEX_HOME
                   ?? join(homedir(), ".codex");
    if (!existsSync(join(codexHome, "auth.json"))) {
        throw new Error(
            `codex: no auth at ${codexHome}/auth.json - ` +
            `run \`codex login\` once to authenticate (or with CODEX_HOME set ` +
            `to the directory above for a non-default account), or set ` +
            `EMBER_CODEX_HOME / [codex] homes = [...] in agent.toml`);
    }

    mkdirSync(args.runDir, { recursive: true });
    const eventsPath = join(args.runDir, "events.jsonl");
    const emit = (e: Record<string, unknown>) => {
        appendFileSync(eventsPath,
            JSON.stringify({ ts: new Date().toISOString(), ...e }) + "\n");
    };

    const claimsPath = join(args.runDir, "claims.jsonl");
    const agentId = args.agentId ?? `${args.role}-${args.runId}`;

    emit({ kind: "start", role: args.role, model: requested, scope: args.scope, agentId,
           budget: args.budget, binary: args.binary, cliHome: codexHome });

    const codex = new Codex({
        env: {
            ...(process.env as Record<string, string>),
            CODEX_HOME: codexHome,
        },
    });

    const thread = codex.startThread({
        // danger-full-access: the agent runs Ember's CLI which writes to
        // ~/.cache/ember/* (the intel db, the disk cache for xrefs /
        // strings / TEEF). workspace-write would deny those writes.
        // Codex isn't running untrusted code - it's running the same
        // ember CLIs every other cascade worker runs. The sandbox rules
        // are out of scope here.
        sandboxMode: "danger-full-access",
        approvalPolicy: "never",
        // No web search - every tool the agent needs is local. Saves
        // quota on irrelevant lookups.
        networkAccessEnabled: false,
        webSearchMode: "disabled",
        skipGitRepoCheck: true,
        workingDirectory: args.runDir,
        ...(cliModel  ? { model: cliModel }                     : {}),
        ...(cliEffort ? { modelReasoningEffort: cliEffort }     : {}),
    });

    const tally = { in_tok: 0, cached_in: 0, out_tok: 0, reasoning_out: 0 };
    let turn = 0;
    let lastAssistantText = "";

    try {
        const prompt = buildPrompt(args, role.system, claimsPath);
        const stream = await thread.runStreamed(prompt);

        for await (const ev of stream.events as AsyncGenerator<ThreadEvent>) {
            switch (ev.type) {
                case "thread.started":
                    break;
                case "turn.started":
                    emit({ kind: "turn", turn });
                    ++turn;
                    break;
                case "turn.completed":
                    if (ev.usage) {
                        tally.in_tok        += ev.usage.input_tokens         ?? 0;
                        tally.cached_in     += ev.usage.cached_input_tokens  ?? 0;
                        tally.out_tok       += ev.usage.output_tokens        ?? 0;
                        tally.reasoning_out += ev.usage.reasoning_output_tokens ?? 0;
                    }
                    break;
                case "turn.failed":
                    emit({ kind: "error", phase: "turn", err: ev.error?.message ?? "turn.failed" });
                    break;
                case "item.completed": {
                    const it = ev.item;
                    if (it.type === "command_execution") {
                        const ok = it.exit_code === 0;
                        emit({
                            kind: ok ? "tool_ok" : "tool_err",
                            name: "shell",
                            input: { command: it.command },
                            bytes: it.aggregated_output?.length ?? 0,
                            ...(ok ? {} : { exit_code: it.exit_code }),
                        });
                    } else if (it.type === "agent_message") {
                        lastAssistantText = it.text;
                    } else if (it.type === "error") {
                        emit({ kind: "error", phase: "item", err: it.message });
                    }
                    // reasoning / file_change / web_search / todo_list /
                    // mcp_tool_call: SDK telemetry not surfaced. Cascade
                    // tally only cares about command_execution + the final
                    // assistant text + claim count.
                    break;
                }
                case "error":
                    emit({ kind: "error", phase: "stream", err: ev.message });
                    break;
                default:
                    break;
            }
        }

        // Drain the claims sink. Each line is a complete intel_claim
        // payload (subject, predicate, value, evidence, confidence). We
        // ingest via the existing `ember-agent intel claim` CLI to
        // get the same validation + id assignment as the in-process
        // intel_claim tool the runWorker loop uses.
        let claimsFiled = 0;
        if (existsSync(claimsPath)) {
            const lines = readFileSync(claimsPath, "utf8").split("\n");
            for (const line of lines) {
                const t = line.trim();
                if (!t) continue;
                let obj: Record<string, unknown>;
                try { obj = JSON.parse(t); }
                catch (e) {
                    emit({ kind: "claim_parse_err", err: String(e), line: t.slice(0, 200) });
                    continue;
                }
                const cliArgs = [
                    process.argv[1], "intel", args.binary, "claim",
                    `--agent-id=${agentId}`,
                    `--subject=${obj.subject}`,
                    `--predicate=${obj.predicate}`,
                    `--value=${obj.value}`,
                    `--evidence=${obj.evidence}`,
                    `--confidence=${obj.confidence}`,
                ];
                if (obj.supersedes) cliArgs.push(`--supersedes=${obj.supersedes}`);
                const r = spawnSync(process.execPath, cliArgs, { encoding: "utf8" });
                if (r.status === 0) {
                    ++claimsFiled;
                    emit({ kind: "tool_ok", name: "intel_claim", input: obj, bytes: 0 });
                } else {
                    emit({ kind: "tool_err", name: "intel_claim",
                           err: ((r.stderr ?? "") + (r.stdout ?? "")).slice(0, 500) });
                }
            }
        }

        emit({
            kind: "done",
            turns: turn,
            tally: {
                usd: 0,    // ChatGPT-plan-backed; quota burn, not cash
                input_tokens: tally.in_tok,
                output_tokens: tally.out_tok,
                cache_read_tokens: tally.cached_in,
                cache_write_tokens: 0,
                reasoning_tokens: tally.reasoning_out,
            },
            claims_filed: claimsFiled,
            final_text_bytes: lastAssistantText.length,
        });
    } catch (e) {
        const err = e instanceof Error ? e.message : String(e);
        emit({ kind: "error", phase: "codex", err });
        throw e;
    }
}
