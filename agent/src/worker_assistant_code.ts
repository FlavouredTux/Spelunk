import { appendFileSync, existsSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { z } from "zod";

import {
    query,
    createSdkMcpServer,
    tool,
    type SDKMessage,
} from "@assistant-ai/assistant-agent-sdk";

import { ALL_TOOLS, type ToolContext } from "./tools/ember.js";
import { EmberDaemon } from "./tools/daemon.js";
import { ROLES } from "./roles/index.js";
import { IntelLog, intelPathFor } from "./intel/log.js";
import type { WorkerArgs } from "./worker.js";

// assistant Code SDK-driven worker. Same interface and event log shape as
// runWorker so cascade.ts can route to either based on model prefix:
//   model = "assistant-code/sonnet"  → runassistantCodeWorker (this file)
//   model = anything else         → runWorker (HTTP-API LLM adapters)
//
// Why this exists: the assistant / OpenAI adapters all implement
// LLM.chat() - single-turn request/response, ember-agent owns the
// agent loop. The assistant Agent SDK's query() owns its own loop with
// built-in tool execution, so the architectural shape is different.
// We let the SDK drive, register ember's tools as in-process MCP
// tools, and translate the SDKMessage stream into the same events.jsonl
// shape so the UI / cascade tally / promote pipeline are unchanged.
//
// Auth: the SDK reads ~/.assistant/.credentials.json (the same store
// `assistant` CLI uses). Setting HOME=~/.assistant/ on the SDK process picks
// up whatever auth state assistant Code already established - Max-plan
// users get to spend their plan quota on cascade workers without ever
// handling an OAuth token. No API key needed; assistant's per-use
// pricing doesn't apply.

// JSON-Schema → Zod shape. Ember tool schemas are strictly flat
// (top-level object with primitive properties), so this covers them
// without a heavyweight converter.
function jsonSchemaToZodShape(schema: { properties?: Record<string, unknown>; required?: string[] }): Record<string, z.ZodTypeAny> {
    const props = schema.properties ?? {};
    const required = new Set(schema.required ?? []);
    const out: Record<string, z.ZodTypeAny> = {};
    for (const [key, raw] of Object.entries(props)) {
        const def = (raw ?? {}) as { type?: string; description?: string };
        let t: z.ZodTypeAny;
        switch (def.type) {
            case "string":  t = z.string();  break;
            case "number":  case "integer": t = z.number();  break;
            case "boolean": t = z.boolean(); break;
            default:        t = z.unknown();
        }
        if (def.description) t = t.describe(def.description);
        if (!required.has(key)) t = t.optional();
        out[key] = t;
    }
    return out;
}

// SDK pricing for Max-plan auth: the request consumes plan quota, not
// per-token billing. We still track tokens for telemetry but USD = 0
// so the cascade budget gate doesn't trigger.
const kZeroCost = { usd: 0, in_tok: 0, out_tok: 0, cache_read: 0, cache_write: 0 };

export async function runassistantCodeWorker(args: WorkerArgs): Promise<void> {
    const role = ROLES[args.role];
    if (!role) throw new Error(`unknown role: ${args.role}`);

    // Strip the "assistant-code/" prefix to recover the SDK model alias.
    // Accept both "assistant-code/sonnet" (alias) and the bare "assistant-code"
    // sentinel (defaults to whatever assistant Code's settings.json picks).
    const requested = args.model ?? role.defaultModel;
    const sdkModel = requested.startsWith("assistant-code/")
        ? requested.slice("assistant-code/".length) || undefined
        : undefined;

    // Locate the user's assistant Code home. The SDK appends ".assistant/" to
    // $HOME itself, so HOME must be the *parent* of the .assistant directory
    // (e.g. /home/Gato), not .assistant itself.
    //
    // Resolution order:
    //   1. WorkerArgs.cliHome - cascade plumbs a per-worker pick from
    //      pickassistantHome() for round-robin across a multi-account pool.
    //   2. EMBER_assistant_HOME - one-shot env override.
    //   3. ~/ - default for the typical single-account case.
    const sdkHome = args.cliHome ?? process.env.EMBER_assistant_HOME ?? homedir();
    const credsPath = join(sdkHome, ".assistant", ".credentials.json");
    if (!existsSync(credsPath)) {
        throw new Error(
            `assistant-code: no credentials at ${credsPath} - ` +
            `run \`assistant\` once to authenticate, or set EMBER_assistant_HOME ` +
            `to the directory containing .assistant/`);
    }

    const intel = new IntelLog(intelPathFor(args.binary));
    const agentId = args.agentId ?? `${args.role}-${args.runId}`;

    let daemon: EmberDaemon | undefined;
    try { daemon = new EmberDaemon(args.emberBin, args.binary, undefined, args.module); }
    catch { daemon = undefined; }

    const ctx: ToolContext = {
        binary: args.binary,
        intel,
        agentId,
        emberBin: args.emberBin,
        daemon,
    };

    mkdirSync(args.runDir, { recursive: true });
    const eventsPath = join(args.runDir, "events.jsonl");
    const emit = (e: Record<string, unknown>) => {
        appendFileSync(eventsPath,
            JSON.stringify({ ts: new Date().toISOString(), ...e }) + "\n");
    };

    let claimsFiled = 0;

    // Wrap every ember tool as an SDK MCP tool. The SDK's loop calls
    // these in-process; our handler dispatches to the existing executor
    // with the bound ToolContext. We don't surface errors as exceptions
    // to the SDK - the loop expects CallToolResult shape, where a
    // user-facing error is content[0].text + isError=true.
    const sdkTools = ALL_TOOLS.map((t) => {
        const shape = jsonSchemaToZodShape(t.def.input_schema);
        return tool(
            t.def.name,
            t.def.description,
            shape,
            async (input: Record<string, unknown>) => {
                try {
                    const out = await t.execute(input, ctx);
                    emit({ kind: "tool_ok", name: t.def.name, input, bytes: out.length });
                    if (t.def.name === "intel_claim") ++claimsFiled;
                    return { content: [{ type: "text" as const, text: out }] };
                } catch (e) {
                    const err = e instanceof Error ? e.message : String(e);
                    emit({ kind: "tool_err", name: t.def.name, err });
                    return {
                        content: [{ type: "text" as const, text: `error: ${err}` }],
                        isError: true,
                    };
                }
            });
    });

    const mcp = createSdkMcpServer({ name: "ember", version: "1.0.0", tools: sdkTools, alwaysLoad: true });

    const userPrompt = buildScopeMessage(args.scope, args.binary);
    emit({ kind: "start", role: args.role, model: requested, scope: args.scope, agentId,
           budget: args.budget, binary: args.binary, cliHome: sdkHome });

    const tally = { ...kZeroCost };

    try {
        const q = query({
            prompt: userPrompt,
            options: {
                // Disable assistant Code's built-in tools - ember's
                // analysis tools are the entire surface this worker
                // should touch. Bash/Read/Edit on the host filesystem
                // would be a footgun on a 200-worker cascade.
                tools: [],
                // Our MCP server is the only tool source. allowedTools
                // lists the fully-qualified MCP tool names so the SDK
                // doesn't prompt for permission on each call.
                mcpServers: { ember: mcp },
                allowedTools: ALL_TOOLS.map((t) => `mcp__ember__${t.def.name}`),
                env: {
                    ...process.env,
                    HOME: sdkHome,                          // SDK reads creds from $HOME/.assistant/.credentials.json
                    assistant_AGENT_SDK_CLIENT_APP: "ember-agent/1.0.1",
                },
                // System prompt: append the role's prompt onto the
                // SDK's defaults so role-specific guidance lands but
                // we keep the SDK's tool-use scaffolding intact.
                systemPrompt: { type: "preset", preset: "assistant_code", append: role.system },
                ...(sdkModel ? { model: sdkModel } : {}),
                maxTurns: args.maxTurns ?? 30,
            },
        });

        let turn = 0;
        for await (const msg of q as AsyncIterable<SDKMessage>) {
            if (msg.type === "assistant") {
                const usage = msg.message.usage as {
                    input_tokens?: number; output_tokens?: number;
                    cache_read_input_tokens?: number; cache_creation_input_tokens?: number;
                };
                tally.in_tok    += usage.input_tokens  ?? 0;
                tally.out_tok   += usage.output_tokens ?? 0;
                tally.cache_read  += usage.cache_read_input_tokens     ?? 0;
                tally.cache_write += usage.cache_creation_input_tokens ?? 0;
                emit({
                    kind: "turn",
                    turn,
                    stop: msg.message.stop_reason ?? "running",
                    usage,
                    tally: { usd: tally.usd },
                });
                ++turn;
            } else if (msg.type === "result") {
                if (msg.subtype === "success") {
                    // SDK reports its own cost figure; mirror it but
                    // remember Max-plan auth means it's assistant-side
                    // accounting, not money out of the user's pocket.
                    tally.usd = msg.total_cost_usd ?? 0;
                    emit({
                        kind: "done",
                        turns: msg.num_turns,
                        tally: {
                            usd: tally.usd,
                            input_tokens: tally.in_tok,
                            output_tokens: tally.out_tok,
                            cache_read_tokens: tally.cache_read,
                            cache_write_tokens: tally.cache_write,
                        },
                        claims_filed: claimsFiled,
                    });
                } else {
                    emit({
                        kind: "error",
                        phase: "result",
                        err: (msg as { result?: string }).result ?? "result.error",
                    });
                }
                break;
            }
            // Other SDK message types (system/tool_progress/etc.) are
            // SDK-internal telemetry. We ignore them - events.jsonl
            // already carries our own tool_ok / tool_err equivalents
            // emitted from the wrapper above.
        }
    } finally {
        try { daemon?.close(); } catch { /* daemon may already be dead */ }
    }
}

// Mirrors worker.ts's buildScopeMessage. Kept private here to avoid
// exporting it from worker.ts and inviting drift.
function buildScopeMessage(scope: string, binary: string): string {
    if (scope.startsWith("fn:")) {
        return `Target: ${binary}\nFunction: ${scope.slice(3)}\n\nProceed.`;
    }
    if (scope.startsWith("dispute:")) {
        const tail = scope.slice("dispute:".length);
        const bar = tail.indexOf("|");
        const subject = bar < 0 ? tail : tail.slice(0, bar);
        const predicate = bar < 0 ? "name" : tail.slice(bar + 1);
        return `Target: ${binary}\nDisputed claim: subject=${subject}, predicate=${predicate}\n\n` +
               `Use intel_disputes to see the conflicting claims, then independently verify with ` +
               `ember_decompile/xrefs/strings/recognize. File ONE intel_claim with your verdict ` +
               `(supersedes one of the existing claim ids).`;
    }
    return `Target: ${binary}\nScope: ${scope}\n\nProceed.`;
}
