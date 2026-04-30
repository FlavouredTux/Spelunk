import { appendFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";

import { makeLLM, providerForModel, type LLM, type ChatRequest, type Message, type ContentBlock, type Usage } from "./llm/index.js";
import { ALL_TOOLS, TOOLS_BY_NAME, type ToolContext } from "./tools/ember.js";
import { ROLES } from "./roles/index.js";
import { IntelLog, intelPathFor } from "./intel/log.js";

// One worker = one role + one scope + one budget. Runs an LLM tool-use
// loop until stop_reason==end_turn, the budget is exhausted, or a hard
// turn cap is hit. Emits JSONL events so the orchestrator can tail
// progress without parsing stdout.

export interface WorkerArgs {
    role: keyof typeof ROLES;
    binary: string;
    scope: string;            // e.g. "fn:0x4012a0" or "disputes" or "graph:from=main"
    model?: string;           // override role default
    budget: number;           // USD
    maxTurns?: number;        // default 30
    runId: string;
    runDir: string;           // ~/.cache/ember/agent/runs/<run-id>/
    emberBin: string;
    agentId?: string;         // default: role-<runId>
}

interface CostTally {
    usd: number;
    input_tokens: number;
    output_tokens: number;
    cache_read_tokens: number;
    cache_write_tokens: number;
}

export async function runWorker(args: WorkerArgs): Promise<void> {
    const role = ROLES[args.role];
    if (!role) throw new Error(`unknown role: ${args.role}`);
    const model = args.model ?? role.defaultModel;
    const llm = makeLLM(providerForModel(model));
    const intel = new IntelLog(intelPathFor(args.binary));
    const agentId = args.agentId ?? `${args.role}-${args.runId}`;
    const ctx: ToolContext = {
        binary: args.binary,
        intel,
        agentId,
        emberBin: args.emberBin,
    };

    mkdirSync(args.runDir, { recursive: true });
    const eventsPath = join(args.runDir, "events.jsonl");
    const emit = (e: Record<string, unknown>) => {
        appendFileSync(eventsPath,
            JSON.stringify({ ts: new Date().toISOString(), ...e }) + "\n");
    };

    const tally: CostTally = {
        usd: 0, input_tokens: 0, output_tokens: 0,
        cache_read_tokens: 0, cache_write_tokens: 0,
    };
    const pricing = llm.pricing(model);
    const addUsage = (u: Usage) => {
        tally.input_tokens  += u.input_tokens;
        tally.output_tokens += u.output_tokens;
        tally.cache_read_tokens  += u.cache_read_input_tokens ?? 0;
        tally.cache_write_tokens += u.cache_creation_input_tokens ?? 0;
        const M = 1_000_000;
        tally.usd += (u.input_tokens * pricing.input) / M;
        tally.usd += (u.output_tokens * pricing.output) / M;
        if (pricing.cache_read && u.cache_read_input_tokens) {
            tally.usd += (u.cache_read_input_tokens * pricing.cache_read) / M;
        }
        if (pricing.cache_write && u.cache_creation_input_tokens) {
            tally.usd += (u.cache_creation_input_tokens * pricing.cache_write) / M;
        }
    };

    emit({ kind: "start", role: args.role, model, scope: args.scope, agentId, budget: args.budget });

    const messages: Message[] = [{
        role: "user",
        content: [{ type: "text", text: buildScopeMessage(args.scope, args.binary) }],
    }];
    const tools = ALL_TOOLS.map((t) => t.def);
    const maxTurns = args.maxTurns ?? 30;

    for (let turn = 0; turn < maxTurns; ++turn) {
        if (tally.usd >= args.budget) {
            emit({ kind: "budget_exhausted", usd: tally.usd, budget: args.budget });
            break;
        }

        const req: ChatRequest = {
            model,
            system: role.system,
            tools,
            messages,
            max_tokens: 4096,
        };

        let resp;
        try {
            resp = await llm.chat(req);
        } catch (e) {
            const err = e instanceof Error ? e.message : String(e);
            emit({ kind: "error", phase: "chat", err });
            throw e;
        }
        addUsage(resp.usage);
        emit({
            kind: "turn",
            turn,
            stop: resp.stop_reason,
            usage: resp.usage,
            tally: { usd: tally.usd },
        });

        // Persist assistant turn to history.
        messages.push({ role: "assistant", content: resp.content });

        if (resp.stop_reason === "end_turn") {
            emit({ kind: "done", turns: turn + 1, tally });
            return;
        }
        if (resp.stop_reason !== "tool_use") {
            emit({ kind: "abort", reason: `stop=${resp.stop_reason}`, tally });
            return;
        }

        // Execute every tool_use block in parallel; build one user message
        // with the corresponding tool_result blocks (in order).
        const calls = resp.content.filter((b): b is Extract<ContentBlock, { type: "tool_use" }> =>
            b.type === "tool_use");
        const results = await Promise.all(calls.map(async (c) => {
            try {
                const tool = TOOLS_BY_NAME[c.name];
                if (!tool) throw new Error(`unknown tool: ${c.name}`);
                const out = await tool.execute(c.input, ctx);
                emit({ kind: "tool_ok", name: c.name, input: c.input, bytes: out.length });
                return { type: "tool_result" as const, tool_use_id: c.id, content: out };
            } catch (e) {
                const err = e instanceof Error ? e.message : String(e);
                emit({ kind: "tool_err", name: c.name, err });
                return {
                    type: "tool_result" as const,
                    tool_use_id: c.id,
                    content: `error: ${err}`,
                    is_error: true,
                };
            }
        }));

        messages.push({ role: "user", content: results });
    }

    emit({ kind: "max_turns", tally });
}

function buildScopeMessage(scope: string, binary: string): string {
    if (scope.startsWith("fn:")) {
        return `Target: ${binary}\nFunction: ${scope.slice(3)}\n\nProceed.`;
    }
    if (scope === "disputes") {
        return `Target: ${binary}\n\nList current disputes via intel_disputes, then resolve the first one. After resolving one, stop.`;
    }
    if (scope.startsWith("graph:")) {
        return `Target: ${binary}\nMap from: ${scope.slice(6)}\n\nProduce coarse cluster tags. Stop after writing 5-10 tag claims.`;
    }
    return `Target: ${binary}\nScope: ${scope}\n\nProceed.`;
}
