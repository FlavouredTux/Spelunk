import { spawnSync } from "node:child_process";

import type { ToolDef } from "../llm/types.js";
import { IntelLog, newId, type Claim, type Retract } from "../intel/log.js";

// One tool == one capability the LLM can invoke. The executor runs the
// real work and returns a string the model reads back as tool_result
// content. Errors get returned as text with is_error=true at the loop
// level, so executors throw on hard failure.

export interface ToolContext {
    binary: string;
    intel: IntelLog;
    agentId: string;
    emberBin: string;          // path to the `ember` CLI
}

export interface Tool {
    def: ToolDef;
    execute(input: unknown, ctx: ToolContext): Promise<string>;
}

// Helpers ----------------------------------------------------------------

function runEmber(emberBin: string, args: string[]): string {
    const r = spawnSync(emberBin, args, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
    if (r.status !== 0) {
        const stderr = (r.stderr || "").trim();
        throw new Error(`ember ${args.join(" ")} failed (${r.status}): ${stderr}`);
    }
    return r.stdout;
}

// Truncate a long stdout to keep tool_result size sane. Models don't need
// the full 5MB string dump of glibc; first 200 lines + a "[N more lines]"
// tail is enough to act on.
function clip(s: string, maxLines = 200): string {
    const lines = s.split("\n");
    if (lines.length <= maxLines) return s;
    const head = lines.slice(0, maxLines).join("\n");
    return `${head}\n[+${lines.length - maxLines} more lines, narrow the query]`;
}

// Tools ------------------------------------------------------------------

const xrefs: Tool = {
    def: {
        name: "ember_xrefs",
        description: "List xrefs (callers, data refs) to an address. Use to understand what calls a function or who reads/writes a global.",
        input_schema: {
            type: "object",
            properties: {
                addr: { type: "string", description: "Hex address with 0x prefix, e.g. '0x4012a0'" },
            },
            required: ["addr"],
        },
    },
    async execute(input, ctx) {
        const { addr } = input as { addr: string };
        const out = runEmber(ctx.emberBin, ["--xrefs", "--xref-to", addr, ctx.binary]);
        return clip(out);
    },
};

const strings: Tool = {
    def: {
        name: "ember_strings",
        description: "List string literals reachable from a function. Use to get semantic hints (error messages, format strings, file paths) about what the function does.",
        input_schema: {
            type: "object",
            properties: {
                fn: { type: "string", description: "Function start address (hex with 0x)" },
            },
            required: ["fn"],
        },
    },
    async execute(input, ctx) {
        const { fn } = input as { fn: string };
        const out = runEmber(ctx.emberBin, ["--strings", "--strings-fn", fn, ctx.binary]);
        return clip(out);
    },
};

const decompile: Tool = {
    def: {
        name: "ember_decompile",
        description: "Get ember pseudo-C for a function. The most information-dense view; use this before naming or typing.",
        input_schema: {
            type: "object",
            properties: {
                fn: { type: "string", description: "Function start address (hex with 0x)" },
            },
            required: ["fn"],
        },
    },
    async execute(input, ctx) {
        const { fn } = input as { fn: string };
        const out = runEmber(ctx.emberBin, ["--decompile", "--fn", fn, ctx.binary]);
        return clip(out, 400);
    },
};

const recognize: Tool = {
    def: {
        name: "ember_recognize",
        description: "Run TEEF library-function recognition on a single function or the whole binary. Returns suggested names with confidence; treat anything ≥0.85 as strong evidence, 0.60-0.85 as a hint.",
        input_schema: {
            type: "object",
            properties: {
                fn: { type: "string", description: "Optional fn addr; omit for whole-binary sweep" },
            },
        },
    },
    async execute(input, ctx) {
        const { fn } = (input as { fn?: string }) ?? {};
        const args = ["--recognize"];
        if (fn) args.push("--fn", fn);
        args.push(ctx.binary);
        const out = runEmber(ctx.emberBin, args);
        return clip(out);
    },
};

const callees: Tool = {
    def: {
        name: "ember_callees",
        description: "List direct callees of a function. Use to understand what a function delegates to before naming it.",
        input_schema: {
            type: "object",
            properties: {
                fn: { type: "string", description: "Function start address (hex with 0x)" },
            },
            required: ["fn"],
        },
    },
    async execute(input, ctx) {
        const { fn } = input as { fn: string };
        const out = runEmber(ctx.emberBin, ["--call-graph", "--fn", fn, ctx.binary]);
        return clip(out);
    },
};

const intelQuery: Tool = {
    def: {
        name: "intel_query",
        description: "Read the current best claim for a (subject, predicate). Returns null if no claim exists. Subjects are typically function addresses like '0x4012a0'.",
        input_schema: {
            type: "object",
            properties: {
                subject: { type: "string" },
                predicate: { type: "string", description: "name | type | note | tag | xref | signature" },
            },
            required: ["subject", "predicate"],
        },
    },
    async execute(input, ctx) {
        const { subject, predicate } = input as { subject: string; predicate: string };
        const view = ctx.intel.fold();
        const d = view.get(`${subject}|${predicate}`);
        if (!d) return JSON.stringify({ found: false });
        return JSON.stringify({
            found: true,
            value: d.winner.value,
            confidence: d.winner.confidence,
            agent: d.winner.agent,
            disputed: d.disputed,
        });
    },
};

const intelEvidence: Tool = {
    def: {
        name: "intel_evidence",
        description: "List ALL claims for a subject across predicates, including losers. Use when resolving a dispute or auditing prior agent work.",
        input_schema: {
            type: "object",
            properties: {
                subject: { type: "string" },
            },
            required: ["subject"],
        },
    },
    async execute(input, ctx) {
        const { subject } = input as { subject: string };
        const out: unknown[] = [];
        for (const e of ctx.intel.read()) {
            if (e.kind === "claim" && e.subject === subject) out.push(e);
        }
        return JSON.stringify(out, null, 2);
    },
};

const intelClaim: Tool = {
    def: {
        name: "intel_claim",
        description: "Write a claim about a subject. Confidence is 0..1; use 0.95+ only when you have direct evidence (TEEF whole-exact match, unambiguous string xref). 0.7-0.9 for strong inference, 0.5-0.7 for educated guess. Always cite evidence.",
        input_schema: {
            type: "object",
            properties: {
                subject:    { type: "string" },
                predicate:  { type: "string", description: "name | type | note | tag | xref | signature" },
                value:      { type: "string" },
                evidence:   { type: "string", description: "Why you believe this. Examples: 'teef:0.92 whole-exact', 'string-xref:\"connection failed\"', 'caller-pattern: invoked from main+malloc' " },
                confidence: { type: "number" },
                supersedes: { type: "string", description: "Optional prior claim id this revises" },
            },
            required: ["subject", "predicate", "value", "evidence", "confidence"],
        },
    },
    async execute(input, ctx) {
        const i = input as Omit<Claim, "kind" | "id" | "agent" | "ts">;
        const c: Claim = {
            kind: "claim",
            id: newId(),
            agent: ctx.agentId,
            ts: new Date().toISOString(),
            subject: i.subject,
            predicate: i.predicate,
            value: i.value,
            evidence: i.evidence,
            confidence: i.confidence,
            supersedes: i.supersedes,
        };
        ctx.intel.append(c);
        return JSON.stringify({ ok: true, id: c.id });
    },
};

const intelRetract: Tool = {
    def: {
        name: "intel_retract",
        description: "Mark a prior claim as withdrawn. Use when you (or another agent) made a claim you now know to be wrong.",
        input_schema: {
            type: "object",
            properties: {
                target_id: { type: "string" },
                reason:    { type: "string" },
            },
            required: ["target_id", "reason"],
        },
    },
    async execute(input, ctx) {
        const { target_id, reason } = input as { target_id: string; reason: string };
        const r: Retract = {
            kind: "retract",
            id: newId(),
            agent: ctx.agentId,
            ts: new Date().toISOString(),
            target_id,
            reason,
        };
        ctx.intel.append(r);
        return JSON.stringify({ ok: true, id: r.id });
    },
};

const intelDisputes: Tool = {
    def: {
        name: "intel_disputes",
        description: "List subjects with conflicting high-confidence claims. Tiebreaker agents start here.",
        input_schema: { type: "object", properties: {} },
    },
    async execute(_input, ctx) {
        const ds = ctx.intel.disputes();
        return JSON.stringify(ds.map((d) => ({
            subject: d.winner.subject,
            predicate: d.winner.predicate,
            top: { value: d.winner.value, conf: d.winner.confidence, agent: d.winner.agent, id: d.winner.id },
            runner: d.runners_up[0] && {
                value: d.runners_up[0].value,
                conf: d.runners_up[0].confidence,
                agent: d.runners_up[0].agent,
                id: d.runners_up[0].id,
            },
        })), null, 2);
    },
};

export const ALL_TOOLS: Tool[] = [
    xrefs, strings, decompile, recognize, callees,
    intelQuery, intelEvidence, intelClaim, intelRetract, intelDisputes,
];

export const TOOLS_BY_NAME: Record<string, Tool> = Object.fromEntries(
    ALL_TOOLS.map((t) => [t.def.name, t]));
