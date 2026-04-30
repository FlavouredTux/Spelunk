import { spawnSync } from "node:child_process";

import type { ToolDef } from "../llm/types.js";
import { IntelLog, newId, type Claim, type Retract } from "../intel/log.js";
import type { EmberDaemon } from "./daemon.js";

// One tool == one capability the LLM can invoke. The executor runs the
// real work and returns a string the model reads back as tool_result
// content. Errors get returned as text with is_error=true at the loop
// level, so executors throw on hard failure.

export interface ToolContext {
    binary: string;
    intel: IntelLog;
    agentId: string;
    emberBin: string;          // path to the `ember` CLI
    daemon?: EmberDaemon;      // long-lived ember --serve client; if present, hot tools route here
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
        if (ctx.daemon) return clip(await ctx.daemon.call("refs_to", { addr }));
        const out = runEmber(ctx.emberBin, ["--refs-to", addr, ctx.binary]);
        return clip(out);
    },
};

const strings: Tool = {
    def: {
        name: "ember_strings",
        description: "List strings whose xref sites fall within a function's address range. Use to get semantic hints (error messages, format strings, file paths) about what a function does.",
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
        const start = parseInt(fn, 16);
        // Get the function's extent so we can filter strings by xref site.
        const cfRaw = ctx.daemon
            ? await ctx.daemon.call("containing_fn", { addr: fn })
            : runEmber(ctx.emberBin, ["--containing-fn", fn, ctx.binary]);
        // Output: <entry>\t<size>\t<name>\t<offset>
        const cf = cfRaw.trim().split("\t");
        const size = cf.length >= 2 ? parseInt(cf[1], 16) : 0;
        const end = start + (size || 0x1000);

        // Daemon path: server-side range filter avoids shipping the
        // whole strings table over the pipe per call. Subprocess
        // fallback still pulls + filters client-side.
        if (ctx.daemon) {
            const body = await ctx.daemon.call("strings_in_range", {
                start: "0x" + start.toString(16),
                end:   "0x" + end.toString(16),
            });
            return body.trim() ? clip(body) : "(no strings reachable from this fn)";
        }
        const all = runEmber(ctx.emberBin, ["--strings", ctx.binary]);
        const lines = all.split("\n");
        const hits: string[] = [];
        for (const ln of lines) {
            const parts = ln.split("|");
            if (parts.length < 3) continue;
            const xrefs = parts[2].trim();
            if (!xrefs) continue;
            for (const x of xrefs.split(",")) {
                const v = parseInt(x.trim(), 16);
                if (Number.isFinite(v) && v >= start && v < end) { hits.push(ln); break; }
            }
        }
        return hits.length ? clip(hits.join("\n")) : "(no strings reachable from this fn)";
    },
};

const decompile: Tool = {
    def: {
        name: "ember_decompile",
        description: "Get ember pseudo-C for a function. The most information-dense view; use this before naming or typing.",
        input_schema: {
            type: "object",
            properties: {
                fn: { type: "string", description: "Function start address (hex with 0x) or symbol name" },
            },
            required: ["fn"],
        },
    },
    async execute(input, ctx) {
        const { fn } = input as { fn: string };
        if (ctx.daemon) return clip(await ctx.daemon.call("decompile", { fn }), 400);
        const out = runEmber(ctx.emberBin, ["-p", "-s", fn, ctx.binary]);
        return clip(out, 400);
    },
};

const recognize: Tool = {
    def: {
        name: "ember_recognize",
        description: "Run TEEF library-function recognition across the whole binary against the configured corpus. Returns suggested names with confidence; treat anything ≥0.85 as strong evidence, 0.60-0.85 as a hint. Output is per-function TSV: addr | current | suggested | confidence | via | [alts]. Filter the output yourself for the function you care about.",
        input_schema: { type: "object", properties: {} },
    },
    async execute(_input, ctx) {
        if (ctx.daemon) return clip(await ctx.daemon.call("recognize"));
        const out = runEmber(ctx.emberBin, ["--recognize", ctx.binary]);
        return clip(out);
    },
};

const callees: Tool = {
    def: {
        name: "ember_callees",
        description: "List direct/tail/indirect-const callees of a function. Use to understand what a function delegates to before naming it.",
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
        if (ctx.daemon) return clip(await ctx.daemon.call("callees", { fn }));
        const out = runEmber(ctx.emberBin, ["--callees", fn, ctx.binary]);
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
