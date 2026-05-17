import { spawn, spawnSync } from "node:child_process";
import { mkdirSync, readdirSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

import { runWorker } from "./worker.js";
import { runassistantCodeWorker } from "./worker_assistant_code.js";
import { isCodexCliModel, runCodexCliWorker } from "./worker_codex_cli.js";
import { pickCodexHome, pickassistantHome } from "./cli_homes.js";
import { promote } from "./promote.js";
import { IntelLog, intelPathFor, newId, type Claim } from "./intel/log.js";

// Pre-warm ember's strings disk cache, and xrefs on smaller binaries, so worker daemons
// pick up cached payloads on first access instead of N×workers
// each rebuilding from scratch. Smoothness:
//   - skip entirely when both caches already exist on disk
//   - run enabled warmups concurrently (different cache slots,
//     no contention) so cold-start is half as long
//   - emit a heartbeat every 5s so the user sees progress
// Cache layout: $XDG_CACHE_HOME/ember/<key>/<tag>, where <key> is
// FNV-style hash mirroring ember's cache::key_for. We don't need to
// match it exactly to *use* ember's cache (ember computes its own
// key on every call); we just need a heuristic for "is it warm
// enough that we can skip the fork." statSync the cache dir for
// the binary's basename pattern; if the relevant tags exist, skip.
async function warmEmberCaches(binary: string, emberBin: string): Promise<void> {
    const cacheRoot = process.env.XDG_CACHE_HOME
        ? join(process.env.XDG_CACHE_HOME, "ember")
        : join(homedir(), ".cache", "ember");

    // Skip-fast check: ember's cache key is FNV1a-64 of (abspath|size|mtime|vN).
    // We don't reproduce that exactly; instead we look across all cache subdirs
    // for files tagged xrefs* / strings-v* whose mtime is newer than the binary's.
    // Cheap heuristic, false-positive-tolerant - if we skip when caches don't
    // actually cover this binary, ember will rebuild them on first call (correct,
    // just no smoothness). False negative (we re-warm when we shouldn't have to)
    // costs at most ~200ms on a warm system.
    let xrefsLikelyWarm = false;
    let stringsLikelyWarm = false;
    let binarySize = 0;
    try {
        const binStat = statSync(binary);
        binarySize = binStat.size;
        for (const dir of readdirSync(cacheRoot)) {
            const slot = join(cacheRoot, dir);
            try {
                const ents = readdirSync(slot);
                for (const ent of ents) {
                    if (!ent.startsWith("xrefs") && !ent.startsWith("strings")) continue;
                    const st = statSync(join(slot, ent));
                    if (st.mtimeMs < binStat.mtimeMs) continue;
                    if (ent.startsWith("xrefs")) xrefsLikelyWarm = true;
                    if (ent.startsWith("strings")) stringsLikelyWarm = true;
                }
                if (xrefsLikelyWarm && stringsLikelyWarm) break;
            } catch { /* slot races; ignore */ }
        }
    } catch { /* no cacheRoot */ }
    if (xrefsLikelyWarm && stringsLikelyWarm) {
        process.stderr.write(`cascade: ember caches already warm for ${binary} (skip)\n`);
        return;
    }

    const largeBinaryXrefCutoff = 96 * 1024 * 1024;
    const warmXrefs = !xrefsLikelyWarm && (
        binarySize < largeBinaryXrefCutoff || process.env.EMBER_WARM_XREFS === "1"
    );
    const warmStrings = !stringsLikelyWarm;
    if (!warmXrefs && !xrefsLikelyWarm) {
        process.stderr.write(
            `cascade: deferring xrefs warmup for large binary ${binary} ` +
            `(set EMBER_WARM_XREFS=1 to force)\n`,
        );
    }
    if (!warmXrefs && !warmStrings) return;

    const t_warm = Date.now();
    process.stderr.write(`cascade: warming ember caches for ${binary}…\n`);

    // Heartbeat ticker so a multi-minute warmup doesn't look hung.
    const heartbeat = setInterval(() => {
        const elapsed = ((Date.now() - t_warm) / 1000).toFixed(0);
        process.stderr.write(`  …still warming (${elapsed}s)\n`);
    }, 5000);

    const run = (flag: string) => new Promise<void>((resolve) => {
        const p = spawn(emberBin, [flag, binary], {
            stdio: ["ignore", "ignore", "pipe"],
        });
        let err = "";
        p.stderr.on("data", (b: Buffer) => { err += b.toString(); });
        p.on("close", (code) => {
            if (code !== 0) {
                process.stderr.write(`  ${flag} warmup failed (continuing): ${err.slice(0, 200)}\n`);
            }
            resolve();
        });
        p.on("error", () => resolve());
    });

    const jobs: Promise<void>[] = [];
    if (warmXrefs) jobs.push(run("--xrefs"));
    if (warmStrings) jobs.push(run("--strings"));
    await Promise.all(jobs);
    clearInterval(heartbeat);
    process.stderr.write(`cascade: selected caches warm (${((Date.now() - t_warm) / 1000).toFixed(1)}s)\n`);
}

// Belt-and-suspenders alongside PR_SET_PDEATHSIG on the C++ side.
// SIGKILL'd cascades can leak `ember --serve` orphans (the C++ guard
// catches normal signals but the kernel can't notify on SIGKILL of
// the orphan's *grandparent*). Scan procfs for any prior --serve
// against the same binary, send SIGTERM, give them a moment to
// flush. If the user explicitly wants to keep an orphan around,
// they can disable this with EMBER_AGENT_NO_ORPHAN_SCAN=1.
function killOrphanDaemons(binary: string): number {
    if (process.env.EMBER_AGENT_NO_ORPHAN_SCAN === "1") return 0;
    if (process.platform !== "linux") return 0;   // /proc reading is Linux-specific
    let entries: string[] = [];
    try { entries = readdirSync("/proc"); } catch { return 0; }
    let killed = 0;
    for (const name of entries) {
        if (!/^\d+$/.test(name)) continue;
        const pid = parseInt(name, 10);
        if (pid === process.pid) continue;
        let cmdline: string;
        try { cmdline = readFileSync(`/proc/${pid}/cmdline`, "utf8"); } catch { continue; }
        // cmdline tokens are NUL-separated. Match `ember --serve <binary>`
        // (or any --serve invocation against this exact binary path).
        const tokens = cmdline.split("\0").filter(Boolean);
        const serveIdx = tokens.indexOf("--serve");
        if (serveIdx < 0) continue;
        if (tokens[serveIdx + 1] !== binary) continue;
        try {
            process.kill(pid, "SIGTERM");
            ++killed;
        } catch { /* permission denied or already gone */ }
    }
    return killed;
}

// Anchor Cascade - iterative bottom-up agent naming.
//
// Background: a single-pass agent fanout treats each function as an
// island. The agent looking at sub_a sees calls to sub_b and sub_c
// rendered as sub_b()/sub_c() - opaque. There's no way to bootstrap
// because every neighbor is also unknown.
//
// Cascade exploits ember's annotations system: emit-time name lookup
// means re-rendering pseudo-C after a promote is essentially free. So
// we run the swarm in rounds:
//
//   round N:
//     1. compute eligibility per fn:
//          known_callees / total_callees >= --eligibility-ratio
//          (PLT thunks count as known; named symbols count as known;
//           intel claims with conf >= threshold count as known)
//        Leaves (no callees) are eligible from round 0.
//     2. spawn workers on top-K eligible (max --per-round)
//     3. promote conf >= --threshold claims into the annotations file
//     4. next round's pseudo-C is automatically richer; loop.
//
// Convergence: each round either adds anchors (progress) or doesn't
// (terminate). On a 7000-fn binary, expected behavior is ~5-10% named
// in round 0 (anchored leaves), another ~15-20% in round 1 (fns whose
// callees were named in round 0), asymptote 50-70% over a few rounds.

export interface CascadeArgs {
    binary: string;
    role: "namer" | "mapper" | "typer" | "tiebreaker";
    model?: string;              // single model (overridden by `models` if set)
    models?: string[];           // optional per-round model list - round N uses
                                 // models[N % models.length]. Lets you escalate
                                 // (e.g. cheap for early rounds, smarter for
                                 // later) or interleave (cross-validation).
    perRound: number;            // max workers spawned per round
    maxRounds: number;
    budget: number;              // USD per worker
    maxTurns: number;
    threshold: number;           // promotion + named-callee threshold
    eligibilityRatio: number;    // min named-callee fraction for eligibility
    maxLowConfRetries?: number;  // skip targets with this many below-threshold
                                 // name claims already in intel. Prevents
                                 // repeated runs from hammering a target that
                                 // keeps producing useful-but-unpromotable names.
    emberBin: string;
    runsRoot: string;
    module?: string;             // --module NAME scope filter; threads through to
                                 // the coord daemon + every worker daemon. Critical
                                 // on minidump targets where the 160K wine-DLL fns
                                 // would otherwise dominate every fn-walk.
    scope?: string;              // target filter: all | list:0x..,.. | range:A-B |
                                 // callers-of:A | callees-of:A | around:A[:radius]
    dryRunPlan?: boolean;        // compute and print target plan; spawn no workers
}

export interface RoundStats {
    round: number;
    eligible: number;
    spawned: number;
    fulfilled: number;            // workers that returned cleanly
    rejected: number;             // workers that threw (provider 5xx, OOM, etc)
    claims_filed: number;          // all accepted intel claims filed by this round's workers
    name_claims: number;           // name claims, including low-confidence ones
    promotable_name_claims: number;// name claims at/above threshold, before dispute filtering
    low_conf_name_claims: number;  // useful naming signal below promotion threshold
    note_claims: number;           // predicate=note claims filed this round
    other_claims: number;          // type/tag/xref/signature/etc.
    unpromoted_claims: number;     // claims below the promotion threshold
    retry_skipped: number;         // planner candidates skipped due to retry policy
    retry_skipped_targets: string[];
    consensus_escalated: number;   // retry-saturated targets retried once due to low-conf agreement
    consensus_targets: string[];
    new_names: number;            // names produced *this round*
    cumulative_named: number;     // running total across all rounds
    model: string;                // model actually used this round
    cost_usd: number;
    elapsed_ms: number;
    targets?: CascadePlanEntry[]; // selected target preview, same ordering as spawned workers
}

export interface CascadeResult {
    rounds: RoundStats[];
    total_named: number;
    total_cost: number;
    plan?: CascadePlan;
}

export interface CascadePlanEntry {
    addr: string;
    score: number;
    ratio: number;
    callees: number;
    callers: number;
    unresolved_callees: number;
    size: number;
    features?: CascadePlanFeatures;
    reasons: string[];
}
export interface CascadePlanFeatures {
    known_callee_ratio: number;
    known_callees: number;
    total_callees: number;
    caller_count: number;
    unresolved_callee_count: number;
    size: number;
    is_leaf: boolean;
}
export interface CascadePlan {
    scope: string;
    policy?: string;
    candidates: number;
    eligible: number;
    selected: number;
    top: CascadePlanEntry[];
}

export interface ConsensusCandidate {
    subject: string;
    value: string;
    count: number;
    best_confidence: number;
    values: string[];
}

function highConfNames(intel: IntelLog, threshold: number): Set<string> {
    const out = new Set<string>();
    for (const [, d] of intel.fold()) {
        if (d.disputed) continue;
        if (d.winner.predicate !== "name") continue;
        if (d.winner.confidence < threshold) continue;
        out.add(d.winner.subject);
    }
    return out;
}

export function summarizeRoundClaims(claims: Claim[], threshold: number) {
    let nameClaims = 0;
    let promotableNameClaims = 0;
    let lowConfNameClaims = 0;
    let noteClaims = 0;
    let otherClaims = 0;
    let unpromotedClaims = 0;

    for (const c of claims) {
        if (c.confidence < threshold) ++unpromotedClaims;
        if (c.predicate === "name") {
            ++nameClaims;
            if (c.confidence >= threshold) ++promotableNameClaims;
            else ++lowConfNameClaims;
        } else if (c.predicate === "note") {
            ++noteClaims;
        } else {
            ++otherClaims;
        }
    }

    return {
        claims_filed: claims.length,
        name_claims: nameClaims,
        promotable_name_claims: promotableNameClaims,
        low_conf_name_claims: lowConfNameClaims,
        note_claims: noteClaims,
        other_claims: otherClaims,
        unpromoted_claims: unpromotedClaims,
    };
}

function claimsByAgents(intel: IntelLog, agentIds: Set<string>): Claim[] {
    return intel.read().filter((e): e is Claim =>
        e.kind === "claim" && agentIds.has(e.agent));
}

export function lowConfNameAttempts(intel: IntelLog, threshold: number): Map<string, number> {
    const out = new Map<string, number>();
    for (const e of intel.read()) {
        if (e.kind !== "claim") continue;
        if (e.predicate !== "name") continue;
        if (e.confidence >= threshold) continue;
        out.set(e.subject, (out.get(e.subject) ?? 0) + 1);
    }
    return out;
}

function normalizeNameForConsensus(value: string): string {
    return value
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "_")
        .replace(/^_+|_+$/g, "")
        .replace(/_+/g, "_");
}

export function consensusNameCandidates(claims: Claim[], threshold: number): Map<string, ConsensusCandidate> {
    const bySubject = new Map<string, Map<string, Claim[]>>();
    for (const c of claims) {
        if (c.predicate !== "name") continue;
        if (c.confidence >= threshold) continue;
        const key = normalizeNameForConsensus(c.value);
        if (!key) continue;
        let groups = bySubject.get(c.subject);
        if (!groups) {
            groups = new Map();
            bySubject.set(c.subject, groups);
        }
        const arr = groups.get(key);
        if (arr) arr.push(c); else groups.set(key, [c]);
    }

    const out = new Map<string, ConsensusCandidate>();
    for (const [subject, groups] of bySubject) {
        let best: Claim[] = [];
        for (const arr of groups.values()) {
            if (arr.length > best.length) {
                best = arr;
            } else if (arr.length === best.length && best.length > 0) {
                const arrBest = Math.max(...arr.map((c) => c.confidence));
                const curBest = Math.max(...best.map((c) => c.confidence));
                if (arrBest > curBest) best = arr;
            }
        }
        if (best.length < 2) continue;
        const sorted = [...best].sort((a, b) => b.confidence - a.confidence);
        out.set(subject, {
            subject,
            value: sorted[0].value,
            count: best.length,
            best_confidence: sorted[0].confidence,
            values: [...new Set(best.map((c) => c.value))],
        });
    }
    return out;
}

function consensusEscalatedTargets(intel: IntelLog): Set<string> {
    const out = new Set<string>();
    for (const e of intel.read()) {
        if (e.kind !== "claim") continue;
        // Only accepted consensus claims count as spent escalations.
        // A provider 429 or worker crash has no claim in intel and must
        // not permanently block the target from being escalated later.
        if (e.agent.includes("-consensus-")) out.add(e.subject);
    }
    return out;
}

export function selectCascadeBatch(args: {
    plan: CascadePlan;
    perRound: number;
    lowConfAttempts: Map<string, number>;
    consensusCandidates?: Map<string, ConsensusCandidate>;
    consensusEscalated?: Set<string>;
    maxLowConfRetries: number;
}): { batch: CascadePlanEntry[]; skipped: CascadePlanEntry[]; consensus: CascadePlanEntry[] } {
    const batch: CascadePlanEntry[] = [];
    const skipped: CascadePlanEntry[] = [];
    const consensus: CascadePlanEntry[] = [];
    for (const target of args.plan.top) {
        const attempts = args.lowConfAttempts.get(target.addr) ?? 0;
        if (attempts > 0 && attempts >= args.maxLowConfRetries) {
            const hasConsensus = args.consensusCandidates?.has(target.addr) ?? false;
            const alreadyEscalated = args.consensusEscalated?.has(target.addr) ?? false;
            if (hasConsensus && !alreadyEscalated && batch.length < args.perRound) {
                batch.push(target);
                consensus.push(target);
                continue;
            }
            skipped.push(target);
            continue;
        }
        if (batch.length < args.perRound) batch.push(target);
    }
    return { batch, skipped, consensus };
}

function consensusScope(addr: string, c: ConsensusCandidate): string {
    return `consensus:${addr}|${c.value}|${c.best_confidence.toFixed(2)}|${c.count}|${c.values.join(",")}`;
}

export function formatCascadePlan(plan: CascadePlan, limit = 12): string[] {
    const policy = plan.policy ? ` policy=${plan.policy}` : "";
    const lines: string[] = [
        `plan: scope=${plan.scope}${policy} candidates=${plan.candidates} eligible=${plan.eligible} selected=${plan.selected}`,
    ];
    const rows = plan.top.slice(0, limit);
    if (rows.length === 0) {
        lines.push("  no eligible targets");
        return lines;
    }
    const addrW = Math.max(6, ...rows.map((r) => r.addr.length));
    const scoreW = Math.max(5, ...rows.map((r) => r.score.toFixed(1).length));
    rows.forEach((r, idx) => {
        const n = String(idx + 1).padStart(2, " ");
        const addr = r.addr.padEnd(addrW, " ");
        const score = r.score.toFixed(1).padStart(scoreW, " ");
        const ratio = `${Math.round(r.ratio * 100)}%`.padStart(4, " ");
        lines.push(
            `  ${n}. ${addr} score=${score} known=${ratio} ` +
            `callers=${r.callers} callees=${r.callees} unresolved=${r.unresolved_callees} ` +
            `- ${r.reasons.join(", ")}`,
        );
    });
    if (plan.top.length > rows.length) {
        lines.push(`  ... ${plan.top.length - rows.length} more selected target(s)`);
    }
    return lines;
}

function runCppCascadePlan(args: {
    binary: string;
    emberBin: string;
    scope?: string;
    perRound: number;
    eligibilityRatio: number;
    module?: string;
}): CascadePlan {
    const cmd = ["--cascade-plan"];
    if (args.module) cmd.push("--module", args.module);
    cmd.push(
        "--cascade-scope", args.scope?.trim() || "all",
        "--per-round", String(args.perRound),
        "--eligibility-ratio", String(args.eligibilityRatio),
        "--json",
        args.binary,
    );
    const r = spawnSync(args.emberBin, cmd, {
        encoding: "utf8",
        maxBuffer: 64 * 1024 * 1024,
    });
    if (r.status !== 0) {
        throw new Error(`ember --cascade-plan failed: ${r.stderr || r.stdout}`);
    }
    const parsed = JSON.parse(r.stdout) as CascadePlan;
    if (!parsed || !Array.isArray(parsed.top)) {
        throw new Error("ember --cascade-plan returned malformed JSON");
    }
    return parsed;
}

function syncIntelToAnnotations(args: CascadeArgs, round: number): void {
    const scriptPath = join(args.runsRoot, `cascade-pre-round-${round}.ember`);
    try {
        promote({
            binary: args.binary,
            out: scriptPath,
            threshold: args.threshold,
            apply: true,
            dryRun: false,
            emberBin: args.emberBin,
        });
    } catch (e) {
        process.stderr.write(`promote failed before round ${round}: ${e}\n`);
    }
}

export async function cascade(args: CascadeArgs): Promise<CascadeResult> {
    const intel = new IntelLog(intelPathFor(args.binary));
    const rounds: RoundStats[] = [];
    let totalCost = 0;
    const maxLowConfRetries = Math.max(0, args.maxLowConfRetries ?? 2);
    mkdirSync(args.runsRoot, { recursive: true });

    // Sweep orphan daemons before starting our own. A previously
    // SIGKILL'd cascade can leak an `ember --serve <binary>` that
    // holds the binary mmap + cache fds and races our fresh daemon's
    // startup, manifesting as a multi-minute hang at "seeded with N
    // annotations" with no further progress. The C++ side's
    // PR_SET_PDEATHSIG covers the parent-died-cleanly case; this
    // scan catches the orphans that escaped that net.
    const cleared = killOrphanDaemons(args.binary);
    if (cleared > 0) {
        process.stderr.write(`cascade: killed ${cleared} orphan ember --serve daemon(s) for ${args.binary}\n`);
    }

    // Planning now lives in C++ (`ember --cascade-plan`). Keep the TS side
    // focused on auth, workers, event logs, cost accounting, and promotion.
    if (!args.dryRunPlan) {
        await warmEmberCaches(args.binary, args.emberBin);
        syncIntelToAnnotations(args, 0);
    }

    let lastPlan: CascadePlan | undefined;
    for (let round = 0; round < args.maxRounds; ++round) {
        const t0 = Date.now();

        const namedFromIntel = highConfNames(intel, args.threshold);
        const lowConfAttempts = lowConfNameAttempts(intel, args.threshold);
        const intelClaims = intel.read().filter((e): e is Claim => e.kind === "claim");
        const consensusCandidates = consensusNameCandidates(intelClaims, args.threshold);
        const alreadyConsensusEscalated = consensusEscalatedTargets(intel);
        const retrySaturated = [...lowConfAttempts.values()]
            .filter((count) => count >= maxLowConfRetries).length;
        const planLimit = args.perRound + Math.min(retrySaturated, Math.max(16, args.perRound * 4));
        const plan = runCppCascadePlan({
            binary: args.binary,
            emberBin: args.emberBin,
            scope: args.scope,
            perRound: planLimit,
            eligibilityRatio: args.eligibilityRatio,
            module: args.module,
        });
        lastPlan = plan;

        if (plan.eligible === 0 || plan.top.length === 0) {
            // Nothing left to bootstrap. Terminate.
            break;
        }

        if (args.dryRunPlan) {
            return {
                rounds: [],
                total_named: namedFromIntel.size,
                total_cost: totalCost,
                plan,
            };
        }

        const { batch, skipped, consensus } = selectCascadeBatch({
            plan,
            perRound: args.perRound,
            lowConfAttempts,
            consensusCandidates,
            consensusEscalated: alreadyConsensusEscalated,
            maxLowConfRetries,
        });
        const consensusAddrs = new Set(consensus.map((t) => t.addr));

        if (batch.length === 0) {
            process.stderr.write(
                `cascade: retry policy skipped all ${skipped.length} planned target(s); ` +
                `raise --max-low-conf-retries to retry them\n`,
            );
            break;
        }

        // Per-round model selection. If the user supplied a list, rotate
        // through it (round N uses models[N % len]). Useful for:
        //   - cheap → smart escalation: --models=owl-alpha,owl-alpha,deepseek-v4-pro
        //   - cross-validation: --models=owl-alpha,deepseek-v4-pro (alternate)
        // Single --model still works for a uniform run.
        const roundModel = (args.models && args.models.length > 0)
            ? args.models[round % args.models.length]
            : args.model;

        process.stderr.write(`cascade: round ${round} target plan\n`);
        for (const line of formatCascadePlan(plan, Math.min(args.perRound, 8))) {
            process.stderr.write(`${line}\n`);
        }
        if (skipped.length > 0) {
            const preview = skipped.slice(0, 6).map((t) => t.addr).join(", ");
            process.stderr.write(
                `cascade: retry policy skipped ${skipped.length} target(s) ` +
                `with >=${maxLowConfRetries} low-conf name claim(s): ${preview}\n`,
            );
        }
        if (consensus.length > 0) {
            const preview = consensus.map((t) => {
                const c = consensusCandidates.get(t.addr);
                return c ? `${t.addr} (${c.value}, ${c.count} votes)` : t.addr;
            }).join(", ");
            process.stderr.write(`cascade: consensus escalation selected ${preview}\n`);
        }
        process.stderr.write(
            `cascade: round ${round} spawning ${batch.length} worker(s), ` +
            `model=${roundModel ?? "(role default)"}, max_turns=${args.maxTurns}, ` +
            `budget=$${args.budget.toFixed(2)} each\n`,
        );

        // Spawn workers in parallel. We use runWorker (in-process)
        // rather than spawning N node processes - the workers all share
        // the same intel JSONL via O_APPEND, which is atomic.
        const before = namedFromIntel.size;
        const ourDirs: string[] = [];
        const ourAgentIds: string[] = [];
        const promises = batch.map((b) => {
            const runId = `r-cas${round}-${newId().slice(0, 4)}`;
            const runDir = join(args.runsRoot, runId);
            ourDirs.push(runDir);
            const agentKind = consensusAddrs.has(b.addr) ? "consensus" : args.role;
            const agentId = `cascade-${agentKind}-${round}-${runId.slice(2)}`;
            ourAgentIds.push(agentId);
            mkdirSync(runDir, { recursive: true });
            // Per-worker auth-home pick. When the user has multiple
            // ChatGPT / assistant Max accounts (typical: 5-account ChatGPT
            // Business setup), `[codex] homes = [...]` / `[assistant_code]
            // homes = [...]` in agent.toml lets us spread cascade load
            // across them round-robin. With 30 workers/round × 5 codex
            // homes that's 6 workers per account per round - staying
            // well under any per-plan rate limit.
            const m = roundModel ?? "";
            const cliHome = m.startsWith("assistant-code") ? pickassistantHome()
                          : isCodexCliModel(m)          ? pickCodexHome()
                          :                               undefined;
            const wargs = {
                role: args.role,
                binary: args.binary,
                scope: consensusAddrs.has(b.addr)
                    ? consensusScope(b.addr, consensusCandidates.get(b.addr)!)
                    : `fn:${b.addr}`,
                model: roundModel,
                budget: args.budget,
                maxTurns: args.maxTurns,
                runId,
                runDir,
                emberBin: args.emberBin,
                agentId,
                module: args.module,
                cliHome,
            };
            // assistant-code/* and codex-cli/* models route to official
            // local CLI workers, using the user's existing subscription
            // auth instead of HTTP API keys. Same events.jsonl shape so
            // the rest of the cascade pipeline is unchanged.
            return m.startsWith("assistant-code") ? runassistantCodeWorker(wargs)
                 : isCodexCliModel(m)          ? runCodexCliWorker(wargs)
                 :                               runWorker(wargs);
        });
        const settled = await Promise.allSettled(promises);
        let fulfilled = 0;
        let rejected = 0;
        for (const s of settled) {
            if (s.status === "fulfilled") {
                ++fulfilled;
            } else {
                ++rejected;
                const reason = s.reason instanceof Error ? s.reason.message : String(s.reason);
                process.stderr.write(`cascade: worker rejected: ${reason}\n`);
            }
        }

        // Tally cost from THIS round's worker dirs only. Earlier
        // versions of this code matched all `r-cas{round}-*` dirs in
        // runsRoot, which collided with prior cascade runs that happened
        // to land at the same round number - a stripped-ember cascade
        // running today would inflate its $0 owl-alpha cost with stale
        // tallies from yesterday's deepseek runs. Now we tally over
        // only the directories THIS cascade just created.
        const fsm = await import("node:fs");
        let roundCost = 0;
        for (const dir of ourDirs) {
            let lastUsd = 0;
            try {
                const events = fsm.readFileSync(join(dir, "events.jsonl"), "utf8");
                for (const line of events.split("\n")) {
                    const t = line.trim(); if (!t) continue;
                    try {
                        const e = JSON.parse(t);
                        if (e.tally?.usd != null) lastUsd = e.tally.usd;
                    } catch { /* skip malformed line */ }
                }
            } catch { /* worker may have failed before writing events */ }
            roundCost += lastUsd;
        }
        totalCost += roundCost;

        // Promote this round's claims into the annotations file. The
        // promote helper writes a .ember script and runs ember --apply
        // (when apply=true). After this returns, the next round's
        // ember_decompile calls render with these names baked in.
        const scriptPath = join(args.runsRoot, `cascade-round-${round}.ember`);
        try {
            promote({
                binary: args.binary,
                out: scriptPath,
                threshold: args.threshold,
                apply: true,
                dryRun: false,
                emberBin: args.emberBin,
            });
        } catch (e) {
            // Apply may fail mid-cascade (e.g. annotations file write
            // race); intel db still grew, just no re-render this round.
            process.stderr.write(`promote failed round ${round}: ${e}\n`);
        }

        const after = highConfNames(intel, args.threshold).size;
        const claimStats = summarizeRoundClaims(
            claimsByAgents(intel, new Set(ourAgentIds)),
            args.threshold,
        );
        rounds.push({
            round,
            eligible: plan.eligible,
            spawned: batch.length,
            fulfilled,
            rejected,
            ...claimStats,
            retry_skipped: skipped.length,
            retry_skipped_targets: skipped.map((t) => t.addr),
            consensus_escalated: consensus.length,
            consensus_targets: consensus.map((t) => t.addr),
            new_names: after - before,
            cumulative_named: after,
            model: roundModel ?? "(role default)",
            cost_usd: roundCost,
            elapsed_ms: Date.now() - t0,
            targets: batch,
        });

        // If a whole round produced no new high-conf names, the cascade
        // is done - every remaining unknown is genuinely too obscured
        // for the swarm to crack. Avoids burning rounds on hopeless
        // binaries.
        if (after - before === 0) break;
    }

    if (args.dryRunPlan) {
        return {
            rounds,
            total_named: highConfNames(intel, args.threshold).size,
            total_cost: totalCost,
            plan: lastPlan,
        };
    }
    return {
        rounds,
        total_named: highConfNames(intel, args.threshold).size,
        total_cost: totalCost,
    };
}
