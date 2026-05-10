import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

import { runWorker } from "./worker.js";
import { runassistantCodeWorker } from "./worker_assistant_code.js";
import { isCodexCliModel, runCodexCliWorker } from "./worker_codex_cli.js";
import { pickCodexHome, pickassistantHome } from "./cli_homes.js";
import { promote } from "./promote.js";
import { IntelLog, intelPathFor, newId } from "./intel/log.js";

// Pre-warm ember's xrefs + strings disk caches so worker daemons
// pick up cached payloads on first access instead of N×workers
// each rebuilding from scratch. Smoothness:
//   - skip entirely when both caches already exist on disk
//   - run the two warmups concurrently (different cache slots,
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
    // for files tagged xrefs / strings-v* whose mtime is newer than the binary's.
    // Cheap heuristic, false-positive-tolerant — if we skip when caches don't
    // actually cover this binary, ember will rebuild them on first call (correct,
    // just no smoothness). False negative (we re-warm when we shouldn't have to)
    // costs at most ~200ms on a warm system.
    let likelyWarm = false;
    try {
        const binStat = statSync(binary);
        for (const dir of readdirSync(cacheRoot)) {
            const slot = join(cacheRoot, dir);
            try {
                const xref = join(slot, "xrefs");
                if (!existsSync(xref)) continue;
                const xs = statSync(xref);
                if (xs.mtimeMs < binStat.mtimeMs) continue;
                // strings-v2 is the current tag; older runs may have strings-v1.
                const ents = readdirSync(slot);
                if (!ents.some((n) => n.startsWith("strings"))) continue;
                likelyWarm = true; break;
            } catch { /* slot races; ignore */ }
        }
    } catch { /* no cacheRoot */ }
    if (likelyWarm) {
        process.stderr.write(`cascade: ember caches already warm for ${binary} (skip)\n`);
        return;
    }

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

    await Promise.all([run("--xrefs"), run("--strings")]);
    clearInterval(heartbeat);
    process.stderr.write(`cascade: caches warm (${((Date.now() - t_warm) / 1000).toFixed(1)}s)\n`);
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

// Anchor Cascade — iterative bottom-up agent naming.
//
// Background: a single-pass agent fanout treats each function as an
// island. The agent looking at sub_a sees calls to sub_b and sub_c
// rendered as sub_b()/sub_c() — opaque. There's no way to bootstrap
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
    models?: string[];           // optional per-round model list — round N uses
                                 // models[N % models.length]. Lets you escalate
                                 // (e.g. cheap for early rounds, smarter for
                                 // later) or interleave (cross-validation).
    perRound: number;            // max workers spawned per round
    maxRounds: number;
    budget: number;              // USD per worker
    maxTurns: number;
    threshold: number;           // promotion + named-callee threshold
    eligibilityRatio: number;    // min named-callee fraction for eligibility
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
    reasons: string[];
}
export interface CascadePlan {
    scope: string;
    candidates: number;
    eligible: number;
    selected: number;
    top: CascadePlanEntry[];
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

export function formatCascadePlan(plan: CascadePlan, limit = 12): string[] {
    const lines: string[] = [
        `plan: scope=${plan.scope} candidates=${plan.candidates} eligible=${plan.eligible} selected=${plan.selected}`,
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
        const plan = runCppCascadePlan({
            binary: args.binary,
            emberBin: args.emberBin,
            scope: args.scope,
            perRound: args.perRound,
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

        const batch = plan.top;

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
        process.stderr.write(
            `cascade: round ${round} spawning ${batch.length} worker(s), ` +
            `model=${roundModel ?? "(role default)"}, max_turns=${args.maxTurns}, ` +
            `budget=$${args.budget.toFixed(2)} each\n`,
        );

        // Spawn workers in parallel. We use runWorker (in-process)
        // rather than spawning N node processes — the workers all share
        // the same intel JSONL via O_APPEND, which is atomic.
        const before = namedFromIntel.size;
        const ourDirs: string[] = [];
        const promises = batch.map((b) => {
            const runId = `r-cas${round}-${newId().slice(0, 4)}`;
            const runDir = join(args.runsRoot, runId);
            ourDirs.push(runDir);
            mkdirSync(runDir, { recursive: true });
            // Per-worker auth-home pick. When the user has multiple
            // ChatGPT / assistant Max accounts (typical: 5-account ChatGPT
            // Business setup), `[codex] homes = [...]` / `[assistant_code]
            // homes = [...]` in agent.toml lets us spread cascade load
            // across them round-robin. With 30 workers/round × 5 codex
            // homes that's 6 workers per account per round — staying
            // well under any per-plan rate limit.
            const m = roundModel ?? "";
            const cliHome = m.startsWith("assistant-code") ? pickassistantHome()
                          : isCodexCliModel(m)          ? pickCodexHome()
                          :                               undefined;
            const wargs = {
                role: args.role,
                binary: args.binary,
                scope: `fn:${b.addr}`,
                model: roundModel,
                budget: args.budget,
                maxTurns: args.maxTurns,
                runId,
                runDir,
                emberBin: args.emberBin,
                agentId: `cascade-${args.role}-${round}-${runId.slice(2)}`,
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
        // to land at the same round number — a stripped-ember cascade
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
        rounds.push({
            round,
            eligible: plan.eligible,
            spawned: batch.length,
            fulfilled,
            rejected,
            new_names: after - before,
            cumulative_named: after,
            model: roundModel ?? "(role default)",
            cost_usd: roundCost,
            elapsed_ms: Date.now() - t0,
            targets: plan.top,
        });

        // If a whole round produced no new high-conf names, the cascade
        // is done — every remaining unknown is genuinely too obscured
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
