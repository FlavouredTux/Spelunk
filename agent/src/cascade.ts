import { spawnSync } from "node:child_process";
import { mkdirSync } from "node:fs";
import { join } from "node:path";

import { runWorker } from "./worker.js";
import { promote } from "./promote.js";
import { IntelLog, intelPathFor, newId } from "./intel/log.js";
import type { Claim } from "./intel/log.js";

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
    model?: string;
    perRound: number;            // max workers spawned per round
    maxRounds: number;
    budget: number;              // USD per worker
    maxTurns: number;
    threshold: number;           // promotion + named-callee threshold
    eligibilityRatio: number;    // min named-callee fraction for eligibility
    emberBin: string;
    runsRoot: string;
}

export interface RoundStats {
    round: number;
    eligible: number;
    spawned: number;
    new_names: number;       // intel claims promoted this round
    cost_usd: number;
    elapsed_ms: number;
}

export interface CascadeResult {
    rounds: RoundStats[];
    total_named: number;
    total_cost: number;
}

interface FnInfo { addr: string; size: number; kind: string; name: string; }

function listFunctions(binary: string, emberBin: string): FnInfo[] {
    const r = spawnSync(emberBin, ["--functions", binary], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
    if (r.status !== 0) throw new Error(`ember --functions failed: ${r.stderr}`);
    const out: FnInfo[] = [];
    for (const line of r.stdout.split("\n")) {
        const t = line.trim(); if (!t) continue;
        const parts = t.split("\t");
        if (parts.length < 4) continue;
        const addr = "0x" + parseInt(parts[0], 16).toString(16);
        out.push({
            addr,
            size: parseInt(parts[1], 16) || 0,
            kind: parts[2],
            name: parts[3],
        });
    }
    return out;
}

function listCallees(addr: string, binary: string, emberBin: string): string[] {
    const r = spawnSync(emberBin, ["--callees", addr, binary], { encoding: "utf8" });
    if (r.status !== 0) return [];   // function may have no callees, not an error
    const out: string[] = [];
    for (const line of r.stdout.split("\n")) {
        const t = line.trim(); if (!t) continue;
        if (!t.startsWith("0x")) continue;
        out.push("0x" + parseInt(t, 16).toString(16));
    }
    return out;
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

export async function cascade(args: CascadeArgs): Promise<CascadeResult> {
    const intel = new IntelLog(intelPathFor(args.binary));
    const rounds: RoundStats[] = [];
    let totalCost = 0;

    // One-time: enumerate all functions + callees so we don't hit the
    // ember CLI per fn per round. This is the dominant cold cost; on a
    // 7000-fn binary it's about 30s walltime, then cached.
    const fns = listFunctions(args.binary, args.emberBin);
    const calleeMap = new Map<string, string[]>();
    const subAddrs = new Set<string>();
    for (const f of fns) {
        if (f.kind === "sub") subAddrs.add(f.addr);
    }
    // Computing callees for every fn upfront is expensive on huge
    // binaries — defer until first eligibility pass and cache.
    const calleesOf = (addr: string): string[] => {
        let v = calleeMap.get(addr);
        if (v == null) {
            v = listCallees(addr, args.binary, args.emberBin);
            calleeMap.set(addr, v);
        }
        return v;
    };

    for (let round = 0; round < args.maxRounds; ++round) {
        const t0 = Date.now();

        const namedFromIntel = highConfNames(intel, args.threshold);
        const isKnown = (callee: string): boolean => {
            // PLT thunks / external calls aren't in our subAddrs set —
            // their pseudo-C rendering already includes the resolved
            // name (puts, malloc, ...), so treat as anchored.
            if (!subAddrs.has(callee)) return true;
            return namedFromIntel.has(callee);
        };

        // Find eligible fns.
        const eligible: { addr: string; ratio: number; total: number; size: number }[] = [];
        for (const f of fns) {
            if (f.kind !== "sub") continue;             // already named (symbol)
            if (namedFromIntel.has(f.addr)) continue;   // already named (intel)
            const callees = calleesOf(f.addr);
            const total = callees.length;
            if (total === 0) {
                // True leaf — eligible from round 0.
                eligible.push({ addr: f.addr, ratio: 1.0, total: 0, size: f.size });
                continue;
            }
            const known = callees.filter(isKnown).length;
            const ratio = known / total;
            if (ratio >= args.eligibilityRatio) {
                eligible.push({ addr: f.addr, ratio, total, size: f.size });
            }
        }

        if (eligible.length === 0) {
            // Nothing left to bootstrap. Terminate.
            break;
        }

        // Sort: highest known-callee ratio first (most informative
        // pseudo-C), break ties by larger size (more signal).
        eligible.sort((a, b) => (b.ratio - a.ratio) || (b.size - a.size));
        const batch = eligible.slice(0, args.perRound);

        // Spawn workers in parallel. We use runWorker (in-process)
        // rather than spawning N node processes — the workers all share
        // the same intel JSONL via O_APPEND, which is atomic.
        const before = namedFromIntel.size;
        const promises = batch.map((b) => {
            const runId = `r-cas${round}-${newId().slice(0, 4)}`;
            const runDir = join(args.runsRoot, runId);
            mkdirSync(runDir, { recursive: true });
            return runWorker({
                role: args.role,
                binary: args.binary,
                scope: `fn:${b.addr}`,
                model: args.model,
                budget: args.budget,
                maxTurns: args.maxTurns,
                runId,
                runDir,
                emberBin: args.emberBin,
                agentId: `cascade-${args.role}-${round}-${runId.slice(2)}`,
            });
        });
        const settled = await Promise.allSettled(promises);
        for (const s of settled) {
            if (s.status === "rejected") {
                process.stderr.write(`worker rejected: ${s.reason}\n`);
            }
        }

        // Tally cost from this round's run dirs. We don't have a
        // built-in callback for usage on runWorker so we re-read the
        // events.jsonl files we just wrote.
        let roundCost = 0;
        for (let i = 0; i < batch.length; ++i) {
            // recover the runId we used. promises is parallel to batch
            // but we don't track it back; compute from settled metadata.
            // Simpler: scan runsRoot for r-cas{round}-* files newer than t0.
        }
        // Re-read runsRoot for our round prefix.
        try {
            const fs = await import("node:fs");
            for (const d of fs.readdirSync(args.runsRoot)) {
                if (!d.startsWith(`r-cas${round}-`)) continue;
                const events = fs.readFileSync(join(args.runsRoot, d, "events.jsonl"), "utf8");
                for (const line of events.split("\n")) {
                    const t = line.trim(); if (!t) continue;
                    try {
                        const e = JSON.parse(t);
                        if (e.tally?.usd != null) {
                            // Last-tally-wins; per-event tallies are running totals.
                            roundCost = Math.max(roundCost, e.tally.usd);
                        }
                    } catch { /* skip */ }
                }
            }
        } catch { /* runsRoot might not exist on first run */ }
        // Above gives us max single-run cost, not sum. Fix: sum per-run final tallies.
        roundCost = 0;
        try {
            const fs = await import("node:fs");
            for (const d of fs.readdirSync(args.runsRoot)) {
                if (!d.startsWith(`r-cas${round}-`)) continue;
                const events = fs.readFileSync(join(args.runsRoot, d, "events.jsonl"), "utf8");
                let lastUsd = 0;
                for (const line of events.split("\n")) {
                    const t = line.trim(); if (!t) continue;
                    try {
                        const e = JSON.parse(t);
                        if (e.tally?.usd != null) lastUsd = e.tally.usd;
                    } catch { /* skip */ }
                }
                roundCost += lastUsd;
            }
        } catch { /* */ }
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
            eligible: eligible.length,
            spawned: batch.length,
            new_names: after - before,
            cost_usd: roundCost,
            elapsed_ms: Date.now() - t0,
        });

        // If a whole round produced no new high-conf names, the cascade
        // is done — every remaining unknown is genuinely too obscured
        // for the swarm to crack. Avoids burning rounds on hopeless
        // binaries.
        if (after - before === 0) break;
    }

    return {
        rounds,
        total_named: highConfNames(intel, args.threshold).size,
        total_cost: totalCost,
    };
}
