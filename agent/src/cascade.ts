import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { createHash } from "node:crypto";
import { join } from "node:path";

import { runWorker } from "./worker.js";
import { promote } from "./promote.js";
import { IntelLog, intelPathFor, newId } from "./intel/log.js";
import { EmberDaemon } from "./tools/daemon.js";
import type { Claim } from "./intel/log.js";

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
}

export interface CascadeResult {
    rounds: RoundStats[];
    total_named: number;
    total_cost: number;
}

interface FnInfo { addr: string; size: number; kind: string; name: string; }

function parseFunctionsTsv(stdout: string): FnInfo[] {
    const out: FnInfo[] = [];
    for (const line of stdout.split("\n")) {
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

function listFunctions(binary: string, emberBin: string): FnInfo[] {
    const r = spawnSync(emberBin, ["--functions", binary], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
    if (r.status !== 0) throw new Error(`ember --functions failed: ${r.stderr}`);
    return parseFunctionsTsv(r.stdout);
}

// Read the binary's currently-resolved rename map via the daemon. TEEF
// anchors and prior-promoted cascade names land here (kind=sub stays
// in --functions but the address is annotated). Cascade seeds the
// known-neighbor set with these so round 0 can actually compound.
async function loadAnnotations(daemon: EmberDaemon): Promise<Set<string>> {
    const out = new Set<string>();
    const body = await daemon.call("annotations");
    for (const line of body.split("\n")) {
        if (!line) continue;
        const tab = line.indexOf("\t");
        if (tab < 0) continue;
        const addr = line.slice(0, tab);
        out.add(addr);
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

// One-shot bulk callee map via daemon. Replaces N round-trips for
// cascade's eligibility pass. Returns Map<caller, callees[]>.
async function loadAllCallees(daemon: EmberDaemon): Promise<Map<string, string[]>> {
    const body = await daemon.call("callees_all");
    const out = new Map<string, string[]>();
    for (const line of body.split("\n")) {
        if (!line) continue;
        const tab = line.indexOf("\t");
        if (tab < 0) continue;
        const caller = line.slice(0, tab);
        const callees = line.slice(tab + 1).split(",").filter(Boolean);
        out.set(caller, callees);
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

    await warmEmberCaches(args.binary, args.emberBin);

    // One-time setup. Spawn a coordinator daemon for cascade-wide
    // bulk queries (callees_all + future shared analyses). Workers
    // still spawn their own daemons since concurrent stdin/stdout
    // multiplexing is more complexity than the win is worth at this
    // scale.
    const coord = (() => {
        try { return new EmberDaemon(args.emberBin, args.binary); }
        catch { return undefined; }
    })();

    // Use daemon-served --functions when the coord is up — the cold
    // subprocess on a 9000-fn binary was the dominant pre-round-0 cost.
    const fns = (await (async () => {
        if (!coord) return listFunctions(args.binary, args.emberBin);
        try {
            const body = await coord.call("functions");
            return parseFunctionsTsv(body);
        } catch { return listFunctions(args.binary, args.emberBin); }
    })());
    const subAddrs = new Set<string>();
    for (const f of fns) {
        if (f.kind === "sub") subAddrs.add(f.addr);
    }

    // Seed annotated-name set from the binary's resolved annotation
    // file. Without this seed, TEEF's `ember --recognize` anchors are
    // invisible to cascade — round 0 starts with zero anchors, can't
    // compound, and terminates immediately on big stripped binaries.
    const annotated = new Set<string>();
    if (coord) {
        try {
            const a = await loadAnnotations(coord);
            for (const x of a) annotated.add(x);
        } catch (e) {
            process.stderr.write(`annotations seed failed: ${e}\n`);
        }
    }
    if (annotated.size > 0) {
        process.stderr.write(`cascade: seeded with ${annotated.size} pre-existing annotations (TEEF + symbols)\n`);
    }

    // Bulk callee map. With daemon: one round-trip pulls the full
    // call graph (a 7000-fn binary used to take ~30s of N×spawnSync
    // for the first eligibility pass). Subprocess fallback keeps the
    // old lazy per-fn behavior.
    const calleeMap = new Map<string, string[]>();
    if (coord) {
        try {
            const all = await loadAllCallees(coord);
            for (const [k, v] of all) calleeMap.set(k, v);
        } catch (e) {
            process.stderr.write(`callees_all failed, falling back to per-fn: ${e}\n`);
        }
    }
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
            // TEEF anchors + prior-promoted cascade names live in the
            // annotation file, not in --functions kind=symbol.
            if (annotated.has(callee)) return true;
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

        // Per-round model selection. If the user supplied a list, rotate
        // through it (round N uses models[N % len]). Useful for:
        //   - cheap → smart escalation: --models=owl-alpha,owl-alpha,deepseek-v4-pro
        //   - cross-validation: --models=owl-alpha,deepseek-v4-pro (alternate)
        // Single --model still works for a uniform run.
        const roundModel = (args.models && args.models.length > 0)
            ? args.models[round % args.models.length]
            : args.model;

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
            return runWorker({
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
            });
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
            eligible: eligible.length,
            spawned: batch.length,
            fulfilled,
            rejected,
            new_names: after - before,
            cumulative_named: after,
            model: roundModel ?? "(role default)",
            cost_usd: roundCost,
            elapsed_ms: Date.now() - t0,
        });

        // If a whole round produced no new high-conf names, the cascade
        // is done — every remaining unknown is genuinely too obscured
        // for the swarm to crack. Avoids burning rounds on hopeless
        // binaries.
        if (after - before === 0) break;
    }

    coord?.close();
    return {
        rounds,
        total_named: highConfNames(intel, args.threshold).size,
        total_cost: totalCost,
    };
}
