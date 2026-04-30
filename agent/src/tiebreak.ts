import { mkdirSync } from "node:fs";
import { join } from "node:path";

import { runWorker } from "./worker.js";
import { IntelLog, intelPathFor, newId } from "./intel/log.js";

// Drive the tiebreaker role across the current dispute set. One
// worker per disputed (subject, predicate) so we don't race them
// on intel_disputes. The role's system prompt already lays out
// the verify-and-resolve protocol; this module just enumerates
// the work and dispatches.

export interface TiebreakArgs {
    binary: string;
    model?: string;
    budget: number;
    maxTurns: number;
    limit: number;            // max disputes to process this run
    emberBin: string;
    runsRoot: string;
}

export interface TiebreakResult {
    disputes_found: number;
    spawned: number;
    fulfilled: number;
    rejected: number;
    elapsed_ms: number;
    cost_usd: number;
}

export async function tiebreak(args: TiebreakArgs): Promise<TiebreakResult> {
    const t0 = Date.now();
    const intel = new IntelLog(intelPathFor(args.binary));
    const disputes = intel.disputes();
    const batch = disputes.slice(0, args.limit);

    if (batch.length === 0) {
        return {
            disputes_found: 0,
            spawned: 0, fulfilled: 0, rejected: 0,
            elapsed_ms: Date.now() - t0,
            cost_usd: 0,
        };
    }

    const fs = await import("node:fs");
    const ourDirs: string[] = [];
    const promises = batch.map((d) => {
        const subject = d.winner.subject;
        const predicate = d.winner.predicate;
        const runId = `r-tie-${newId().slice(0, 6)}`;
        const runDir = join(args.runsRoot, runId);
        ourDirs.push(runDir);
        mkdirSync(runDir, { recursive: true });
        return runWorker({
            role: "tiebreaker",
            binary: args.binary,
            scope: `dispute:${subject}|${predicate}`,
            model: args.model,
            budget: args.budget,
            maxTurns: args.maxTurns,
            runId,
            runDir,
            emberBin: args.emberBin,
            agentId: `tiebreaker-${runId.slice(2)}`,
        });
    });

    const settled = await Promise.allSettled(promises);
    let fulfilled = 0, rejected = 0;
    for (const s of settled) {
        if (s.status === "fulfilled") ++fulfilled;
        else {
            ++rejected;
            const reason = s.reason instanceof Error ? s.reason.message : String(s.reason);
            process.stderr.write(`tiebreak: worker rejected: ${reason}\n`);
        }
    }

    let cost_usd = 0;
    for (const dir of ourDirs) {
        let lastUsd = 0;
        try {
            const events = fs.readFileSync(join(dir, "events.jsonl"), "utf8");
            for (const line of events.split("\n")) {
                const t = line.trim(); if (!t) continue;
                try {
                    const e = JSON.parse(t);
                    if (e.tally?.usd != null) lastUsd = e.tally.usd;
                } catch { /* skip */ }
            }
        } catch { /* worker may have failed before writing */ }
        cost_usd += lastUsd;
    }

    return {
        disputes_found: disputes.length,
        spawned: batch.length,
        fulfilled, rejected,
        elapsed_ms: Date.now() - t0,
        cost_usd,
    };
}
