import { spawn, spawnSync } from "node:child_process";
import { join } from "node:path";

import { ROLES } from "./roles/index.js";
import { newId } from "./intel/log.js";

// Fanout: pick N functions from a binary, spawn N detached workers.
//
// Selection strategy depends on --pick:
//   "all"      — every fn ember reports (filter trivial < min-size)
//   "unnamed"  — only sub_* (skips already-named symbols)
//   "list:..." — comma-separated list of explicit fn addrs
//
// Each spawned worker is fully detached (parent exits as soon as it has
// printed run-ids), so this can be invoked from a long-lived
// orchestrator without holding the workers in the process tree.

export interface FanoutArgs {
    binary: string;
    role: keyof typeof ROLES;
    model?: string;
    pick: string;                // "all" | "unnamed" | "list:0x...,0x..."
    limit: number;               // max workers to spawn
    minSize: number;             // skip fns smaller than this many bytes
    budget: number;              // USD per worker
    maxTurns: number;
    emberBin: string;
    runsRoot: string;
}

interface FanoutResult {
    spawned: Array<{ run_id: string; fn: string; pid: number }>;
    skipped: { too_small: number; already_named: number; over_limit: number };
}

export function fanout(args: FanoutArgs): FanoutResult {
    const fns = pickFunctions(args);
    const out: FanoutResult = {
        spawned: [],
        skipped: { too_small: 0, already_named: 0, over_limit: 0 },
    };
    const role = ROLES[args.role];
    if (!role) throw new Error(`unknown role: ${args.role}`);

    for (const f of fns.candidates) {
        if (out.spawned.length >= args.limit) { ++out.skipped.over_limit; continue; }
        const runId = `r-${newId().slice(0, 6)}`;
        const runDir = join(args.runsRoot, runId);
        // Re-invoke ourselves as a foreground worker, detached. The
        // child writes its own events.jsonl as it goes; we only care
        // that it survives parent exit.
        const wargs = [
            // process.argv[0] is the node binary; argv[1] is dist/main.js
            process.argv[1],
            "worker",
            `--role=${args.role}`,
            `--binary=${args.binary}`,
            `--scope=fn:${f}`,
            `--budget=${args.budget}`,
            `--max-turns=${args.maxTurns}`,
            `--run-id=${runId}`,
        ];
        if (args.model) wargs.push(`--model=${args.model}`);
        const child = spawn(process.execPath, wargs, {
            detached: true,
            stdio: "ignore",
            env: { ...process.env, EMBER_BIN: args.emberBin },
        });
        child.unref();
        out.spawned.push({ run_id: runId, fn: f, pid: child.pid ?? -1 });
    }
    out.skipped.too_small = fns.too_small;
    out.skipped.already_named = fns.already_named;
    return out;
}

interface PickResult {
    candidates: string[];
    too_small: number;
    already_named: number;
}

function pickFunctions(args: FanoutArgs): PickResult {
    if (args.pick.startsWith("list:")) {
        return {
            candidates: args.pick.slice(5).split(",").map((s) => s.trim()).filter(Boolean),
            too_small: 0,
            already_named: 0,
        };
    }
    // ember --functions emits TSV: addr<TAB>size<TAB>kind<TAB>name
    const r = spawnSync(args.emberBin, ["--functions", args.binary], { encoding: "utf8" });
    if (r.status !== 0) throw new Error(`ember --functions failed: ${r.stderr}`);
    const candidates: string[] = [];
    let too_small = 0, already_named = 0;
    for (const line of r.stdout.split("\n")) {
        const t = line.trim();
        if (!t) continue;
        const parts = t.split("\t");
        if (parts.length < 4) continue;
        const [addrFull, sizeHex, _kind, name] = parts;
        const size = parseInt(sizeHex, 16);
        // ember reports size 0 for sub_* in some configs — still useful
        // to dispatch, just less informative. Apply the min-size filter
        // only to fns that report a real size.
        if (size > 0 && size < args.minSize) { ++too_small; continue; }
        if (args.pick === "unnamed" && !name.startsWith("sub_")) { ++already_named; continue; }
        // Compact hex form (drop leading zeros) — that's what our scope
        // parser and ember -s both accept.
        const addr = "0x" + parseInt(addrFull, 16).toString(16);
        candidates.push(addr);
    }
    return { candidates, too_small, already_named };
}
