#!/usr/bin/env node
import { existsSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { spawn } from "node:child_process";

import { runWorker } from "./worker.js";
import { ROLES } from "./roles/index.js";
import { IntelLog, intelPathFor, newId } from "./intel/log.js";
import { promote } from "./promote.js";
import { fanout } from "./fanout.js";

// CLI entry. Subcommands:
//   worker --role=R --binary=B --scope=S [--model=M] [--budget=N] [--detach]
//   intel <binary> query --subject S --predicate P
//   intel <binary> evidence --subject S
//   intel <binary> claim --subject S --predicate P --value V --evidence E --confidence C [--agent-id A]
//   intel <binary> retract --target-id T --reason R
//   intel <binary> disputes
//   runs list
//   runs status <run-id>
//   runs tail <run-id>

const RUNS_ROOT = join(
    process.env.XDG_CACHE_HOME ?? join(homedir(), ".cache"),
    "ember", "agent", "runs");

function parseFlags(argv: string[]): Map<string, string> {
    const out = new Map<string, string>();
    for (let i = 0; i < argv.length; ++i) {
        const a = argv[i];
        if (!a.startsWith("--")) continue;
        const eq = a.indexOf("=");
        if (eq >= 0) {
            out.set(a.slice(2, eq), a.slice(eq + 1));
        } else {
            const v = argv[i + 1];
            if (v && !v.startsWith("--")) { out.set(a.slice(2), v); ++i; }
            else                           { out.set(a.slice(2), "true"); }
        }
    }
    return out;
}

function findEmberBin(): string {
    const env = process.env.EMBER_BIN;
    if (env && existsSync(env)) return env;
    // Default: build/ relative to repo root (this file lives in agent/dist/).
    const candidates = [
        join(process.cwd(), "build", "cli", "ember"),
        join(process.cwd(), "build", "ember"),
        "/usr/local/bin/ember",
        "ember",
    ];
    for (const c of candidates) if (existsSync(c)) return c;
    return "ember";
}

async function cmdWorker(argv: string[]) {
    const f = parseFlags(argv);
    const role = f.get("role");
    const binary = f.get("binary");
    const scope = f.get("scope");
    if (!role || !binary || !scope) {
        console.error("usage: worker --role=R --binary=B --scope=S [--model=M] [--budget=N] [--detach]");
        process.exit(2);
    }
    if (!ROLES[role]) {
        console.error(`unknown role: ${role} (have: ${Object.keys(ROLES).join(", ")})`);
        process.exit(2);
    }
    const runId = f.get("run-id") ?? `r-${newId().slice(0, 6)}`;
    const runDir = join(RUNS_ROOT, runId);

    if (f.get("detach") === "true") {
        const child = spawn(process.execPath, [process.argv[1], "worker",
            ...argv.filter((a) => a !== "--detach")], {
                detached: true, stdio: "ignore",
            });
        child.unref();
        console.log(JSON.stringify({ run_id: runId, run_dir: runDir, pid: child.pid }));
        return;
    }

    await runWorker({
        role: role as keyof typeof ROLES,
        binary: resolve(binary),
        scope,
        model: f.get("model"),
        budget: parseFloat(f.get("budget") ?? "1.00"),
        maxTurns: parseInt(f.get("max-turns") ?? "30", 10),
        runId,
        runDir,
        emberBin: findEmberBin(),
        agentId: f.get("agent-id"),
    });
    console.log(JSON.stringify({ run_id: runId, run_dir: runDir, status: "complete" }));
}

async function cmdIntel(argv: string[]) {
    const [binary, op, ...rest] = argv;
    if (!binary || !op) {
        console.error("usage: intel <binary> <query|evidence|claim|retract|disputes> [flags]");
        process.exit(2);
    }
    statSync(binary);  // throws if missing
    const log = new IntelLog(intelPathFor(resolve(binary)));
    const f = parseFlags(rest);

    switch (op) {
        case "query": {
            const subject = f.get("subject"); const predicate = f.get("predicate");
            if (!subject || !predicate) { console.error("--subject --predicate required"); process.exit(2); }
            const view = log.fold();
            const d = view.get(`${subject}|${predicate}`);
            console.log(JSON.stringify(d ?? null, null, 2));
            return;
        }
        case "evidence": {
            const subject = f.get("subject");
            if (!subject) { console.error("--subject required"); process.exit(2); }
            for (const e of log.read()) {
                if (e.kind === "claim" && e.subject === subject) console.log(JSON.stringify(e));
                if (e.kind === "retract") console.log(JSON.stringify(e));
            }
            return;
        }
        case "claim": {
            const required = ["subject", "predicate", "value", "evidence", "confidence"] as const;
            for (const k of required) if (!f.has(k)) { console.error(`--${k} required`); process.exit(2); }
            const id = newId();
            log.append({
                kind: "claim", id,
                agent: f.get("agent-id") ?? "cli",
                ts: new Date().toISOString(),
                subject:    f.get("subject")!,
                predicate:  f.get("predicate")!,
                value:      f.get("value")!,
                evidence:   f.get("evidence")!,
                confidence: parseFloat(f.get("confidence")!),
                supersedes: f.get("supersedes"),
            });
            console.log(JSON.stringify({ ok: true, id }));
            return;
        }
        case "retract": {
            const target_id = f.get("target-id"); const reason = f.get("reason");
            if (!target_id || !reason) { console.error("--target-id --reason required"); process.exit(2); }
            const id = newId();
            log.append({
                kind: "retract", id, agent: f.get("agent-id") ?? "cli",
                ts: new Date().toISOString(), target_id, reason,
            });
            console.log(JSON.stringify({ ok: true, id }));
            return;
        }
        case "disputes": {
            console.log(JSON.stringify(log.disputes(), null, 2));
            return;
        }
        default:
            console.error(`unknown intel op: ${op}`);
            process.exit(2);
    }
}

async function cmdRuns(argv: string[]) {
    const [op, runId] = argv;
    switch (op) {
        case "list": {
            const { readdirSync } = await import("node:fs");
            try {
                for (const d of readdirSync(RUNS_ROOT)) console.log(d);
            } catch { /* no runs yet */ }
            return;
        }
        case "status":
        case "tail": {
            if (!runId) { console.error(`runs ${op} <run-id>`); process.exit(2); }
            const path = join(RUNS_ROOT, runId, "events.jsonl");
            if (op === "status") {
                const raw = readFileSync(path, "utf8").split("\n").filter(Boolean);
                const last = raw.length ? JSON.parse(raw[raw.length - 1]) : null;
                let usd = 0;
                for (const line of raw) {
                    const e = JSON.parse(line);
                    if (e.tally?.usd != null) usd = e.tally.usd;
                }
                console.log(JSON.stringify({
                    run_id: runId,
                    turns: raw.filter((l) => JSON.parse(l).kind === "turn").length,
                    last: last?.kind,
                    usd,
                }, null, 2));
                return;
            }
            // tail: stream-print
            const fs = await import("node:fs");
            const watcher = fs.watch(path);
            let pos = 0;
            const flush = () => {
                const buf = fs.readFileSync(path, "utf8");
                if (buf.length > pos) {
                    process.stdout.write(buf.slice(pos));
                    pos = buf.length;
                }
            };
            flush();
            watcher.on("change", flush);
            return;
        }
        default:
            console.error("usage: runs <list|status|tail> [run-id]");
            process.exit(2);
    }
}

async function cmdPromote(argv: string[]) {
    const [binary, ...rest] = argv;
    if (!binary) {
        console.error("usage: promote <binary> [--out PATH] [--threshold N] [--apply | --dry-run]");
        process.exit(2);
    }
    const f = parseFlags(rest);
    const out = f.get("out") ?? `${resolve(binary)}.intel.ember`;
    const r = promote({
        binary: resolve(binary),
        out,
        threshold: parseFloat(f.get("threshold") ?? "0.85"),
        apply:  f.get("apply") === "true",
        dryRun: f.get("dry-run") === "true",
        emberBin: findEmberBin(),
    });
    console.log(JSON.stringify({
        out_script: out,
        promoted: r.promoted,
        skipped: {
            disputed: r.skipped_disputed,
            low_conf: r.skipped_low_conf,
            other: r.skipped_other,
        },
    }, null, 2));
}

async function cmdFanout(argv: string[]) {
    const f = parseFlags(argv);
    const binary = f.get("binary");
    if (!binary) {
        console.error("usage: fanout --binary=B [--role=namer] [--pick=unnamed|all|list:0x..,..] [--limit=N] [--min-size=N] [--budget=N] [--model=M]");
        process.exit(2);
    }
    const role = (f.get("role") ?? "namer") as keyof typeof ROLES;
    if (!ROLES[role]) { console.error(`unknown role: ${role}`); process.exit(2); }
    const r = fanout({
        binary: resolve(binary),
        role,
        model: f.get("model"),
        pick: f.get("pick") ?? "unnamed",
        limit: parseInt(f.get("limit") ?? "8", 10),
        minSize: parseInt(f.get("min-size") ?? "8", 10),
        budget: parseFloat(f.get("budget") ?? "0.10"),
        maxTurns: parseInt(f.get("max-turns") ?? "12", 10),
        emberBin: findEmberBin(),
        runsRoot: RUNS_ROOT,
    });
    console.log(JSON.stringify(r, null, 2));
}

async function main() {
    const [, , cmd, ...rest] = process.argv;
    switch (cmd) {
        case "worker":   await cmdWorker(rest);  return;
        case "intel":    await cmdIntel(rest);   return;
        case "runs":     await cmdRuns(rest);    return;
        case "promote":  await cmdPromote(rest); return;
        case "fanout":   await cmdFanout(rest);  return;
        default:
            console.error("usage: ember-agent <worker|intel|runs|promote|fanout> ...");
            process.exit(2);
    }
}

main().catch((e) => {
    console.error(e instanceof Error ? e.stack ?? e.message : String(e));
    process.exit(1);
});
