import { appendFileSync, mkdirSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { createHash } from "node:crypto";

// Append-only intel database.
//
// One JSONL file per binary at $XDG_CACHE_HOME/ember/<key>/intel.jsonl.
// `key` is FNV-style hash of (abspath, size, mtime) so different binaries
// (or different builds of the same binary) get isolated state. Matches
// ember's --xrefs/--strings cache scheme but lives in its own subtree so
// `ember --no-cache` doesn't wipe it.
//
// Each line is one of:
//   {kind:"claim",    id, agent, ts, subject, predicate, value, evidence, confidence, supersedes?}
//   {kind:"retract",  id, agent, ts, target_id, reason}
//
// The materialized view (per (subject, predicate) → winning claim) is a
// fold over the log: any claim whose id is the target of a retract is
// dropped; among survivors, max(confidence) wins, ties broken by
// recency.

export type Claim = {
    kind: "claim";
    id: string;
    agent: string;
    ts: string;            // ISO-8601
    subject: string;       // "0x4012a0", "string:.rdata+0x10", "struct:s12"
    predicate: string;     // "name" | "type" | "note" | "tag" | "xref" | "signature"
    value: string;
    evidence: string;
    confidence: number;    // 0..1
    supersedes?: string;
};

export type Retract = {
    kind: "retract";
    id: string;
    agent: string;
    ts: string;
    target_id: string;
    reason: string;
};

export type Entry = Claim | Retract;

export interface Decision {
    winner: Claim;
    runners_up: Claim[];
    disputed: boolean;     // top two within 0.10 confidence and from different agents
}

export class IntelLog {
    constructor(public readonly path: string) {
        mkdirSync(dirname(path), { recursive: true });
    }

    append(entry: Entry): void {
        appendFileSync(this.path, JSON.stringify(entry) + "\n", { flag: "a" });
    }

    read(): Entry[] {
        let raw: string;
        try { raw = readFileSync(this.path, "utf8"); } catch { return []; }
        const out: Entry[] = [];
        for (const line of raw.split("\n")) {
            const t = line.trim();
            if (!t) continue;
            try { out.push(JSON.parse(t)); } catch { /* skip corrupt */ }
        }
        return out;
    }

    // Fold the log into one Decision per (subject, predicate) key.
    fold(): Map<string, Decision> {
        const entries = this.read();
        const retracted = new Set<string>();
        for (const e of entries) {
            if (e.kind === "retract") retracted.add(e.target_id);
        }

        const buckets = new Map<string, Claim[]>();
        for (const e of entries) {
            if (e.kind !== "claim") continue;
            if (retracted.has(e.id)) continue;
            const k = `${e.subject}|${e.predicate}`;
            const arr = buckets.get(k);
            if (arr) arr.push(e); else buckets.set(k, [e]);
        }

        const view = new Map<string, Decision>();
        for (const [k, arr] of buckets) {
            arr.sort((a, b) => {
                if (b.confidence !== a.confidence) return b.confidence - a.confidence;
                return b.ts.localeCompare(a.ts);
            });
            const [winner, ...runners_up] = arr;
            const second = runners_up[0];
            const disputed = !!second
                && winner.confidence - second.confidence < 0.10
                && winner.agent !== second.agent
                && winner.value !== second.value;
            view.set(k, { winner, runners_up, disputed });
        }
        return view;
    }

    disputes(): Decision[] {
        return [...this.fold().values()].filter((d) => d.disputed);
    }
}

// Path resolution: matches ember's cache key scheme well enough that
// agents looking at the same binary land on the same intel.jsonl. We
// can't share the C++ FNV-1a-64 implementation, but binaries are
// identified by (abspath, size, mtime, version=1) just like ember-side.
export function intelPathFor(binary: string): string {
    const cacheRoot = process.env.XDG_CACHE_HOME
        ? join(process.env.XDG_CACHE_HOME, "ember")
        : join(homedir(), ".cache", "ember");
    const st = statSync(binary);
    const key = createHash("sha256")
        .update(binary)
        .update("|")
        .update(String(st.size))
        .update("|")
        .update(String(Math.floor(st.mtimeMs)))
        .update("|v1")
        .digest("hex")
        .slice(0, 16);
    return join(cacheRoot, key, "intel.jsonl");
}

export function newId(): string {
    return createHash("sha256")
        .update(String(process.hrtime.bigint()))
        .update(String(Math.random()))
        .digest("hex")
        .slice(0, 12);
}
