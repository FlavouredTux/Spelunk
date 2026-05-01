import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

// Round-robin pool of CLI auth-home directories for the SDK-driven
// workers (Codex CLI / assistant Code). Same shape as llm/index.ts's
// API-key rotation: pull a list out of ~/.config/ember/agent.toml or
// the env, return one entry per call via a module-local counter.
//
// agent.toml shape:
//
//   [codex]
//   homes = ["~/.codex-acct1", "~/.codex-acct2", "~/.codex-acct3"]
//
//   [assistant_code]
//   homes = ["~/.assistant-personal", "~/.assistant-work"]
//
// Each path points at a directory containing the same auth artifacts
// the corresponding CLI's `login` command writes — for codex that's
// `auth.json`, for assistant-code that's `.credentials.json`. Per-worker
// the dispatcher picks one in round-robin order, so a 30-worker cascade
// with 5 codex homes spreads load to 6 workers per account per round —
// staying well under any per-plan rate limit.
//
// Env override: CODEX_HOMES_CSV / assistant_HOMES_CSV (comma-separated)
// take precedence over the toml file. Single-account users who don't
// set anything fall through to the legacy default — runCodexCliWorker
// reads ~/.codex, runassistantCodeWorker reads ~/.assistant — and the
// previous behaviour is unchanged.

interface CliHomes {
    codex: string[];
    assistant_code: string[];
}

function expandHome(p: string): string {
    if (p.startsWith("~/")) return join(homedir(), p.slice(2));
    if (p === "~")           return homedir();
    return p;
}

function loadCliHomes(): CliHomes {
    const out: CliHomes = { codex: [], assistant_code: [] };

    const fromCsv = (env: string | undefined) =>
        (env ?? "").split(",").map((s) => s.trim()).filter(Boolean).map(expandHome);
    out.codex.push(...fromCsv(process.env.CODEX_HOMES_CSV));
    out.assistant_code.push(...fromCsv(process.env.assistant_HOMES_CSV));

    const cfgPath = join(homedir(), ".config", "ember", "agent.toml");
    let raw: string;
    try { raw = readFileSync(cfgPath, "utf8"); }
    catch { return out; }

    // Collapse multi-line array values onto a single line so the
    // line-by-line section walk can match `homes = [...]` whether the
    // user wrote it inline or on multiple lines (the more idiomatic
    // TOML style for long path lists).
    const flat = raw.replace(/=\s*\[[\s\S]*?\]/g, (m) => m.replace(/\s+/g, " "));

    let section = "";
    for (const line of flat.split("\n")) {
        const t = line.trim();
        if (!t || t.startsWith("#")) continue;
        const m = /^\[(\w+)\]$/.exec(t);
        if (m) { section = m[1]; continue; }
        const arr = /^homes\s*=\s*\[(.+)\]\s*$/.exec(t);
        if (!arr) continue;
        const target = section === "codex"        ? out.codex
                     : section === "assistant_code"  ? out.assistant_code
                     : null;
        if (!target) continue;
        for (const m2 of arr[1].matchAll(/"([^"]*)"/g)) {
            const p = expandHome(m2[1]);
            if (!target.includes(p)) target.push(p);
        }
    }
    return out;
}

// Module-local rotation counters. One worker process == one cascade ==
// one rotation; per-cascade fairness is what matters. Across cascades
// the counter resets, which is also fine — a fresh cascade starts at
// home 0 and walks forward.
const _rot: Record<string, number> = { codex: 0, assistant_code: 0 };

function pickFromList(list: string[], pool: keyof CliHomes): string | undefined {
    if (list.length === 0) return undefined;
    if (list.length === 1) return list[0];
    const i = _rot[pool] % list.length;
    _rot[pool] = (_rot[pool] + 1) | 0;
    return list[i];
}

// Returns the next codex home to use for a worker, or undefined when
// the user hasn't configured a pool. The worker falls back to its own
// EMBER_CODEX_HOME / ~/.codex resolution in that case.
export function pickCodexHome(): string | undefined {
    return pickFromList(loadCliHomes().codex, "codex");
}

// Same for assistant Code.
export function pickassistantHome(): string | undefined {
    return pickFromList(loadCliHomes().assistant_code, "assistant_code");
}

// Diagnostic: surface how many homes are configured per pool. Useful
// in the UI Settings drawer ("Codex: 5 accounts in rotation").
export function homeCount(pool: "codex" | "assistant_code"): number {
    return loadCliHomes()[pool].length;
}
