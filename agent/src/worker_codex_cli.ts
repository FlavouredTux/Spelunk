import { appendFileSync, mkdirSync } from "node:fs";
import { spawn } from "node:child_process";
import { join } from "node:path";

import { ROLES } from "./roles/index.js";
import type { WorkerArgs } from "./worker.js";

// Codex CLI worker. This preserves the same events.jsonl contract as
// runWorker / runassistantCodeWorker while delegating the agent loop to
// `codex exec`.
//
// Model ids use the sentinel prefix:
//   codex-cli/gpt-5       -> codex exec --model gpt-5
//   codex-cli/gpt-5.4     -> codex exec --model gpt-5.4
//   codex-cli             -> Codex config default
//
// Codex CLI does not expose the same in-process MCP helper API that
// assistant Agent SDK does here. Instead we give it a constrained prompt
// that points at Ember's CLI and the intel JSONL protocol. The worker
// still runs in the user's Codex login context, so ChatGPT
// subscription auth stays inside the official tool.

const kZeroCost = {
    usd: 0,
    input_tokens: 0,
    output_tokens: 0,
    cache_read_tokens: 0,
    cache_write_tokens: 0,
};

export function isCodexCliModel(model: string | undefined): boolean {
    return (model ?? "").startsWith("codex-cli");
}

export async function runCodexCliWorker(args: WorkerArgs): Promise<void> {
    const role = ROLES[args.role];
    if (!role) throw new Error(`unknown role: ${args.role}`);

    const requested = args.model ?? role.defaultModel;
    const cliModel = requested.startsWith("codex-cli/")
        ? requested.slice("codex-cli/".length) || undefined
        : undefined;

    mkdirSync(args.runDir, { recursive: true });
    const eventsPath = join(args.runDir, "events.jsonl");
    const emit = (e: Record<string, unknown>) => {
        appendFileSync(eventsPath,
            JSON.stringify({ ts: new Date().toISOString(), ...e }) + "\n");
    };

    const prompt = buildCodexPrompt(args, role.system);
    emit({
        kind: "start",
        role: args.role,
        model: requested,
        scope: args.scope,
        agentId: args.agentId ?? `${args.role}-${args.runId}`,
        budget: args.budget,
        binary: args.binary,
    });

    const codexArgs = [
        "exec",
        "--json",
        "--ephemeral",
        "--ignore-rules",
        "-c",
        'approval_policy="never"',
        "--skip-git-repo-check",
        "--sandbox",
        "workspace-write",
        ...(cliModel ? ["--model", cliModel] : []),
        "-",
    ];

    await new Promise<void>((resolve, reject) => {
        const child = spawn("codex", codexArgs, {
            cwd: process.cwd(),
            stdio: ["pipe", "pipe", "pipe"],
            env: {
                ...process.env,
                CODEXCLI_APPROVAL_POLICY: "never",
            },
        });

        let stderr = "";
        let pending = "";
        let finalMessage = "";

        child.stdout.on("data", (chunk) => {
            pending += chunk.toString();
            let idx;
            while ((idx = pending.indexOf("\n")) !== -1) {
                const line = pending.slice(0, idx);
                pending = pending.slice(idx + 1);
                const msg = parseCodexEvent(line);
                if (!msg) continue;
                if (msg.kind === "agent_message") {
                    finalMessage = msg.text;
                    emit({ kind: "message", bytes: msg.text.length });
                } else if (msg.kind === "tool") {
                    emit({ kind: "tool_ok", name: msg.name, input: msg.input, bytes: msg.bytes });
                } else if (msg.kind === "turn") {
                    emit({ kind: "turn", turn: msg.turn, stop: msg.stop, usage: msg.usage, tally: kZeroCost });
                }
            }
        });
        child.stderr.on("data", (d) => { stderr += d.toString(); });
        child.on("error", (err: NodeJS.ErrnoException) => {
            const msg = err.code === "ENOENT"
                ? "codex binary not found on PATH. Install Codex CLI and run `codex login`."
                : `codex: ${err.message}`;
            emit({ kind: "error", phase: "spawn", err: msg });
            reject(new Error(msg));
        });
        child.on("close", (code) => {
            if (pending.trim()) {
                const msg = parseCodexEvent(pending);
                if (msg?.kind === "agent_message") finalMessage = msg.text;
            }
            if (code === 0) {
                emit({
                    kind: "done",
                    turns: 1,
                    tally: kZeroCost,
                    claims_filed: finalMessage.includes("intel_claim") ? 1 : 0,
                });
                resolve();
                return;
            }
            const err = friendlyCodexError(code, stderr);
            emit({ kind: "error", phase: "codex", err });
            reject(new Error(err));
        });

        child.stdin.write(prompt);
        child.stdin.end();
    });
}

type ParsedCodexEvent =
    | { kind: "agent_message"; text: string }
    | { kind: "tool"; name: string; input?: unknown; bytes: number }
    | { kind: "turn"; turn: number; stop: string; usage?: unknown };

function parseCodexEvent(line: string): ParsedCodexEvent | null {
    if (!line.trim().startsWith("{")) return null;
    let j: any;
    try { j = JSON.parse(line); } catch { return null; }
    const msg = j.msg ?? j;
    if (msg.type === "agent_message" && typeof msg.message === "string") {
        return { kind: "agent_message", text: msg.message };
    }
    if (msg.type === "exec_command_begin") {
        return {
            kind: "tool",
            name: "shell",
            input: { command: msg.command },
            bytes: 0,
        };
    }
    if (msg.type === "exec_command_end") {
        return {
            kind: "tool",
            name: "shell",
            input: { exit_code: msg.exit_code },
            bytes: typeof msg.stdout === "string" ? msg.stdout.length : 0,
        };
    }
    if (msg.type === "token_count") {
        return {
            kind: "turn",
            turn: 0,
            stop: "running",
            usage: msg.info ?? msg,
        };
    }
    return null;
}

function friendlyCodexError(code: number | null, stderr: string): string {
    const diag = stderr.toLowerCase();
    if (/not logged in|login required|unauthorized|authentication/.test(diag)) {
        return "Codex CLI is not signed in. Run `codex login` in a terminal, then retry.";
    }
    if (/rate.?limit|429/.test(diag)) {
        return "Codex CLI was rate-limited by OpenAI. Wait a bit and retry, or switch provider.";
    }
    const tail = stderr.trim().slice(-600);
    return `codex exited ${code ?? "unknown"}${tail ? `: ${tail}` : ""}`;
}

function buildCodexPrompt(args: WorkerArgs, system: string): string {
    const agentId = args.agentId ?? `${args.role}-${args.runId}`;
    return `${system}

You are running inside Ember's Codex CLI worker. Do not edit repository files.
Use shell commands only for analysis and for writing intel claims.

Target binary: ${args.binary}
Scope: ${args.scope}
Agent id: ${agentId}
Ember CLI: ${args.emberBin}

Useful commands:
- Decompile: \`${args.emberBin} -d ${args.binary} -s <function-or-address>\`
- Xrefs: \`${args.emberBin} --xrefs ${args.binary}\`
- Strings: \`${args.emberBin} --strings ${args.binary}\`
- Recognize: \`${args.emberBin} --recognize ${args.binary}\`
- Query intel: \`node ${process.argv[1]} intel ${args.binary} query --subject <subject> --predicate <predicate>\`
- File a claim: \`node ${process.argv[1]} intel ${args.binary} claim --agent-id ${agentId} --subject <subject> --predicate <predicate> --value <value> --evidence <evidence> --confidence <0..1>\`

Finish only after following the role instructions. If the role requires
an intel_claim, file it with the command above before answering.

Initial task:
${buildScopeMessage(args.scope, args.binary)}`;
}

function buildScopeMessage(scope: string, binary: string): string {
    if (scope.startsWith("fn:")) {
        return `Target: ${binary}\nFunction: ${scope.slice(3)}\n\nProceed.`;
    }
    if (scope.startsWith("dispute:")) {
        const tail = scope.slice("dispute:".length);
        const bar = tail.indexOf("|");
        const subject = bar < 0 ? tail : tail.slice(0, bar);
        const predicate = bar < 0 ? "name" : tail.slice(bar + 1);
        return `Target: ${binary}\nDisputed claim: subject=${subject}, predicate=${predicate}\n\n` +
               `Use intel disputes and Ember CLI evidence to independently verify. File ONE ` +
               `intel_claim with your verdict.`;
    }
    return `Target: ${binary}\nScope: ${scope}\n\nProceed.`;
}
